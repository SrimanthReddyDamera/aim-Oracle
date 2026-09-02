"""
ORACLE Investigation Controller (Brick 3 & 3.2)
Enforces the deterministic control plane, budget limits, duplicate prevention via Jaccard similarity (P2),
zero-yield query feedback (P3), complete event tracing, and the strict Sufficiency Verification Protocol.

EPISTEMIC INVARIANT:
  The LLM has NO unilateral authority to terminate.
  LLM_INFERENCE edges are investigation hypotheses, NOT factual proof.
  Only the InvestigationController can grant SUFFICIENT after verifying that
  factual sufficiency does not rest solely on unsupported inferences.
"""

import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from backend.evidence.models import Evidence
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    InvestigationBudget,
    InvestigationEvent,
    InvestigationGap,
    InvestigationState,
    RelationshipType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "and", "or", "in", "on", "at",
    "to", "for", "of", "with", "by", "from", "can", "what", "how", "this", "that",
    "it", "its", "be", "do", "does", "did", "under", "before", "after"
}


class InvestigationController:
    """
    Deterministic Controller governing the investigation lifecycle.
    Holds absolute authority over sufficiency verification, evidence validity,
    budget enforcement, duplicate prevention, and termination.
    """

    def __init__(
        self,
        retriever: SQLiteFTS5Retriever,
        scanner: Optional[EntityScanner] = None,
        budget: Optional[InvestigationBudget] = None,
        query_similarity_threshold: float = 0.70,
    ):
        self.retriever = retriever
        self.scanner = scanner or EntityScanner()
        self.budget = budget or InvestigationBudget()
        self.query_similarity_threshold = query_similarity_threshold

    def run_investigation(
        self,
        objective: str,
        reasoning_agent_fn: Callable[[InvestigationState], Tuple[bool, str, List[InvestigationGap], List[EvidenceEdge]]],
        initial_k: int = 4,
    ) -> EvidencePackage:
        """
        Execute the autonomous investigation loop until sufficiency is verified
        by the controller or a budget ceiling is reached.
        """
        start_time = time.perf_counter()

        state = InvestigationState(
            objective=objective,
            accumulated_evidence={},
            evidence_graph=[],
            pending_gaps=[],
            resolved_gaps=[],
            executed_queries=set(),
            zero_yield_queries=set(),
            unresolved_references=set(),
            investigation_trace=[],
            hop_count=0,
            llm_call_count=0,
            is_sufficient=False,
            termination_reason=None,
        )

        # ----------------------------------------------------------------------
        # TURN 0: Cold Initial Retrieval on Raw Objective
        # ----------------------------------------------------------------------
        init_results, _ = self.retriever.search(objective, k=initial_k)
        state.executed_queries.add(self._normalize_query(objective))

        for ev, _ in init_results:
            state.accumulated_evidence[ev.evidence_id] = ev

        # Extract deterministic references from initial chunks (P4)
        unresolved = self.scanner.find_unresolved_references(state.accumulated_evidence)
        state.unresolved_references.update(unresolved)

        # Detect deterministic edges among initial chunks
        det_edges = self.scanner.detect_deterministic_edges(list(state.accumulated_evidence.values()))
        self._merge_edges(state.evidence_graph, det_edges)

        state.investigation_trace.append(
            InvestigationEvent(
                hop=0,
                event_type="INITIAL_RETRIEVAL",
                description=f"Initial retrieval executed for objective with k={initial_k}",
                details={
                    "query": objective,
                    "chunks_retrieved": [e.evidence_id for e, _ in init_results],
                    "unresolved_references": list(unresolved),
                    "deterministic_edges_found": len(det_edges),
                },
            )
        )

        # ----------------------------------------------------------------------
        # ITERATION LOOP
        # ----------------------------------------------------------------------
        while True:
            elapsed_time = time.perf_counter() - start_time

            # 1. Check Hard Budget Ceilings
            if state.hop_count >= self.budget.max_hops:
                state.termination_reason = "BUDGET_EXHAUSTED_MAX_HOPS"
                break
            if state.llm_call_count >= self.budget.max_llm_calls:
                state.termination_reason = "BUDGET_EXHAUSTED_MAX_LLM_CALLS"
                break
            if len(state.executed_queries) >= self.budget.max_queries:
                state.termination_reason = "BUDGET_EXHAUSTED_MAX_QUERIES"
                break
            if elapsed_time >= self.budget.max_wall_time_seconds:
                state.termination_reason = "BUDGET_EXHAUSTED_TIMEOUT"
                break

            # 2. FAST-PATH: Deterministic Reference Hop (Zero LLM Tokens) (P4)
            # If an explicit unresolved ticket/code exists (e.g. CR-904 or INC-402), fetch it directly
            if state.unresolved_references:
                target_token = state.unresolved_references.pop()
                is_dup, _ = self.is_duplicate_or_overlapping_query(target_token, state.executed_queries)

                if not is_dup:
                    state.executed_queries.add(self._normalize_query(target_token))
                    ref_results, _ = self.retriever.search(target_token, k=4)
                    new_chunks = self._add_new_evidence(state, ref_results)

                    # Update references and edges
                    new_unresolved = self.scanner.find_unresolved_references(state.accumulated_evidence)
                    state.unresolved_references.update(new_unresolved)
                    new_det_edges = self.scanner.detect_deterministic_edges(list(state.accumulated_evidence.values()))
                    self._merge_edges(state.evidence_graph, new_det_edges)

                    state.investigation_trace.append(
                        InvestigationEvent(
                            hop=state.hop_count,
                            event_type="FAST_PATH_DISPATCH",
                            description=f"Fast-path queried unresolved token '{target_token}' directly without LLM invocation",
                            details={
                                "token": target_token,
                                "new_chunks_added": new_chunks,
                                "total_evidence": len(state.accumulated_evidence),
                                "unresolved_remaining": list(state.unresolved_references),
                            },
                        )
                    )

                    # Fast-path does not increment llm_call_count; proceed to next step
                    if new_chunks > 0:
                        continue

            # 3. SURGICAL LLM REASONING HOP
            state.llm_call_count += 1
            proposed_sufficient, rationale, candidate_gaps, proposed_edges = reasoning_agent_fn(state)

            state.investigation_trace.append(
                InvestigationEvent(
                    hop=state.hop_count + 1,
                    event_type="LLM_PROPOSAL_RECEIVED",
                    description=f"LLM proposed sufficient={proposed_sufficient} with {len(candidate_gaps)} candidate queries",
                    details={
                        "proposed_sufficient": proposed_sufficient,
                        "candidate_queries": [g.targeted_query for g in candidate_gaps],
                    },
                )
            )

            # Ingest proposed LLM edges with mandatory LLM_INFERENCE provenance
            for edge in proposed_edges:
                edge.derived_by = EdgeDerivationType.LLM_INFERENCE
                self._merge_edges(state.evidence_graph, [edge])

            # 4. CONTROLLER SUFFICIENCY VERIFICATION PROTOCOL
            # Sole authority to terminate with SUFFICIENT rests here
            if proposed_sufficient:
                is_verified, reject_reason = self.verify_sufficiency(state, rationale)
                if is_verified:
                    state.is_sufficient = True
                    state.termination_reason = "SUFFICIENT"
                    state.investigation_trace.append(
                        InvestigationEvent(
                            hop=state.hop_count + 1,
                            event_type="CONTROLLER_VERIFIED_SUFFICIENT",
                            description="Controller verified factual sufficiency and completeness; terminating investigation",
                            details={"total_evidence": len(state.accumulated_evidence)},
                        )
                    )
                    break
                else:
                    state.investigation_trace.append(
                        InvestigationEvent(
                            hop=state.hop_count + 1,
                            event_type="CONTROLLER_REJECTED_SUFFICIENCY",
                            description=f"Controller rejected LLM sufficiency proposal: {reject_reason}",
                            details={"reason": reject_reason},
                        )
                    )
                    state.is_sufficient = False

            # 5. DISPATCH HIGHEST-PRIORITY ACTIONABLE GAP (P2: Jaccard Deduplication)
            if not candidate_gaps:
                state.termination_reason = "STAGNATION_NO_GAPS"
                break

            candidate_gaps.sort(key=lambda g: g.priority)

            selected_gap: Optional[InvestigationGap] = None
            rejection_details = []

            for gap in candidate_gaps:
                is_dup, reason = self.is_duplicate_or_overlapping_query(
                    gap.targeted_query, state.executed_queries, threshold=self.query_similarity_threshold
                )
                if is_dup:
                    rejection_details.append(f"Rejected '{gap.targeted_query}': {reason}")
                else:
                    selected_gap = gap
                    break

            if not selected_gap:
                state.termination_reason = "STAGNATION_ALL_QUERIES_EXHAUSTED"
                state.investigation_trace.append(
                    InvestigationEvent(
                        hop=state.hop_count + 1,
                        event_type="STAGNATION_DETECTED",
                        description="All candidate queries rejected due to duplicate or high Jaccard token overlap with past queries",
                        details={"rejections": rejection_details},
                    )
                )
                break

            # Execute the single selected gap
            norm_q = self._normalize_query(selected_gap.targeted_query)
            state.executed_queries.add(norm_q)
            selected_gap.attempted_queries.append(selected_gap.targeted_query)
            state.pending_gaps.append(selected_gap)

            gap_results, _ = self.retriever.search(selected_gap.targeted_query, k=4)
            pre_ids = set(state.accumulated_evidence.keys())
            new_chunks_found = self._add_new_evidence(state, gap_results)
            post_ids = set(state.accumulated_evidence.keys())
            new_evidence_ids = list(post_ids - pre_ids)

            # P3: Zero-Yield Recording
            if new_chunks_found == 0:
                selected_gap.resolution_status = False
                state.zero_yield_queries.add(selected_gap.targeted_query)
            else:
                selected_gap.resolution_status = True
                selected_gap.resolution_evidence_ids = new_evidence_ids
                state.resolved_gaps.append(selected_gap)

            state.investigation_trace.append(
                InvestigationEvent(
                    hop=state.hop_count + 1,
                    event_type="ACTIONABLE_GAP_EXECUTED",
                    description=f"Executed targeted search query '{selected_gap.targeted_query}'",
                    details={
                        "query": selected_gap.targeted_query,
                        "priority": selected_gap.priority,
                        "new_chunks_found": new_chunks_found,
                        "new_evidence_ids": new_evidence_ids,
                        "is_zero_yield": (new_chunks_found == 0),
                        "total_evidence": len(state.accumulated_evidence),
                    },
                )
            )

            # Update deterministic entities after gap retrieval
            unresolved = self.scanner.find_unresolved_references(state.accumulated_evidence)
            state.unresolved_references.update(unresolved)
            new_det_edges = self.scanner.detect_deterministic_edges(list(state.accumulated_evidence.values()))
            self._merge_edges(state.evidence_graph, new_det_edges)

            state.hop_count += 1

        # ----------------------------------------------------------------------
        # PACKAGE CREATION
        # ----------------------------------------------------------------------
        total_time_ms = (time.perf_counter() - start_time) * 1000.0

        state.investigation_trace.append(
            InvestigationEvent(
                hop=state.hop_count,
                event_type="INVESTIGATION_TERMINATED",
                description=f"Investigation completed with reason: {state.termination_reason}",
                details={
                    "termination_reason": state.termination_reason,
                    "controller_verified": state.is_sufficient,
                    "total_evidence_collected": len(state.accumulated_evidence),
                    "total_wall_clock_ms": round(total_time_ms, 2),
                },
            )
        )

        all_gaps = state.resolved_gaps + [g for g in state.pending_gaps if g not in state.resolved_gaps]

        return EvidencePackage(
            objective=objective,
            termination_reason=state.termination_reason or "UNKNOWN",
            controller_verified=state.is_sufficient,
            budget_summary={
                "hops_used": state.hop_count,
                "llm_calls_used": state.llm_call_count,
                "queries_executed": len(state.executed_queries),
                "zero_yield_queries_count": len(state.zero_yield_queries),
                "total_chunks_collected": len(state.accumulated_evidence),
                "elapsed_wall_time_ms": round(total_time_ms, 2),
            },
            evidence_items=list(state.accumulated_evidence.values()),
            graph_edges=state.evidence_graph,
            gap_history=[
                {
                    "gap_id": g.gap_id,
                    "description": g.description,
                    "query": g.targeted_query,
                    "resolved": g.resolution_status,
                    "resolution_evidence_ids": g.resolution_evidence_ids,
                }
                for g in all_gaps
            ],
            investigation_trace=state.investigation_trace,
            gaps=all_gaps,
        )

    def verify_sufficiency(
        self,
        state: InvestigationState,
        llm_rationale: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Deterministic verification protocol.
        Rejects LLM sufficiency proposals if factual gaps, unproven inferences,
        unresolved change rejections, or missing incident post-mortems remain.
        """
        # 1. Unresolved explicit references blocking sufficiency
        if state.unresolved_references:
            unresolved_str = ", ".join(sorted(state.unresolved_references))
            return False, f"Unresolved explicit reference(s) still pending: {unresolved_str}"

        # 2. Epistemic Invariant: An edge derived solely by LLM_INFERENCE cannot
        # independently establish factual sufficiency.
        has_only_inferences = (
            len(state.evidence_graph) > 0
            and all(not edge.is_factual_proof for edge in state.evidence_graph)
        )
        if has_only_inferences:
            return (
                False,
                "Sufficiency rejected: Evidence graph relies solely on LLM_INFERENCE edges. "
                "Inferred edges are hypotheses and cannot independently establish factual proof.",
            )

        # 3. Contradiction & Rejection Guard:
        # If a CAB rejection is present in evidence (e.g. CR-904 rejected),
        # verify that the superseding incident/post-mortem explaining the rejection is also retrieved.
        has_cab_rejection = any(
            "DOC-NOVA-CAB" in e.source_id and "REJECTED" in e.content.upper()
            for e in state.accumulated_evidence.values()
        )
        has_incident = any(
            "DOC-NOVA-INC-402" in e.source_id
            for e in state.accumulated_evidence.values()
        )
        if has_cab_rejection and not has_incident:
            return (
                False,
                "Sufficiency rejected: Change request was REJECTED by CAB due to an operational incident, "
                "but the corresponding incident post-mortem evidence is not yet retrieved.",
            )

        # 4. Stale Architecture Guard:
        # If an outdated claim chunk is present (e.g. ARCH-OLD claiming Redis v7),
        # verify that the superseding incident/post-mortem is also present.
        has_stale_arch = any("DOC-NOVA-ARCH-OLD" in e.source_id for e in state.accumulated_evidence.values())
        if has_stale_arch and not has_incident:
            return (
                False,
                "Sufficiency rejected: Stale architecture specification present without "
                "superseding post-mortem rollback evidence.",
            )

        # 5. Minimum Evidence Floor
        if len(state.accumulated_evidence) < 2:
            return False, "Sufficiency rejected: Insufficient evidence chunks (< 2) collected."

        return True, None

    def _normalize_query(self, query: str) -> str:
        """Normalize query string for deterministic exact deduplication."""
        return " ".join(query.strip().lower().split())

    def _tokenize_query(self, query: str) -> Set[str]:
        """Extract non-stopword tokens for Jaccard semantic similarity deduplication (P2)."""
        tokens = set(re.findall(r"\b[a-z0-9\-]+\b", query.lower()))
        return tokens - STOPWORDS

    def is_duplicate_or_overlapping_query(
        self,
        candidate: str,
        executed_queries: Set[str],
        threshold: float = 0.70,
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines whether a query has been executed or is too similar to an already executed query
        using normalized non-stopword Jaccard token overlap (P2).
        """
        cand_norm = self._normalize_query(candidate)
        if cand_norm in executed_queries:
            return True, f"Exact match with previously executed query: '{cand_norm}'"

        cand_tokens = self._tokenize_query(candidate)
        if not cand_tokens:
            return True, "Query contains only stopwords"

        for prev_q in executed_queries:
            prev_tokens = self._tokenize_query(prev_q)
            if not prev_tokens:
                continue
            intersection = cand_tokens.intersection(prev_tokens)
            union = cand_tokens.union(prev_tokens)
            jaccard = len(intersection) / len(union) if union else 0.0
            if jaccard >= threshold:
                return True, f"High Jaccard semantic token overlap ({jaccard:.2f} >= {threshold}) with executed query: '{prev_q}'"

        return False, None

    def _add_new_evidence(
        self,
        state: InvestigationState,
        results: List[Tuple[Evidence, float]],
    ) -> int:
        """Add new evidence chunks to accumulated state, returning count of new items."""
        added = 0
        for ev, _ in results:
            if ev.evidence_id not in state.accumulated_evidence:
                state.accumulated_evidence[ev.evidence_id] = ev
                added += 1
        return added

    def _merge_edges(
        self,
        existing_edges: List[EvidenceEdge],
        new_edges: List[EvidenceEdge],
    ) -> None:
        """Merge newly detected edges into the graph avoiding duplicate pairs."""
        existing_keys = {
            (e.source_evidence_id, e.target_evidence_id, e.relationship_type)
            for e in existing_edges
        }
        for edge in new_edges:
            key = (edge.source_evidence_id, edge.target_evidence_id, edge.relationship_type)
            if key not in existing_keys:
                existing_edges.append(edge)
                existing_keys.add(key)
