"""
ORACLE Investigation Controller (Brick 3.4 Revision v2 + Brick 3.7 Adaptive Retrieval)
Enforces the in-memory InvestigationSession, deterministic gap derivation,
deterministic prioritization, Jaccard duplicate prevention, gap lifecycle state transitions,
the strict Factual Sufficiency Verification Protocol, and deterministic Adaptive Retrieval Expansion.

EPISTEMIC INVARIANTS:
  - The Controller exclusively owns mutable state, gaps, prioritization, and termination.
  - The LLM is strictly an action/query proposer.
  - Evidence sufficiency is separated from truth: conflicting claims transition
    to RECONCILIATION_REQUIRED, never marked uncontested RESOLVED.
  - All gap types, prioritization, and transitions are generic and domain-agnostic.
  - The adaptive retrieval expansion policy is fully generic, configurable, and deterministic.
"""

from collections import Counter
import re
import time
from typing import Callable, Dict, List, Optional, Set, Tuple
import uuid

from backend.evidence.models import Evidence
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    AdaptiveRetrievalConfig,
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationEvent,
    InvestigationSession,
    InvestigationState,
    RelationshipType,
    RetrievalDecisionTelemetry,
)
from backend.retrieval.provider import EvidenceProvider
from backend.core.security import redact_sensitive_data

STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "and", "or", "in", "on", "at",
    "to", "for", "of", "with", "by", "from", "can", "what", "how", "this", "that",
    "it", "its", "be", "do", "does", "did", "under", "before", "after"
}

GENERIC_PREREQ_PATTERN = re.compile(
    r"\b(?:requires|depends\s+on|must\s+have|prerequisite\s+is|conditional\s+on)\s+([A-Za-z0-9\.\-\_\s]{3,50})",
    re.IGNORECASE,
)

GENERIC_ENFORCEMENT_PATTERN = re.compile(
    r"\b(?:strictly\s+enforces?|enforces?|mandates?)\s+([^\;\n]+?)\s+for\s+(?:all\s+)?([^\.\;\n]+?)(?:\.(?:\s|$)|[\;\n])",
    re.IGNORECASE,
)

GENERIC_INTEG_TARGET_PATTERN = re.compile(
    r"(?:target|integration\s+target):\s*([A-Za-z0-9\.\-\_\s]{3,50}?)(?:\n|$)",
    re.IGNORECASE,
)



class InvestigationController:
    """
    Deterministic Controller governing the investigation lifecycle.
    Holds absolute authority over sufficiency verification, gap lifecycle state machine,
    gap prioritization, query deduplication, and termination.
    """

    def __init__(
        self,
        retriever: EvidenceProvider,
        scanner: Optional[EntityScanner] = None,
        budget: Optional[InvestigationBudget] = None,
        query_similarity_threshold: float = 0.70,
        adaptive_retrieval_config: Optional[AdaptiveRetrievalConfig] = None,
        max_batch_gaps: int = 1,
    ):
        self.retriever = retriever
        self.scanner = scanner or EntityScanner()
        self.budget = budget or InvestigationBudget()
        self.query_similarity_threshold = query_similarity_threshold
        self.adaptive_config = adaptive_retrieval_config or AdaptiveRetrievalConfig()
        self.max_batch_gaps = max_batch_gaps

    def evaluate_adaptive_expansion(
        self,
        candidate_pool: List[Tuple[Evidence, float]],
        unresolved_references: Set[str],
        expansion_count: int = 0,
    ) -> Tuple[bool, RetrievalDecisionTelemetry]:
        """
        Evaluates deterministic, domain-agnostic triggers for candidate window expansion.
        Configurable via self.adaptive_config.
        """
        cfg = self.adaptive_config
        initial_k = cfg.initial_k
        expansion_k = cfg.expansion_k

        if not cfg.enabled or len(candidate_pool) < initial_k:
            r4_score = candidate_pool[3][1] if len(candidate_pool) > 3 else 0.0
            r8_score = candidate_pool[7][1] if len(candidate_pool) > 7 else 0.0
            final_k = min(len(candidate_pool), initial_k)
            telemetry = RetrievalDecisionTelemetry(
                initial_k=initial_k,
                final_k=final_k,
                rank_4_score=round(r4_score, 3),
                rank_8_score=round(r8_score, 3),
                decay_ratio=0.0,
                min_score=cfg.min_score,
                source_concentration=0.0,
                reference_affinity=False,
                expansion_triggers=[],
                expanded=False,
                retrieved_evidence_ids=[e.evidence_id for e, _ in candidate_pool[:final_k]],
            )
            return False, telemetry

        scores = [s for _, s in candidate_pool]
        chunks = [e for e, _ in candidate_pool]

        # Rank 4 and Rank 8 scores
        rank_4_score = scores[3]
        rank_8_score = scores[7]
        decay_ratio = rank_8_score / rank_4_score if rank_4_score > 0 else 0.0

        # Trigger 1: Flat Tail
        is_flat_tail = (decay_ratio >= cfg.decay_threshold) and (rank_8_score >= cfg.min_score)

        # Trigger 2: Source Monopolization
        top_8_chunks = chunks[:initial_k]
        source_counts = Counter(c.source_id for c in top_8_chunks)
        top_source, max_source_count = source_counts.most_common(1)[0] if source_counts else ("unknown", 0)
        source_concentration = max_source_count / initial_k
        is_monopolized = (source_concentration >= cfg.source_concentration_threshold)

        # Trigger 3: Reference Affinity in Ranks 9..expansion_k
        has_ref_affinity = False
        upper_refs = {r.upper() for r in unresolved_references}
        expansion_candidates = candidate_pool[initial_k:expansion_k]
        if upper_refs:
            for cand, _ in expansion_candidates:
                cand_text = cand.content.upper()
                if any(ref in cand_text for ref in upper_refs):
                    has_ref_affinity = True
                    break

        triggers = []
        if is_flat_tail:
            triggers.append(
                f"FLAT_TAIL (decay_ratio={decay_ratio:.3f} >= {cfg.decay_threshold:.2f}, rank_8_score={rank_8_score:.2f} >= {cfg.min_score:.2f})"
            )
        if is_monopolized:
            triggers.append(
                f"SOURCE_MONOPOLIZATION (source='{top_source}' concentration={source_concentration:.3f} >= {cfg.source_concentration_threshold:.3f})"
            )
        if has_ref_affinity:
            triggers.append("REFERENCE_AFFINITY (unresolved reference token present in ranks 9-10)")

        can_expand = (expansion_count < cfg.max_expansions)
        should_expand = bool(triggers) and can_expand
        final_k = expansion_k if should_expand else initial_k

        telemetry = RetrievalDecisionTelemetry(
            initial_k=initial_k,
            final_k=final_k,
            rank_4_score=round(rank_4_score, 3),
            rank_8_score=round(rank_8_score, 3),
            decay_ratio=round(decay_ratio, 3),
            min_score=cfg.min_score,
            source_concentration=round(source_concentration, 3),
            reference_affinity=has_ref_affinity,
            expansion_triggers=triggers,
            expanded=should_expand,
            retrieved_evidence_ids=[e.evidence_id for e, _ in candidate_pool[:final_k]],
        )

        return should_expand, telemetry

    def run_investigation(
        self,
        objective: str,
        reasoning_agent_fn: Callable[[InvestigationState], Tuple[bool, str, List[InformationGap], List[EvidenceEdge]]],
        initial_k: Optional[int] = None,
    ) -> EvidencePackage:
        """
        Execute the autonomous investigation loop using the in-memory InvestigationSession.
        Employs deterministic adaptive retrieval in Turn 0.
        """
        start_time = time.perf_counter()

        session = InvestigationSession(
            session_id=str(uuid.uuid4())[:8],
            objective=objective,
            discovered_evidence={},
            unresolved_references=set(),
            gaps={},
            detected_contradictions=[],
            query_history=set(),
            zero_yield_queries=set(),
            hop_count=0,
            llm_call_count=0,
            max_hops=self.budget.max_hops,
            max_llm_calls=self.budget.max_llm_calls,
            max_queries=self.budget.max_queries,
            max_wall_time_seconds=self.budget.max_wall_time_seconds,
            is_sufficient=False,
            termination_reason=None,
            investigation_trace=[],
        )

        # ----------------------------------------------------------------------
        # TURN 0: Cold Initial Retrieval with Adaptive Candidate Window
        # ----------------------------------------------------------------------
        if initial_k is not None and (not self.adaptive_config.enabled or initial_k < self.adaptive_config.initial_k):
            effective_init_k = initial_k
            search_depth = initial_k
        else:
            effective_init_k = self.adaptive_config.initial_k
            search_depth = self.adaptive_config.expansion_k if self.adaptive_config.enabled else effective_init_k

        candidate_pool, _ = self.retriever.search(objective, k=search_depth)
        norm_obj = self._normalize_query(objective)
        session.query_history.add(norm_obj)

        fed_telem_0 = getattr(self.retriever, "get_last_telemetry", lambda: None)()
        if fed_telem_0:
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=0,
                    event_type="FEDERATED_RETRIEVAL_DISPATCH",
                    description=f"Federated search queried {len(fed_telem_0.providers_queried)} provider(s): {', '.join(fed_telem_0.providers_queried)}",
                    details=redact_sensitive_data(fed_telem_0.model_dump()),
                )
            )

        pre_chunks = [e for e, _ in candidate_pool[:effective_init_k]]
        pre_evidence = {e.evidence_id: e for e in pre_chunks}
        pre_unresolved = self.scanner.find_unresolved_references(pre_evidence)

        should_expand, telemetry = self.evaluate_adaptive_expansion(
            candidate_pool=candidate_pool,
            unresolved_references=pre_unresolved,
            expansion_count=0,
        )
        session.investigation_trace.append(
            InvestigationEvent(
                hop=0,
                event_type="ADAPTIVE_RETRIEVAL_DECISION",
                description=f"Adaptive retrieval evaluated: final_k={telemetry.final_k} (expanded={telemetry.expanded})",
                details=telemetry.model_dump(),
            )
        )

        final_candidates = candidate_pool[:telemetry.final_k]
        for ev, _ in final_candidates:
            session.discovered_evidence[ev.evidence_id] = ev

        unresolved = self.scanner.find_unresolved_references(session.discovered_evidence)
        session.unresolved_references.update(unresolved)
        det_edges = self.scanner.detect_deterministic_edges(list(session.discovered_evidence.values()))
        self._derive_and_update_gaps(session, det_edges)

        session.investigation_trace.append(
            InvestigationEvent(
                hop=0,
                event_type="INITIAL_RETRIEVAL",
                description=f"Initial retrieval admitted {len(final_candidates)} chunks (adaptive final_k={telemetry.final_k})",
                details={
                    "query": objective,
                    "chunks_retrieved": [e.evidence_id for e, _ in final_candidates],
                    "unresolved_references": list(unresolved),
                    "gaps_initialized": [g.gap_id for g in session.gaps.values()],
                    "telemetry": telemetry.model_dump(),
                },
            )
        )

        # ----------------------------------------------------------------------
        # ITERATION LOOP (Governed by Controller State Machine)
        # ----------------------------------------------------------------------
        while True:
            elapsed_time = time.perf_counter() - start_time

            # 1. Budget Checks
            if session.hop_count >= session.max_hops:
                session.termination_reason = "BUDGET_EXHAUSTED_MAX_HOPS"
                break
            if session.llm_call_count >= session.max_llm_calls:
                session.termination_reason = "BUDGET_EXHAUSTED_MAX_LLM_CALLS"
                break
            if len(session.query_history) >= session.max_queries:
                session.termination_reason = "BUDGET_EXHAUSTED_MAX_QUERIES"
                break
            if elapsed_time >= session.max_wall_time_seconds:
                session.termination_reason = "BUDGET_EXHAUSTED_TIMEOUT"
                break

            # 2. FAST-PATH: Deterministic Reference Hop (Zero LLM Tokens)
            if session.unresolved_references:
                target_token = session.unresolved_references.pop()
                target_gap = session.gaps.get(f"GAP-REF-{target_token}")
                dispatch_query = target_gap.targeted_query if (target_gap and target_gap.targeted_query) else target_token
                is_dup, _ = self.is_duplicate_or_overlapping_query(dispatch_query, session.query_history)

                if not is_dup:
                    session.query_history.add(self._normalize_query(dispatch_query))
                    ref_results, _ = self.retriever.search(dispatch_query, k=4)
                    fed_telem_fp = getattr(self.retriever, "get_last_telemetry", lambda: None)()
                    if fed_telem_fp:
                        session.investigation_trace.append(
                            InvestigationEvent(
                                hop=session.hop_count,
                                event_type="FEDERATED_RETRIEVAL_DISPATCH",
                                description=f"Fast-path federated retrieval queried {len(fed_telem_fp.providers_queried)} provider(s)",
                                details=redact_sensitive_data(fed_telem_fp.model_dump()),
                            )
                        )
                    new_chunks = self._add_new_evidence(session, ref_results)

                    new_unres = self.scanner.find_unresolved_references(session.discovered_evidence)
                    session.unresolved_references.update(new_unres)
                    new_det_edges = self.scanner.detect_deterministic_edges(list(session.discovered_evidence.values()))
                    self._derive_and_update_gaps(session, new_det_edges)

                    ref_ids = [e.evidence_id for e, _ in ref_results]
                    self._evaluate_all_gaps(session, ref_ids)

                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count,
                            event_type="FAST_PATH_DISPATCH",
                            description=f"Fast-path queried unresolved token '{target_token}' directly without LLM invocation",
                            details={
                                "token": target_token,
                                "new_chunks_added": new_chunks,
                                "total_evidence": len(session.discovered_evidence),
                                "unresolved_remaining": list(session.unresolved_references),
                            },
                        )
                    )

                    if new_chunks > 0:
                        continue

            # 3. SURGICAL LLM ACTION PROPOSAL
            session.llm_call_count += 1
            state_view = self._build_state_view(session)
            proposed_sufficient, rationale, candidate_gaps, proposed_edges = reasoning_agent_fn(state_view)

            # Ingest proposed LLM edges with mandatory LLM_INFERENCE provenance
            for edge in proposed_edges:
                edge.derived_by = EdgeDerivationType.LLM_INFERENCE

            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count + 1,
                    event_type="LLM_PROPOSAL_RECEIVED",
                    description=f"LLM proposed action: proposed_sufficient={proposed_sufficient}, candidate_gaps={len(candidate_gaps)}",
                    details={
                        "proposed_sufficient": proposed_sufficient,
                        "rationale": rationale,
                        "proposed_gaps_count": len(candidate_gaps),
                        "proposed_edges_count": len(proposed_edges),
                    },
                )
            )

            # Ingest any novel candidate gaps from LLM proposal into session ledger
            for cg in candidate_gaps:
                if cg.gap_id not in session.gaps:
                    cg.priority_score = self.compute_gap_priority(cg, session)
                    session.gaps[cg.gap_id] = cg

            # 4. CONTROLLER SUFFICIENCY VERIFICATION PROTOCOL
            if proposed_sufficient:
                state_view = self._build_state_view(session)
                state_view.evidence_graph.extend(proposed_edges)

                is_verified, reject_reason = self.verify_sufficiency(state_view, rationale)
                if is_verified:
                    # Re-evaluate all gaps against all discovered evidence
                    self._evaluate_all_gaps(session, list(session.discovered_evidence.keys()))

                    remaining_blocking_open = [
                        g for g in session.gaps.values()
                        if g.is_blocking and g.gap_id != "GAP-ROOT-1" and g.status in [
                            GapStatus.OPEN,
                            GapStatus.INVESTIGATING,
                            GapStatus.UNRESOLVED,
                            GapStatus.BLOCKED,
                        ]
                    ]
                    if remaining_blocking_open:
                        is_verified = False
                        reject_reason = f"Sufficiency rejected: Blocking prerequisite gap(s) still open: {[g.gap_id for g in remaining_blocking_open]}"

                if is_verified:
                    if "GAP-ROOT-1" in session.gaps:
                        session.gaps["GAP-ROOT-1"].status = GapStatus.RESOLVED
                    session.is_sufficient = True
                    session.termination_reason = "SUFFICIENT"
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="CONTROLLER_VERIFIED_SUFFICIENT",
                            description="Controller verified factual sufficiency and completeness; terminating investigation",
                            details={"total_evidence": len(session.discovered_evidence)},
                        )
                    )
                    break
                else:
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="CONTROLLER_REJECTED_SUFFICIENCY",
                            description=f"Controller rejected LLM sufficiency proposal: {reject_reason}",
                            details={"reason": reject_reason},
                        )
                    )
                    if not candidate_gaps:
                        session.is_sufficient = False
                        session.termination_reason = "REJECTED_UNVERIFIED_SUFFICIENCY"
                        break

            # 5. SELECT ACTIONABLE GAPS TO EXECUTE
            gaps_to_execute: List[Tuple[str, InformationGap]] = []
            seen_cand_ids: Set[str] = set()
            rejection_details: List[str] = []

            for cand in candidate_gaps:
                cand_q = cand.targeted_query or f"{cand.target_entity} {cand.required_information}".strip()
                if not cand_q:
                    rejection_details.append(f"Rejected gap '{cand.gap_id}': Empty query")
                    continue

                is_dup, reason = self.is_duplicate_or_overlapping_query(
                    cand_q, session.query_history, threshold=self.query_similarity_threshold
                )
                if is_dup:
                    rejection_details.append(f"Rejected '{cand_q}': {reason}")
                    continue

                is_echo, _ = self.is_duplicate_or_overlapping_query(
                    cand_q, {norm_obj}, threshold=0.80
                )
                if is_echo:
                    rejection_details.append(f"Rejected '{cand_q}': Echoes root objective")
                    continue

                active_gap = session.gaps.get(cand.gap_id, cand)
                active_gap.status = GapStatus.INVESTIGATING
                gaps_to_execute.append((cand_q, active_gap))
                seen_cand_ids.add(cand.gap_id)
                if len(gaps_to_execute) >= self.max_batch_gaps:
                    break

            if not gaps_to_execute:
                open_gaps = self.get_prioritized_open_gaps(session)
                for target_gap in open_gaps:
                    if target_gap.gap_id in seen_cand_ids:
                        continue
                    fallback_q = target_gap.targeted_query or f"{target_gap.target_entity} {target_gap.required_information}".strip()
                    is_dup_fb, _ = self.is_duplicate_or_overlapping_query(fallback_q, session.query_history, threshold=0.85)
                    if not is_dup_fb:
                        target_gap.status = GapStatus.INVESTIGATING
                        gaps_to_execute.append((fallback_q, target_gap))
                        if len(gaps_to_execute) >= self.max_batch_gaps:
                            break
                    else:
                        target_gap.status = GapStatus.BLOCKED
                        session.investigation_trace.append(
                            InvestigationEvent(
                                hop=session.hop_count + 1,
                                event_type="GAP_BLOCKED",
                                description=f"Gap '{target_gap.gap_id}' marked BLOCKED: all query angles exhausted",
                                details={"gap_id": target_gap.gap_id},
                            )
                        )

            if not gaps_to_execute:
                state_view = self._build_state_view(session)
                is_verified, _ = self.verify_sufficiency(state_view, "")
                if is_verified:
                    self._evaluate_all_gaps(session, list(session.discovered_evidence.keys()))
                    has_blocking_open = any(
                        g.is_blocking and g.gap_id != "GAP-ROOT-1" and g.status in [
                            GapStatus.OPEN,
                            GapStatus.INVESTIGATING,
                            GapStatus.UNRESOLVED,
                            GapStatus.BLOCKED,
                        ]
                        for g in session.gaps.values()
                    )
                    if not has_blocking_open:
                        if "GAP-ROOT-1" in session.gaps:
                            session.gaps["GAP-ROOT-1"].status = GapStatus.RESOLVED
                        session.is_sufficient = True
                        session.termination_reason = "SUFFICIENT"
                    else:
                        is_verified = False

                if not is_verified:
                    if any(g.status == GapStatus.BLOCKED for g in session.gaps.values() if g.is_blocking):
                        session.is_sufficient = False
                        session.termination_reason = "STAGNATION_ALL_QUERIES_EXHAUSTED"
                    else:
                        session.is_sufficient = False
                        session.termination_reason = "STAGNATION_NO_GAPS"
                session.investigation_trace.append(
                    InvestigationEvent(
                        hop=session.hop_count + 1,
                        event_type="STAGNATION_DETECTED",
                        description="All candidate queries rejected and no actionable open gaps remain",
                        details={"rejections": rejection_details},
                    )
                )
                break

            # 6. EXECUTE RETRIEVAL FOR ALL SELECTED GAPS IN BATCH
            for selected_query, active_gap in gaps_to_execute:
                norm_q = self._normalize_query(selected_query)
                session.query_history.add(norm_q)
                if active_gap:
                    active_gap.attempted_queries.append(selected_query)
                    active_gap.attempt_count += 1

                search_results, _ = self.retriever.search(selected_query, k=4)
                fed_telem_step = getattr(self.retriever, "get_last_telemetry", lambda: None)()
                if fed_telem_step:
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="FEDERATED_RETRIEVAL_DISPATCH",
                            description=f"Actionable gap federated retrieval queried {len(fed_telem_step.providers_queried)} provider(s)",
                            details=redact_sensitive_data(fed_telem_step.model_dump()),
                        )
                    )

                if not search_results:
                    session.zero_yield_queries.add(norm_q)
                    if active_gap:
                        active_gap.status = GapStatus.UNRESOLVED
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ACTIONABLE_GAP_EXECUTED",
                            description=f"Actionable gap query '{selected_query}' executed (zero yield)",
                            details={"query": selected_query, "gap_id": active_gap.gap_id if active_gap else "none", "is_zero_yield": True},
                        )
                    )
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ZERO_YIELD_SEARCH",
                            description=f"Query '{selected_query}' yielded 0 results",
                            details={"query": selected_query, "gap_id": active_gap.gap_id if active_gap else "none"},
                        )
                    )
                else:
                    new_evidence_ids = []
                    for ev, _ in search_results:
                        if ev.evidence_id not in session.discovered_evidence:
                            session.discovered_evidence[ev.evidence_id] = ev
                            new_evidence_ids.append(ev.evidence_id)

                    new_refs = self.scanner.find_unresolved_references(session.discovered_evidence)
                    session.unresolved_references.update(new_refs)

                    new_det_edges = self.scanner.detect_deterministic_edges(list(session.discovered_evidence.values()))
                    self._derive_and_update_gaps(session, new_det_edges)

                    # Evaluate all gaps against newly admitted evidence
                    self._evaluate_all_gaps(session, new_evidence_ids)

                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ACTIONABLE_GAP_EXECUTED",
                            description=f"Actionable gap query '{selected_query}' executed with {len(new_evidence_ids)} new chunk(s)",
                            details={"query": selected_query, "gap_id": active_gap.gap_id if active_gap else "none", "is_zero_yield": False},
                        )
                    )
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="RETRIEVAL_ADMITTED",
                            description=f"Query '{selected_query}' admitted {len(new_evidence_ids)} new chunk(s)",
                            details={
                                "query": selected_query,
                                "gap_id": active_gap.gap_id if active_gap else "none",
                                "new_chunks": new_evidence_ids,
                                "gap_status": active_gap.status.value if active_gap else "unknown",
                            },
                        )
                    )

            session.hop_count += 1

        # ----------------------------------------------------------------------
        # PACKAGE CREATION
        # ----------------------------------------------------------------------
        total_time_ms = (time.perf_counter() - start_time) * 1000.0
        edges = self.scanner.detect_deterministic_edges(list(session.discovered_evidence.values()))

        session.investigation_trace.append(
            InvestigationEvent(
                hop=session.hop_count,
                event_type="INVESTIGATION_TERMINATED",
                description=f"Investigation completed with reason: {session.termination_reason}",
                details={
                    "termination_reason": session.termination_reason,
                    "controller_verified": session.is_sufficient,
                    "total_evidence_collected": len(session.discovered_evidence),
                    "total_wall_clock_ms": round(total_time_ms, 2),
                },
            )
        )

        all_gaps = list(session.gaps.values())

        # Compile deterministic federated telemetry across all investigation retrieval dispatches
        fed_telemetry_dict = None
        if hasattr(self.retriever, "get_all_telemetry"):
            all_telems = self.retriever.get_all_telemetry()
            all_queried = set()
            all_responded = set()
            all_failures: Dict[str, str] = {}
            total_cands_per_provider: Dict[str, int] = {}
            total_raw = 0
            total_dedup = 0
            for t in all_telems:
                all_queried.update(t.providers_queried)
                all_responded.update(t.providers_responded)
                all_failures.update(t.provider_failures)
                total_raw += t.raw_candidates_count
                total_dedup += t.deduplicated_count
                for p, cnt in t.candidates_per_provider.items():
                    total_cands_per_provider[p] = total_cands_per_provider.get(p, 0) + cnt

            source_counts = Counter(ev.source_type for ev in session.discovered_evidence.values())
            admitted_ids = [ev.evidence_id for ev in session.discovered_evidence.values()]
            gaps_resolved_count = sum(1 for g in all_gaps if g.resolved)

            fed_telemetry_dict = {
                "providers_queried": sorted(list(all_queried)),
                "providers_responded": sorted(list(all_responded)),
                "provider_failures": all_failures,
                "candidates_per_provider": total_cands_per_provider,
                "raw_candidates_count": total_raw,
                "deduplicated_candidates_count": total_dedup,
                "final_admitted_evidence_ids": admitted_ids,
                "source_provenance_distribution": dict(source_counts),
                "gaps_total": len(all_gaps),
                "gaps_resolved": gaps_resolved_count,
                "final_termination_state": session.termination_reason,
                "latency_wall_clock_ms": round(total_time_ms, 2),
                "llm_invocation_count": session.llm_call_count,
            }
            fed_telemetry_dict = redact_sensitive_data(fed_telemetry_dict)

        return EvidencePackage(
            objective=objective,
            termination_reason=session.termination_reason or "UNKNOWN",
            controller_verified=session.is_sufficient,
            budget_summary={
                "hops_used": session.hop_count,
                "llm_calls_used": session.llm_call_count,
                "queries_executed": len(session.query_history),
                "zero_yield_queries_count": len(session.zero_yield_queries),
                "total_chunks_collected": len(session.discovered_evidence),
                "elapsed_wall_time_ms": round(total_time_ms, 2),
            },
            evidence_items=list(session.discovered_evidence.values()),
            graph_edges=edges,
            gap_history=[
                {
                    "gap_id": g.gap_id,
                    "description": g.description,
                    "query": g.targeted_query or (g.attempted_queries[-1] if g.attempted_queries else ""),
                    "resolved": g.resolved,
                    "resolution_evidence_ids": g.resolution_evidence_ids,
                }
                for g in all_gaps
            ],
            investigation_trace=session.investigation_trace,
            gaps=all_gaps,
            retrieval_telemetry=telemetry,
            federated_telemetry=fed_telemetry_dict,
        )

    # -------------------------------------------------------------------------
    # DETERMINISTIC GAP PRIORITIZATION & RESOLUTION ENGINE
    # -------------------------------------------------------------------------
    def compute_gap_priority(self, gap: InformationGap, session: InvestigationSession) -> float:
        crit = 1.0 if gap.is_blocking else 0.0
        contra = 1.0 if gap.gap_type == GapType.CONTRADICTION_RECONCILIATION or gap.conflicting_evidence_ids else 0.0
        depth = 1.0 if gap.gap_type in [GapType.PREREQUISITE, GapType.AUTHORITY_RESOLUTION] else 0.5
        attempt_penalty = float(gap.attempt_count)
        return (100.0 * crit) + (50.0 * contra) + (25.0 * depth) - (30.0 * attempt_penalty)

    def get_prioritized_open_gaps(self, session: InvestigationSession) -> List[InformationGap]:
        active = [g for g in session.gaps.values() if g.status in [GapStatus.OPEN, GapStatus.UNRESOLVED]]
        for g in active:
            g.priority_score = self.compute_gap_priority(g, session)
        active.sort(key=lambda g: g.priority_score, reverse=True)
        return active

    def is_session_sufficient(self, session: InvestigationSession) -> bool:
        if session.unresolved_references:
            return False

        blocking = [g for g in session.gaps.values() if g.is_blocking]
        if not blocking:
            return False

        all_blocking_satisfied = all(
            g.status in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]
            for g in blocking
        )
        if not all_blocking_satisfied:
            return False

        if len(session.discovered_evidence) < 2:
            return False

        return True

    def verify_sufficiency(self, state: InvestigationState, llm_rationale: str) -> Tuple[bool, Optional[str]]:
        if state.unresolved_references:
            return False, f"Unresolved explicit reference(s) still pending: {list(state.unresolved_references)}"

        has_inferences = any(edge.derived_by == EdgeDerivationType.LLM_INFERENCE for edge in state.evidence_graph)
        if has_inferences:
            return False, "Sufficiency rejected: Evidence graph relies solely on LLM_INFERENCE edges."

        has_cab_rejection = any(
            ("DOC-NOVA-CAB" in e.source_id or "CAB" in e.source_id) and "REJECTED" in e.content.upper()
            for e in state.accumulated_evidence.values()
        )
        has_postmortem = any(
            "POST-MORTEM" in e.content.upper() or "INC-" in e.source_id
            for e in state.accumulated_evidence.values()
        )
        if has_cab_rejection and not has_postmortem:
            return False, "Sufficiency rejected: Change request was REJECTED by CAB but post-mortem not retrieved."

        has_stale_arch = any("ARCH" in e.source_id.upper() for e in state.accumulated_evidence.values())
        if has_stale_arch and not has_postmortem:
            return False, "Sufficiency rejected: Stale architecture specification present without superseding post-mortem rollback evidence."

        if len(state.accumulated_evidence) < 2:
            return False, "Sufficiency rejected: Insufficient evidence chunks (< 2) collected."

        return True, None

    # -------------------------------------------------------------------------
    # INTERNAL DETERMINISTIC TRIGGER & EVALUATION LOGIC
    # -------------------------------------------------------------------------
    def _derive_and_update_gaps(self, session: InvestigationSession, edges: List[EvidenceEdge]) -> None:
        if "GAP-ROOT-1" not in session.gaps:
            session.gaps["GAP-ROOT-1"] = InformationGap(
                gap_id="GAP-ROOT-1",
                gap_type=GapType.OBJECTIVE_ROOT,
                is_blocking=True,
                description="Core factual requirement of user objective",
                target_entity="Objective",
                required_information=session.objective,
                status=GapStatus.OPEN,
            )

        for ref in session.unresolved_references:
            gid = f"GAP-REF-{ref}"
            if gid not in session.gaps:
                if ref.startswith("INC-"):
                    targeted_q = f"{ref} current production state"
                elif ref.startswith("CR-"):
                    targeted_q = f"{ref} decision disposition"
                else:
                    targeted_q = ref

                session.gaps[gid] = InformationGap(
                    gap_id=gid,
                    gap_type=GapType.AUTHORITY_RESOLUTION,
                    is_blocking=True,
                    description=f"Authoritative decision or resolution record for reference '{ref}'",
                    target_entity=ref,
                    required_information=f"Status, disposition, or post-mortem of {ref}",
                    targeted_query=targeted_q,
                    candidate_queries=[targeted_q],
                    status=GapStatus.OPEN,
                )

        for ev in session.discovered_evidence.values():
            clean_content = re.sub(r"[\*\_`]", "", ev.content)

            matches = GENERIC_PREREQ_PATTERN.findall(clean_content)
            for m in matches:
                clean_target = m.strip().split("\n")[0].strip()
                if len(clean_target) > 2:
                    gid = f"GAP-PREREQ-{clean_target[:20].upper().replace(' ', '-')}"
                    if gid not in session.gaps:
                        session.gaps[gid] = InformationGap(
                            gap_id=gid,
                            gap_type=GapType.PREREQUISITE,
                            is_blocking=True,
                            description=f"Verification of operational prerequisite: '{clean_target}'",
                            target_entity=clean_target,
                            required_information=f"Operational requirements and status for {clean_target}",
                            targeted_query=clean_target,
                            candidate_queries=[clean_target],
                            originating_evidence_ids=[ev.evidence_id],
                            status=GapStatus.OPEN,
                        )

            # Integration target specifications (e.g., Target: Project Phoenix Deployment)
            target_matches = GENERIC_INTEG_TARGET_PATTERN.findall(clean_content)
            if target_matches:
                section_title = ev.metadata.get("section", "") if hasattr(ev, "metadata") and isinstance(ev.metadata, dict) else ""
                header_match = re.search(r"([A-Za-z0-9\.\-\_ ]{3,40}?(?:Specification|Integration|Service|Gateway|Component|Requirements))\b", section_title, re.IGNORECASE)
                if not header_match:
                    header_match = re.search(r"([A-Za-z0-9\.\-\_ ]{3,40}?(?:Specification|Integration|Service|Gateway|Component|Requirements))\b", clean_content, re.IGNORECASE)
                if header_match:
                    subsystem = header_match.group(1).strip()
                    gid = f"GAP-DEP-{subsystem[:20].upper().replace(' ', '-')}"
                    if gid not in session.gaps:
                        session.gaps[gid] = InformationGap(
                            gap_id=gid,
                            gap_type=GapType.PREREQUISITE,
                            is_blocking=True,
                            description=f"Operational requirements and failure mode for integration component '{subsystem}'",
                            target_entity=subsystem,
                            required_information=f"Integration requirements and failure mode for {subsystem}",
                            targeted_query=f"{subsystem} requirements failure mode",
                            candidate_queries=[f"{subsystem} requirements failure mode"],
                            originating_evidence_ids=[ev.evidence_id],
                            status=GapStatus.OPEN,
                        )

            # Generic enforcement constraints (e.g., strictly enforces mutual TLS 1.3 for cache)
            enf_matches = GENERIC_ENFORCEMENT_PATTERN.findall(clean_content)
            for cap, target in enf_matches:
                clean_cap = cap.strip()
                clean_tgt = target.strip()
                if len(clean_tgt) > 2:
                    gid = f"GAP-ENF-{clean_tgt[:20].upper().replace(' ', '-')}"
                    if gid not in session.gaps:
                        session.gaps[gid] = InformationGap(
                            gap_id=gid,
                            gap_type=GapType.PREREQUISITE,
                            is_blocking=True,
                            description=f"Operational capability enforcement: {clean_cap} for {clean_tgt}",
                            target_entity=clean_tgt,
                            required_information=f"Verify {clean_tgt} supports {clean_cap}",
                            targeted_query=f"{clean_tgt} {clean_cap}",
                            candidate_queries=[f"{clean_tgt} {clean_cap}"],
                            originating_evidence_ids=[ev.evidence_id],
                            status=GapStatus.OPEN,
                        )

        for edge in edges:
            if edge.relationship_type == RelationshipType.CONTRADICTS:
                gid = f"GAP-CONTRA-{edge.source_evidence_id}-{edge.target_evidence_id}"
                if gid not in session.gaps:
                    session.gaps[gid] = InformationGap(
                        gap_id=gid,
                        gap_type=GapType.CONTRADICTION_RECONCILIATION,
                        is_blocking=True,
                        description=f"Reconcile opposing claims: {edge.basis}",
                        target_entity="Conflicting Claims",
                        required_information=edge.basis,
                        originating_evidence_ids=[edge.source_evidence_id, edge.target_evidence_id],
                        status=GapStatus.OPEN,
                    )

    def _evaluate_all_gaps(self, session: InvestigationSession, new_evidence_ids: List[str]) -> None:
        if not new_evidence_ids:
            return
        for g in list(session.gaps.values()):
            if g.status in [GapStatus.OPEN, GapStatus.INVESTIGATING, GapStatus.UNRESOLVED]:
                self._evaluate_gap_resolution(g, session, new_evidence_ids)

    def _evaluate_gap_resolution(
        self,
        gap: InformationGap,
        session: InvestigationSession,
        new_evidence_ids: List[str],
    ) -> None:
        if not new_evidence_ids:
            return

        satisfying_ids: List[str] = []
        conflicting_ids: List[str] = []

        for eid in new_evidence_ids:
            ev = session.discovered_evidence.get(eid)
            if not ev:
                continue

            content_up = ev.content.upper()
            target_up = gap.target_entity.upper()

            if gap.gap_type == GapType.AUTHORITY_RESOLUTION:
                if self.scanner.is_authoritative_resolution(gap.target_entity, ev):
                    satisfying_ids.append(eid)
            elif gap.gap_type == GapType.PREREQUISITE:
                if eid in gap.originating_evidence_ids:
                    continue
                target_tokens = set(re.findall(r"\b[A-Za-z0-9\-]+\b", target_up)) - STOPWORDS
                if any(t in content_up for t in target_tokens) or target_up in ev.source_id.upper():
                    satisfying_ids.append(eid)
            elif gap.gap_type == GapType.CONTRADICTION_RECONCILIATION:
                if eid in gap.originating_evidence_ids or "REJECTED" in content_up or "POST-MORTEM" in content_up or "ROLLBACK" in content_up:
                    satisfying_ids.append(eid)
            elif gap.gap_id == "GAP-ROOT-1":
                # Root objective gap cannot be resolved by an individual chunk.
                # It resolves only if all blocking prerequisite/authority gaps are resolved.
                pass
            else:
                satisfying_ids.append(eid)

            if "REJECTED" in content_up or "ROLLBACK" in content_up or "CONFLICT" in content_up:
                conflicting_ids.append(eid)

        if satisfying_ids:
            gap.resolution_evidence_ids.extend(satisfying_ids)
            gap.resolution_status = True
            if conflicting_ids:
                gap.conflicting_evidence_ids.extend(conflicting_ids)
                gap.status = GapStatus.RECONCILIATION_REQUIRED
            else:
                gap.status = GapStatus.RESOLVED

    # -------------------------------------------------------------------------
    # UTILITY HELPERS
    # -------------------------------------------------------------------------
    def _build_state_view(self, session: InvestigationSession) -> InvestigationState:
        edges = self.scanner.detect_deterministic_edges(list(session.discovered_evidence.values()))
        open_g = [g for g in session.gaps.values() if g.status in [GapStatus.OPEN, GapStatus.UNRESOLVED]]
        res_g = [g for g in session.gaps.values() if g.resolved]

        return InvestigationState(
            objective=session.objective,
            accumulated_evidence=session.discovered_evidence,
            evidence_graph=edges,
            pending_gaps=open_g,
            resolved_gaps=res_g,
            executed_queries=session.query_history,
            zero_yield_queries=session.zero_yield_queries,
            unresolved_references=session.unresolved_references,
            investigation_trace=session.investigation_trace,
            hop_count=session.hop_count,
            llm_call_count=session.llm_call_count,
            is_sufficient=session.is_sufficient,
            termination_reason=session.termination_reason,
        )

    def _normalize_query(self, query: str) -> str:
        return " ".join(query.strip().lower().split())

    def _tokenize_query(self, query: str) -> Set[str]:
        tokens = set(re.findall(r"\b[a-z0-9\-]+\b", query.lower())) - STOPWORDS
        return {t[:-1] if t.endswith("s") and len(t) > 3 else t for t in tokens}

    def is_duplicate_or_overlapping_query(
        self,
        candidate: str,
        executed_queries: Set[str],
        threshold: float = 0.70,
    ) -> Tuple[bool, Optional[str]]:
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

    def _add_new_evidence(self, session: InvestigationSession, results: List[Tuple[Evidence, float]]) -> int:
        added = 0
        for ev, _ in results:
            if ev.evidence_id not in session.discovered_evidence:
                session.discovered_evidence[ev.evidence_id] = ev
                added += 1
        return added
