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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from backend.evidence.models import Evidence
from backend.investigation.entity_scanner import (
    CR_DECISION_PATTERN,
    INCIDENT_RESOLUTION_PATTERN,
    EntityScanner,
)
from backend.investigation.models import (
    ActionStatus,
    ActionType,
    AdaptiveRetrievalConfig,
    ContradictionRecord,
    EdgeDerivationType,
    EvidenceEdge,
    EvidencePackage,
    GapStatus,
    GapType,
    InformationGap,
    InvalidGapTransitionError,
    InvestigationAction,
    InvestigationBudget,
    InvestigationEvent,
    InvestigationHypothesis,
    InvestigationPlan,
    InvestigationSession,
    InvestigationState,
    RelationshipType,
    RetrievalDecisionTelemetry,
    VALID_GAP_TRANSITIONS,
)
from backend.investigation.evaluator import EntityScopedEvaluator
from backend.investigation.planner import InvestigationPlanner
from backend.investigation.polarity import OppositionEngine
from backend.investigation.semantic_dedup import SemanticQueryDeduplicator
from backend.investigation.dag import DependencyGraph
from backend.retrieval.provider import EvidenceProvider
from backend.core.security import redact_sensitive_data

STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "and", "or", "in", "on", "at",
    "to", "for", "of", "with", "by", "from", "can", "what", "how", "this", "that",
    "it", "its", "be", "do", "does", "did", "under", "before", "after", "we",
    "should", "could", "would"
}

GENERIC_ENTITY_NOUNS = {
    "SERVICE", "SERVICES", "COMPONENT", "COMPONENTS", "SYSTEM", "SYSTEMS",
    "MODULE", "MODULES", "GATEWAY", "GATEWAYS", "APP", "SERVER", "DATABASE",
    "DOCUMENT", "SPECIFICATION", "INTEGRATION", "TECHNICAL", "REQUIREMENTS"
}

GENERIC_REQ_WORDS = {
    "VERIFY", "CHECK", "FIND", "REQUIREMENTS", "REQUIREMENT", "STATUS",
    "OPERATIONAL", "DETAILS", "INFORMATION", "INFO", "STATE", "IDENTIFY",
    "PROVIDE", "SEARCH"
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
        planner: Optional[InvestigationPlanner] = None,
        budget: Optional[InvestigationBudget] = None,
        query_similarity_threshold: float = 0.70,
        adaptive_retrieval_config: Optional[AdaptiveRetrievalConfig] = None,
        max_batch_gaps: int = 1,
        opposition_engine: Optional[OppositionEngine] = None,
        evaluator: Optional[EntityScopedEvaluator] = None,
        deduplicator: Optional[SemanticQueryDeduplicator] = None,
        dag: Optional[DependencyGraph] = None,
    ):
        self.retriever = retriever
        self.scanner = scanner or EntityScanner()
        self.planner = planner or InvestigationPlanner(scanner=self.scanner, jaccard_threshold=query_similarity_threshold)
        self.budget = budget or InvestigationBudget()
        self.query_similarity_threshold = query_similarity_threshold
        self.adaptive_config = adaptive_retrieval_config or AdaptiveRetrievalConfig()
        self.max_batch_gaps = max_batch_gaps
        self.opposition_engine = opposition_engine or OppositionEngine()
        self.evaluator = evaluator or EntityScopedEvaluator(scanner=self.scanner, opposition_engine=self.opposition_engine)
        self.deduplicator = deduplicator or SemanticQueryDeduplicator(
            semantic_threshold=0.75, lexical_threshold=query_similarity_threshold
        )
        self.dag = dag or DependencyGraph()

    def transition_gap(
        self,
        gap: InformationGap,
        target_status: GapStatus,
        reason: str = "",
        session: Optional[InvestigationSession] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Controller-owned gap state transition validator.
        Enforces VALID_GAP_TRANSITIONS; rejects invalid transitions.
        """
        allowed = VALID_GAP_TRANSITIONS.get(gap.status, set())
        if target_status not in allowed and target_status != gap.status:
            raise InvalidGapTransitionError(
                f"Invalid gap transition from {gap.status.value} to {target_status.value} for gap '{gap.gap_id}': {reason}"
            )
        old_status = gap.status
        gap.status = target_status
        gap.gap_version += 1
        if session:
            session.session_version += 1
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count,
                    event_type="GAP_TRANSITION",
                    description=f"Gap '{gap.gap_id}' transitioned {old_status.value} -> {target_status.value}: {reason}",
                    details={
                        "gap_id": gap.gap_id,
                        "from_status": old_status.value,
                        "to_status": target_status.value,
                        "reason": reason,
                        **(metadata or {}),
                    },
                )
            )
        return True

    def register_gap_dependency(
        self,
        session: InvestigationSession,
        dependent_gap_id: str,
        prerequisite_gap_id: Any,
    ) -> bool:
        """
        Explicitly registers a directed prerequisite edge in the session gap DAG.
        dependent_gap_id depends on prerequisite_gap_id.
        Supports passing either a single gap_id or a collection of prerequisite gap_ids.
        Validates graph structure (cycles, self-dependencies, nonexistent gaps).
        """
        if isinstance(prerequisite_gap_id, (list, set, tuple)):
            all_ok = True
            for pid in prerequisite_gap_id:
                if not self.register_gap_dependency(session, dependent_gap_id, pid):
                    all_ok = False
            return all_ok

        existing_ids = set(session.gaps.keys())
        val_res = self.dag.add_dependency(dependent_gap_id, prerequisite_gap_id, existing_ids, session.gaps)
        if not val_res.is_valid:
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count,
                    event_type="INVALID_DEPENDENCY_GRAPH",
                    description=f"Dependency rejected ({val_res.error_type}): {val_res.error_message}",
                    details=val_res.model_dump(),
                )
            )
            return False

        dep_gap = session.gaps.get(dependent_gap_id)
        if dep_gap and dep_gap.unsatisfied_prerequisites:
            if dep_gap.status != GapStatus.DEPENDENCY_UNSATISFIED:
                try:
                    self.transition_gap(
                        dep_gap,
                        GapStatus.DEPENDENCY_UNSATISFIED,
                        reason=f"Prerequisite gap '{prerequisite_gap_id}' is unresolved",
                        session=session,
                    )
                except InvalidGapTransitionError:
                    dep_gap.status = GapStatus.DEPENDENCY_UNSATISFIED
        return True

    def propagate_dependency_invalidation(
        self,
        session: InvestigationSession,
        invalidated_gap_id: str,
        reason: str = "",
    ) -> List[str]:
        """
        Topologically propagates invalidation down the DAG.
        If gap A is invalidated / reopened / blocked / reconciliation_required,
        all downstream gaps B that depend on A transition to DEPENDENCY_UNSATISFIED.
        """
        affected = self.dag.propagate_invalidation(invalidated_gap_id, session.gaps)
        for gid in affected:
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count,
                    event_type="GAP_DEPENDENCY_UNSATISFIED",
                    description=f"Gap '{gid}' marked DEPENDENCY_UNSATISFIED due to upstream invalidation of '{invalidated_gap_id}': {reason}",
                    details={"invalidated_prereq": invalidated_gap_id},
                )
            )
        return affected

    def propagate_dependency_restoration(
        self,
        session: InvestigationSession,
        resolved_gap_id: str,
    ) -> List[str]:
        """
        Topologically propagates satisfaction down the DAG.
        Downstream gaps only transition to OPEN when ALL prerequisites are satisfied.
        """
        restored = self.dag.propagate_restoration(resolved_gap_id, session.gaps)
        for gid in restored:
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count,
                    event_type="GAP_DEPENDENCY_RESTORED",
                    description=f"Gap '{gid}' restored to OPEN because all prerequisites (including '{resolved_gap_id}') are satisfied",
                    details={"restored_by": resolved_gap_id},
                )
            )
        return restored

    def validate_action(
        self,
        action: InvestigationAction,
        session: InvestigationSession,
    ) -> Tuple[bool, Optional[str]]:
        """
        Controller-owned action validator.
        Normalizes, validates, and deduplicates proposed search queries against query history.
        Enforces controller authority: LLM cannot target root gap or gaps with unsatisfied prerequisites.
        """
        norm_q = self._normalize_query(action.query)
        if not norm_q:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = "Empty search query"
            return False, action.rejection_reason

        tokens = self._tokenize_query(action.query)
        if not tokens:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = "Query contains only stopwords"
            return False, action.rejection_reason

        if len(action.query) > 200:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = "Query exceeds maximum length of 200 characters"
            return False, action.rejection_reason

        # 1. Check duplicate / overlap against executed queries (Lexical)
        is_dup, dup_reason = self.is_duplicate_or_overlapping_query(
            action.query, session.query_history, threshold=self.query_similarity_threshold
        )
        if is_dup:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = dup_reason
            return False, dup_reason

        # Check duplicate against zero yield queries (Lexical)
        is_zero_dup, zero_reason = self.is_duplicate_or_overlapping_query(
            action.query, session.zero_yield_queries, threshold=0.75
        )
        if is_zero_dup:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = f"Near-duplicate of failed zero-yield query: {zero_reason}"
            return False, action.rejection_reason

        # Semantic query deduplication check (Paraphrase & Intent protection)
        gap = session.gaps.get(action.gap_id)
        sem_res = self.deduplicator.check_duplicate(
            action.query,
            session.query_history,
            context={"gap": gap, "session": session, "objective": session.objective}
        )
        if sem_res.is_duplicate:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = sem_res.rejection_reason or f"Semantic paraphrase duplicate of '{sem_res.comparison_query}'"
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count,
                    event_type="SEMANTIC_QUERY_DEDUPLICATION_REJECTION",
                    description=f"Action '{action.action_id}' rejected as semantic duplicate of '{sem_res.comparison_query}'",
                    details=sem_res.model_dump(),
                )
            )
            return False, action.rejection_reason

        # 2. CONTROLLER AUTHORITY: Check root gap bypass and gap association
        if action.gap_id == "GAP-ROOT-1":
            action.status = ActionStatus.REJECTED
            action.rejection_reason = "Direct search action against root objective gap (GAP-ROOT-1 / OBJECTIVE_ROOT) is prohibited; actions must target decomposed child gaps"
            return False, action.rejection_reason

        if action.gap_id not in session.gaps:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = f"Referenced gap '{action.gap_id}' does not exist in session"
            return False, action.rejection_reason

        associated_gap = session.gaps[action.gap_id]

        if associated_gap.gap_type == GapType.OBJECTIVE_ROOT:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = "Direct search action against root objective gap (GAP-ROOT-1 / OBJECTIVE_ROOT) is prohibited; actions must target decomposed child gaps"
            return False, action.rejection_reason

        # DEPENDENCY INVARIANT: Disallow actions against gaps with unsatisfied prerequisites
        if associated_gap.status == GapStatus.DEPENDENCY_UNSATISFIED:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = f"Associated gap '{action.gap_id}' has unsatisfied prerequisites: {associated_gap.unsatisfied_prerequisites}"
            return False, action.rejection_reason

        if associated_gap.status == GapStatus.RESOLVED:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = f"Associated gap '{action.gap_id}' is already RESOLVED"
            return False, action.rejection_reason

        # Check root objective echo (threshold 0.55 or containment of objective non-stopword tokens)
        norm_obj = self._normalize_query(session.objective)
        is_echo, _ = self.is_duplicate_or_overlapping_query(action.query, {norm_obj}, threshold=0.55)
        if not is_echo:
            obj_tokens = self._tokenize_query(session.objective)
            act_tokens = self._tokenize_query(action.query)
            if obj_tokens and act_tokens:
                # Exclude target entity tokens so multi-word entities don't trigger false echo detection
                ent_tokens: Set[str] = set()
                if associated_gap and associated_gap.target_entity:
                    ent_tokens = {t.lower() for t in self.evaluator.extract_entity_tokens(associated_gap.target_entity)}
                obj_non_ent = {t for t in obj_tokens if t not in ent_tokens}
                act_non_ent = {t for t in act_tokens if t not in ent_tokens}

                if obj_non_ent and act_non_ent:
                    overlap = len(obj_non_ent.intersection(act_non_ent))
                    containment = overlap / min(len(obj_non_ent), len(act_non_ent))
                    if containment >= 0.60 and overlap >= 2:
                        is_echo = True
                else:
                    overlap = len(obj_tokens.intersection(act_tokens))
                    containment = overlap / min(len(obj_tokens), len(act_tokens))
                    if containment >= 0.70 and overlap >= 3:
                        is_echo = True
        if is_echo:
            action.status = ActionStatus.REJECTED
            action.rejection_reason = "Echoes root objective without decomposing into specific child requirements"
            return False, action.rejection_reason

        action.status = ActionStatus.APPROVED
        return True, None

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
            hypotheses=[],
            discovered_evidence={},
            unresolved_references=set(),
            gaps={},
            detected_contradictions=[],
            actions=[],
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
        # PHASE 1: INVESTIGATION PLANNING (QUESTION -> HYPOTHESES & INITIAL GAPS)
        # ----------------------------------------------------------------------
        plan = self.planner.plan(
            objective=objective,
            priority_evaluator=lambda g: self.compute_gap_priority(g, session),
        )
        session.hypotheses = plan.hypotheses
        for g in plan.gaps:
            session.gaps[g.gap_id] = g

        session.investigation_trace.append(
            InvestigationEvent(
                hop=0,
                event_type="INVESTIGATION_PLANNED",
                description=f"Investigation plan formulated with {len(plan.hypotheses)} hypotheses and {len(plan.gaps)} gaps",
                details={
                    "hypotheses": [h.statement for h in plan.hypotheses],
                    "gaps": [g.gap_id for g in plan.gaps],
                    "actions_planned": [a.query for a in plan.planned_actions],
                },
            )
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
        self._evaluate_all_gaps(session, [e.evidence_id for e, _ in final_candidates])

        session.hop_count = 0
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

            if session.hop_count >= session.max_hops:
                # Before terminating due to max hops, check if current evidence is sufficient
                state_view = self._build_state_view(session)
                is_ver, _ = self.verify_sufficiency(state_view, "Final hop sufficiency evaluation")
                if is_ver:
                    remaining_blocking = [
                        g for g in session.gaps.values()
                        if g.is_blocking and g.gap_id != "GAP-ROOT-1" and not g.resolved
                    ]
                    if not remaining_blocking:
                        if "GAP-ROOT-1" in session.gaps:
                            session.gaps["GAP-ROOT-1"].status = GapStatus.RESOLVED
                        session.is_sufficient = True
                        session.termination_reason = "SUFFICIENT"
                        session.investigation_trace.append(
                            InvestigationEvent(
                                hop=session.hop_count,
                                event_type="CONTROLLER_VERIFIED_SUFFICIENT",
                                description="Controller verified factual sufficiency upon final hop evidence evaluation",
                                details={"total_evidence": len(session.discovered_evidence)},
                            )
                        )
                        break

                # If not verified and LLM budget remains, allow reasoning agent one final synthesis call (no more retrievals)
                if session.llm_call_count < session.max_llm_calls:
                    session.llm_call_count += 1
                    proposed_sufficient, rationale, candidate_gaps, proposed_edges = reasoning_agent_fn(state_view)
                    if proposed_sufficient:
                        self._evaluate_all_gaps(session, list(session.discovered_evidence.keys()))
                        state_view = self._build_state_view(session)
                        state_view.evidence_graph.extend(proposed_edges)
                        is_ver_llm, _ = self.verify_sufficiency(state_view, rationale)
                        remaining_blocking_llm = [
                            g for g in session.gaps.values()
                            if g.is_blocking and g.gap_id != "GAP-ROOT-1" and not g.resolved
                        ]
                        if is_ver_llm and not remaining_blocking_llm:
                            if "GAP-ROOT-1" in session.gaps:
                                session.gaps["GAP-ROOT-1"].status = GapStatus.RESOLVED
                            session.is_sufficient = True
                            session.termination_reason = "SUFFICIENT"
                            session.investigation_trace.append(
                                InvestigationEvent(
                                    hop=session.hop_count,
                                    event_type="CONTROLLER_VERIFIED_SUFFICIENT",
                                    description="Controller verified factual sufficiency following agent proposal upon final hop",
                                    details={"total_evidence": len(session.discovered_evidence)},
                                )
                            )
                            break

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
                    session.hop_count += 1
                    fp_action = InvestigationAction(
                        action_id=f"ACT-FASTPATH-{len(session.actions)+1:02d}",
                        gap_id=target_gap.gap_id if target_gap else f"GAP-REF-{target_token}",
                        action_type=ActionType.SEARCH,
                        query=dispatch_query,
                        reason=f"Fast-path query for unresolved token '{target_token}'",
                        status=ActionStatus.APPROVED,
                        created_at_hop=session.hop_count,
                        executed_at_hop=session.hop_count,
                    )
                    session.query_history.add(self._normalize_query(dispatch_query))
                    ref_results, _ = self.retriever.search(dispatch_query, k=4)
                    fp_action.yield_chunk_count = len(ref_results)
                    fp_action.status = ActionStatus.EXECUTED
                    session.actions.append(fp_action)

                    if target_gap:
                        target_gap.attempted_actions.append(fp_action)
                        target_gap.attempted_queries.append(dispatch_query)
                        target_gap.attempt_count += 1
                        self.transition_gap(target_gap, GapStatus.SEARCHING, reason="Fast-path dispatch", session=session)

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

                    if session.hop_count >= session.max_hops:
                        session.termination_reason = "BUDGET_EXHAUSTED_MAX_HOPS"
                        break

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
            # Controller invariant: The LLM cannot directly set gap status to RESOLVED,
            # and cannot propose/modify GAP-ROOT-1.
            for cg in candidate_gaps:
                if cg.gap_id == "GAP-ROOT-1" or cg.gap_type == GapType.OBJECTIVE_ROOT:
                    continue
                if cg.status in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]:
                    cg.status = GapStatus.OPEN
                if cg.gap_id not in session.gaps:
                    cg.priority_score = self.compute_gap_priority(cg, session)
                    cg.status = GapStatus.PLANNED
                    session.gaps[cg.gap_id] = cg

            # 4. CONTROLLER SUFFICIENCY VERIFICATION PROTOCOL
            if proposed_sufficient:
                # Re-evaluate all gaps against all discovered evidence
                self._evaluate_all_gaps(session, list(session.discovered_evidence.keys()))

                state_view = self._build_state_view(session)
                state_view.evidence_graph.extend(proposed_edges)

                is_verified, reject_reason = self.verify_sufficiency(state_view, rationale)
                if is_verified:
                    remaining_blocking_open = [
                        g for g in session.gaps.values()
                        if g.is_blocking and g.gap_id != "GAP-ROOT-1" and not g.resolved
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
            gaps_to_execute: List[Tuple[InvestigationAction, InformationGap]] = []
            seen_cand_ids: Set[str] = set()
            rejection_details: List[str] = []

            for cand in candidate_gaps:
                cand_q = cand.targeted_query or f"{cand.target_entity} {cand.required_information}".strip()
                action = InvestigationAction(
                    action_id=f"ACT-HOP{session.hop_count+1}-{len(session.actions)+1:02d}",
                    gap_id=cand.gap_id,
                    action_type=ActionType.SEARCH,
                    query=cand_q,
                    reason=f"Targeted query proposed for gap '{cand.gap_id}'",
                    status=ActionStatus.PROPOSED,
                    created_at_hop=session.hop_count + 1,
                )
                is_valid, reject_reason = self.validate_action(action, session)
                if not is_valid:
                    rejection_details.append(f"Rejected '{cand_q}': {reject_reason}")
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ACTION_REJECTED",
                            description=f"Controller rejected proposed action for gap '{cand.gap_id}': {reject_reason}",
                            details={"query": cand_q, "gap_id": cand.gap_id, "reason": reject_reason},
                        )
                    )
                    continue

                active_gap = session.gaps.get(cand.gap_id, cand)
                self.transition_gap(active_gap, GapStatus.SEARCHING, reason=f"Executing action {action.action_id}", session=session)
                gaps_to_execute.append((action, active_gap))
                seen_cand_ids.add(cand.gap_id)
                if len(gaps_to_execute) >= self.max_batch_gaps:
                    break

            if not gaps_to_execute:
                open_gaps = self.get_prioritized_open_gaps(session)
                for target_gap in open_gaps:
                    if target_gap.gap_id in seen_cand_ids:
                        continue
                    fallback_q = target_gap.targeted_query or f"{target_gap.target_entity} {target_gap.required_information}".strip()
                    fb_action = InvestigationAction(
                        action_id=f"ACT-HOP{session.hop_count+1}-{len(session.actions)+1:02d}",
                        gap_id=target_gap.gap_id,
                        action_type=ActionType.SEARCH,
                        query=fallback_q,
                        reason=f"Controller fallback query for open gap '{target_gap.gap_id}'",
                        status=ActionStatus.PROPOSED,
                        created_at_hop=session.hop_count + 1,
                    )
                    is_valid_fb, fb_rej = self.validate_action(fb_action, session)
                    if is_valid_fb:
                        self.transition_gap(target_gap, GapStatus.SEARCHING, reason=f"Executing fallback action {fb_action.action_id}", session=session)
                        gaps_to_execute.append((fb_action, target_gap))
                        if len(gaps_to_execute) >= self.max_batch_gaps:
                            break
                    else:
                        target_gap.status = GapStatus.BLOCKED
                        session.investigation_trace.append(
                            InvestigationEvent(
                                hop=session.hop_count + 1,
                                event_type="GAP_BLOCKED",
                                description=f"Gap '{target_gap.gap_id}' marked BLOCKED: all query angles exhausted",
                                details={"gap_id": target_gap.gap_id, "reason": fb_rej},
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
                            GapStatus.PLANNED,
                            GapStatus.SEARCHING,
                            GapStatus.INVESTIGATING,
                            GapStatus.UNDER_REVIEW,
                            GapStatus.UNRESOLVED,
                            GapStatus.BLOCKED,
                            GapStatus.REOPENED,
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
            for active_action, active_gap in gaps_to_execute:
                norm_q = self._normalize_query(active_action.query)
                session.query_history.add(norm_q)
                active_action.status = ActionStatus.EXECUTED
                active_action.executed_at_hop = session.hop_count + 1
                session.actions.append(active_action)
                if active_gap:
                    active_gap.attempted_actions.append(active_action)
                    active_gap.attempted_queries.append(active_action.query)
                    active_gap.attempt_count += 1

                search_results, _ = self.retriever.search(active_action.query, k=4)
                active_action.yield_chunk_count = len(search_results)
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
                        if active_gap.attempt_count >= active_gap.max_attempts:
                            active_gap.status = GapStatus.BLOCKED
                        else:
                            active_gap.status = GapStatus.UNRESOLVED
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ACTIONABLE_GAP_EXECUTED",
                            description=f"Actionable gap query '{active_action.query}' executed (zero yield)",
                            details={"query": active_action.query, "gap_id": active_gap.gap_id if active_gap else "none", "is_zero_yield": True},
                        )
                    )
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ZERO_YIELD_SEARCH",
                            description=f"Query '{active_action.query}' yielded 0 results",
                            details={"query": active_action.query, "gap_id": active_gap.gap_id if active_gap else "none"},
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

                    retrieved_evidence_ids = [ev.evidence_id for ev, _ in search_results]

                    # First evaluate the active_gap specifically against the chunks returned by its search
                    if active_gap:
                        self._evaluate_gap_resolution(active_gap, session, retrieved_evidence_ids)

                    # Evaluate all gaps against newly admitted evidence (and include active_gap results)
                    eval_ids = list(set(new_evidence_ids + (retrieved_evidence_ids if not new_evidence_ids else [])))
                    self._evaluate_all_gaps(session, eval_ids)

                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="ACTIONABLE_GAP_EXECUTED",
                            description=f"Actionable gap query '{active_action.query}' executed with {len(new_evidence_ids)} new chunk(s)",
                            details={"query": active_action.query, "gap_id": active_gap.gap_id if active_gap else "none", "is_zero_yield": False},
                        )
                    )
                    session.investigation_trace.append(
                        InvestigationEvent(
                            hop=session.hop_count + 1,
                            event_type="RETRIEVAL_ADMITTED",
                            description=f"Query '{active_action.query}' admitted {len(new_evidence_ids)} new chunk(s)",
                            details={
                                "query": active_action.query,
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
            hypotheses=session.hypotheses,
            actions=session.actions,
            evidence_items=list(session.discovered_evidence.values()),
            graph_edges=edges,
            gap_history=[
                {
                    "gap_id": g.gap_id,
                    "description": g.description,
                    "why_needed": g.why_needed,
                    "evidence_requirement": g.evidence_requirement,
                    "status": g.status.value if hasattr(g.status, "value") else str(g.status),
                    "query": g.targeted_query or (g.attempted_queries[-1] if g.attempted_queries else ""),
                    "resolved": g.resolved,
                    "resolution_evidence_ids": g.resolution_evidence_ids,
                    "conflicting_evidence_ids": g.conflicting_evidence_ids,
                    "resolution": g.resolution,
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
        """
        Hard-tiered priority computation.
        Guarantees that blocking gaps (Tier 1) can NEVER be starved by non-blocking gaps (Tier 2),
        regardless of attempt counts.
        """
        # Tier 1: Blocking Gaps (Base: 1000.0, Range: 950.0 - 1300.0)
        # Tier 2: Non-blocking Gaps (Base: 100.0, Range: 50.0 - 150.0)
        is_blocking = gap.is_blocking
        base = 1000.0 if is_blocking else 100.0

        # Contradiction / Reopened boost
        contra_boost = 200.0 if (
            gap.gap_type == GapType.CONTRADICTION_RECONCILIATION
            or bool(gap.conflicting_evidence_ids)
            or gap.status == GapStatus.REOPENED
        ) else 0.0

        # Leaf prerequisite boost (foundational gaps that unblock downstream dependents)
        leaf_boost = 50.0 if (
            gap.dependent_gap_ids
            or gap.gap_type in [GapType.PREREQUISITE, GapType.AUTHORITY_RESOLUTION]
        ) else 0.0

        # Attempt penalty within tier (capped at -50.0 so tier boundaries are strictly preserved)
        capped_attempts = min(gap.attempt_count, 5)
        attempt_penalty = 10.0 * float(capped_attempts)

        return base + contra_boost + leaf_boost - attempt_penalty

    def get_prioritized_open_gaps(self, session: InvestigationSession) -> List[InformationGap]:
        active = [
            g for g in session.gaps.values()
            if g.gap_id != "GAP-ROOT-1" and g.gap_type != GapType.OBJECTIVE_ROOT
            and g.status in [GapStatus.OPEN, GapStatus.PLANNED, GapStatus.UNRESOLVED, GapStatus.REOPENED]
        ]
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

        # TERM-INV-10: Evidence that was necessary for a resolved gap must exist in discovered_evidence
        for g in blocking:
            if g.gap_id != "GAP-ROOT-1" and g.status == GapStatus.RESOLVED:
                if g.resolution_evidence_ids and not any(eid in session.discovered_evidence for eid in g.resolution_evidence_ids):
                    return False

        if len(session.discovered_evidence) < 2:
            return False

        return True

    def verify_sufficiency(self, state: InvestigationState, llm_rationale: str) -> Tuple[bool, Optional[str]]:
        if state.unresolved_references:
            return False, f"Unresolved explicit reference(s) still pending: {list(state.unresolved_references)}"

        has_inferences = any(edge.derived_by == EdgeDerivationType.LLM_INFERENCE for edge in state.evidence_graph)
        has_factual = any(edge.is_factual_proof for edge in state.evidence_graph)
        if has_inferences and not has_factual:
            return False, "Sufficiency rejected: Evidence graph relies solely on LLM_INFERENCE edges."

        # Domain-agnostic check: Ensure no blocking gaps are unresolved in pending_gaps
        blocking_pending = [g for g in state.pending_gaps if g.is_blocking and g.gap_id != "GAP-ROOT-1" and not g.resolved]
        if blocking_pending:
            return False, f"Sufficiency rejected: Blocking gap(s) still open: {[g.gap_id for g in blocking_pending]}"

        # Domain-agnostic check: Ensure resolved blocking gaps have their satisfying evidence present in accumulated_evidence
        for g in state.resolved_gaps:
            if g.is_blocking and g.gap_id != "GAP-ROOT-1":
                if g.resolution_evidence_ids and not any(eid in state.accumulated_evidence for eid in g.resolution_evidence_ids):
                    return False, f"Sufficiency rejected: Resolved gap {g.gap_id} lacks supporting evidence in accumulated evidence."

        # Domain-agnostic check: If the evidence graph contains an unresolved contradiction without superseding/reconciling resolution
        contra_edges = [e for e in state.evidence_graph if e.relationship_type == RelationshipType.CONTRADICTS]
        supersede_edges = [e for e in state.evidence_graph if e.relationship_type == RelationshipType.SUPERSEDES]
        if contra_edges and not supersede_edges:
            for c_edge in contra_edges:
                has_reconciliation = any(
                    ev.evidence_id not in (c_edge.source_evidence_id, c_edge.target_evidence_id)
                    and (
                        any(self.scanner.is_authoritative_resolution(token, ev)
                            for token in self.scanner.extract_references(ev.content).get("INCIDENT", set())
                            | self.scanner.extract_references(ev.content).get("CHANGE_REQUEST", set()))
                        or bool(INCIDENT_RESOLUTION_PATTERN.search(ev.content))
                        or bool(CR_DECISION_PATTERN.search(ev.content))
                    )
                    for ev in state.accumulated_evidence.values()
                )
                if not has_reconciliation:
                    return False, "Sufficiency rejected: Unreconciled contradiction detected in evidence graph without superseding or authoritative resolution."

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
                ref_category = self.scanner.classify_token(ref)
                if ref_category == "INCIDENT":
                    targeted_q = f"{ref} current production state"
                elif ref_category == "CHANGE_REQUEST":
                    targeted_q = f"{ref} decision disposition"
                elif ref_category == "REGULATION":
                    targeted_q = f"{ref} compliance requirements"
                elif ref_category == "DOC_ID":
                    targeted_q = f"{ref} operational specification"
                else:
                    targeted_q = ref

                originating_chunks = [
                    e.evidence_id for e in session.discovered_evidence.values()
                    if ref in e.content or ref in e.source_id
                ]

                session.gaps[gid] = InformationGap(
                    gap_id=gid,
                    gap_type=GapType.AUTHORITY_RESOLUTION,
                    is_blocking=True,
                    description=f"Authoritative decision or resolution record for reference '{ref}'",
                    target_entity=ref,
                    required_information=f"Status, disposition, or resolution of {ref}",
                    targeted_query=targeted_q,
                    candidate_queries=[targeted_q],
                    originating_evidence_ids=originating_chunks,
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

            # Integration target specifications (e.g., Target: Production Deployment)
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
                            is_blocking=False,
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

    def _check_gap_reopening(
        self,
        gap: InformationGap,
        session: InvestigationSession,
        new_evidence_ids: List[str],
    ) -> bool:
        """
        Evaluate whether newly admitted evidence contradicts or invalidates
        a previously RESOLVED gap using the semantic OppositionEngine and EntityScopedEvaluator.
        If invalidated, controller reopens the gap and propagates invalidation down the DAG.
        """
        if gap.status != GapStatus.RESOLVED:
            return False

        # Reconciliation gaps resolved by authoritative records cannot be recursively reopened by earlier opposing evidence
        if gap.gap_type == GapType.CONTRADICTION_RECONCILIATION:
            return False

        reopened = False

        for eid in new_evidence_ids:
            if eid in gap.resolution_evidence_ids or eid in gap.originating_evidence_ids:
                continue
            ev = session.discovered_evidence.get(eid)
            if not ev:
                continue

            # Check if any resolution evidence supersedes this new evidence
            is_superseded_by_resolution = False
            has_contra_edge = False
            for res_id in gap.resolution_evidence_ids:
                if res_id == eid:
                    continue
                res_ev = session.discovered_evidence.get(res_id)
                if res_ev:
                    edges = self.scanner.detect_deterministic_edges([res_ev, ev])
                    if any(edge.relationship_type == RelationshipType.SUPERSEDES and edge.source_evidence_id == res_ev.evidence_id for edge in edges):
                        is_superseded_by_resolution = True
                        break
                    if any(edge.relationship_type == RelationshipType.CONTRADICTS for edge in edges):
                        has_contra_edge = True

            if is_superseded_by_resolution:
                continue

            eval_res = self.evaluator.evaluate_chunk(gap, ev)

            if eval_res.opposition_found or has_contra_edge:
                if eid not in gap.conflicting_evidence_ids:
                    gap.conflicting_evidence_ids.append(eid)
                reopened = True

                # Record contradiction in session
                contra_id = f"CONTRA-{gap.gap_id}-{eid}"
                session.detected_contradictions.append(
                    ContradictionRecord(
                        contradiction_id=contra_id,
                        claim_a_evidence_id=gap.resolution_evidence_ids[0] if gap.resolution_evidence_ids else "unknown",
                        claim_b_evidence_id=eid,
                        conflicting_subject=gap.target_entity or gap.description,
                        basis=f"Evidence {eid} invalidates earlier resolution: {ev.content[:80]}",
                        reconciled=False,
                    )
                )

                # Formulate blocking reconciliation gap if not already a contradiction gap
                contra_gap_id = f"GAP-CONTRA-{gap.gap_id}"
                if contra_gap_id not in session.gaps and "CONTRA" not in gap.gap_id:
                    session.gaps[contra_gap_id] = InformationGap(
                        gap_id=contra_gap_id,
                        gap_type=GapType.CONTRADICTION_RECONCILIATION,
                        is_blocking=True,
                        description=f"Reconcile invalidation of {gap.target_entity} by {eid}",
                        why_needed=f"New evidence {eid} contradicts resolved state of {gap.gap_id}",
                        evidence_requirement=f"Authoritative decision reconciling opposing claims for {gap.target_entity}",
                        target_entity=gap.target_entity,
                        required_information=f"Determine authoritative state of {gap.target_entity}",
                        targeted_query=f"{gap.target_entity} authoritative resolution disposition",
                        originating_evidence_ids=list(set(gap.resolution_evidence_ids + [eid])),
                        status=GapStatus.OPEN,
                    )
                break

        if reopened:
            self.transition_gap(
                gap,
                GapStatus.REOPENED,
                reason=f"Invalidated by contradictory evidence {gap.conflicting_evidence_ids}",
                session=session,
            )
            self.propagate_dependency_invalidation(session, gap.gap_id, reason="Reopened due to contradictory evidence")
            session.investigation_trace.append(
                InvestigationEvent(
                    hop=session.hop_count,
                    event_type="GAP_REOPENED",
                    description=f"Gap '{gap.gap_id}' REOPENED due to contradictory evidence",
                    details={
                        "gap_id": gap.gap_id,
                        "conflicting_evidence_ids": gap.conflicting_evidence_ids,
                    },
                )
            )

        return reopened

    def _evaluate_all_gaps(self, session: InvestigationSession, new_evidence_ids: List[str]) -> None:
        if not new_evidence_ids:
            return
        for g in list(session.gaps.values()):
            if g.status in [
                GapStatus.OPEN,
                GapStatus.PLANNED,
                GapStatus.SEARCHING,
                GapStatus.INVESTIGATING,
                GapStatus.UNDER_REVIEW,
                GapStatus.UNRESOLVED,
                GapStatus.REOPENED,
            ]:
                self._evaluate_gap_resolution(g, session, new_evidence_ids)
            elif g.status == GapStatus.RESOLVED:
                self._check_gap_reopening(g, session, new_evidence_ids)

    def _evaluate_gap_resolution(
        self,
        gap: InformationGap,
        session: InvestigationSession,
        new_evidence_ids: List[str],
    ) -> None:
        if not new_evidence_ids:
            return

        valid_types = {
            GapType.OBJECTIVE_ROOT,
            GapType.AUTHORITY_RESOLUTION,
            GapType.PREREQUISITE,
            GapType.STATE_VERIFICATION,
            GapType.CONTRADICTION_RECONCILIATION,
        }
        if gap.gap_type not in valid_types:
            return

        # TERM-INV-01 / TERM-INV-02: Root objective gap cannot be satisfied directly by an individual chunk
        if gap.gap_id == "GAP-ROOT-1" or gap.gap_type == GapType.OBJECTIVE_ROOT:
            return

        satisfying_ids: List[str] = []
        conflicting_ids: List[str] = []

        for eid in new_evidence_ids:
            ev = session.discovered_evidence.get(eid)
            if not ev:
                continue

            eval_res = self.evaluator.evaluate_chunk(gap, ev)
            if eval_res.satisfies:
                satisfying_ids.append(eid)
            if eval_res.opposition_found:
                conflicting_ids.append(eid)

        if satisfying_ids:
            # Temporal provenance conflict resolution for state verification:
            # If multiple chunks satisfy state verification (e.g. Obsolete spec vs current production record),
            # resolve using the latest timestamp chunk.
            if gap.gap_type == GapType.STATE_VERIFICATION and len(satisfying_ids) > 1:
                chunk_objects = [session.discovered_evidence[sid] for sid in satisfying_ids if sid in session.discovered_evidence]
                timestamps = [getattr(c, "created_at", None) for c in chunk_objects if getattr(c, "created_at", None)]
                if len(timestamps) > 1 and len(set(timestamps)) > 1:
                    chunk_objects.sort(key=lambda c: getattr(c, "created_at", "") or "", reverse=True)
                    satisfying_ids = [chunk_objects[0].evidence_id]

            for sid in satisfying_ids:
                if sid not in gap.resolution_evidence_ids:
                    gap.resolution_evidence_ids.append(sid)
            gap.resolution_status = True
            gap.resolution = f"Satisfied by evidence chunk(s): {', '.join(satisfying_ids)}"
            if conflicting_ids:
                for cid in conflicting_ids:
                    if cid not in gap.conflicting_evidence_ids:
                        gap.conflicting_evidence_ids.append(cid)
                gap.status = GapStatus.RECONCILIATION_REQUIRED
                self.propagate_dependency_invalidation(session, gap.gap_id, reason="Gap requires reconciliation due to contradictory evidence")
            else:
                gap.status = GapStatus.RESOLVED
                self.propagate_dependency_restoration(session, gap.gap_id)
        else:
            if gap.status in [GapStatus.SEARCHING, GapStatus.INVESTIGATING, GapStatus.UNDER_REVIEW]:
                if conflicting_ids:
                    for cid in conflicting_ids:
                        if cid not in gap.conflicting_evidence_ids:
                            gap.conflicting_evidence_ids.append(cid)
                    gap.status = GapStatus.RECONCILIATION_REQUIRED
                    self.propagate_dependency_invalidation(session, gap.gap_id, reason="Contradictory evidence detected during investigation")
                elif gap.attempt_count >= gap.max_attempts:
                    gap.status = GapStatus.BLOCKED
                    self.propagate_dependency_invalidation(session, gap.gap_id, reason="Max attempts reached without resolution")
                else:
                    gap.status = GapStatus.UNRESOLVED

    # -------------------------------------------------------------------------
    # UTILITY HELPERS
    # -------------------------------------------------------------------------
    def _build_state_view(self, session: InvestigationSession) -> InvestigationState:
        edges = self.scanner.detect_deterministic_edges(list(session.discovered_evidence.values()))
        open_g = [g for g in session.gaps.values() if not g.resolved]
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
