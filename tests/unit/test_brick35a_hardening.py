"""
Unit and Integration Tests for Brick 3.5A — Architectural Hardening.

Covers:
1. Cross-entity evidence leakage elimination.
2. Incidental token overlap rejection.
3. Semantic opposition detection without keywords.
4. LLM root-gap authority bypass prevention.
5. Controller action validation on dependency-unsatisfied gaps.
6. Investigation budget fast-path hop counting & max_hops enforcement.
7. Blocking-gap starvation immunity.
8. Single prerequisite dependency invalidation.
9. Chained prerequisite dependency invalidation cascade.
10. Prerequisite dependency restoration cascade.
11. Comprehensive Vertical Integration Test:
    QUESTION -> PLAN -> MULTIPLE GAPS -> DEPENDENCIES -> EVIDENCE ->
    CONTRADICTION -> GAP REOPENING / BLOCKING -> TARGETED REINVESTIGATION ->
    SUFFICIENCY -> VERIFIED TERMINATION.
"""

import pytest
from typing import List, Tuple, Dict, Any, Optional, Set

from backend.evidence.models import Evidence
from backend.investigation.models import (
    GapType,
    GapStatus,
    ActionType,
    ActionStatus,
    InvestigationAction,
    InformationGap,
    EvidenceEdge,
    EvidencePackage,
    InvestigationBudget,
    InvestigationSession,
    InvestigationState,
    RelationshipType,
    EdgeDerivationType,
)
from backend.investigation.polarity import (
    OppositionEngine,
    OppositionDomain,
    Polarity,
)
from backend.investigation.evaluator import EntityScopedEvaluator
from backend.investigation.planner import InvestigationPlanner
from backend.investigation.controller import InvestigationController
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult


class MockMemoryRetriever(EvidenceProvider):
    """Configurable in-memory retriever for targeted adversarial testing."""

    def __init__(self, evidence_items: Optional[List[Evidence]] = None):
        self.evidence_pool: Dict[str, Evidence] = {e.evidence_id: e for e in (evidence_items or [])}
        self.query_log: List[str] = []
        self.canned_responses: Dict[str, List[Evidence]] = {}

    @property
    def provider_id(self) -> str:
        return "mock_memory_retriever"

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.LEXICAL_SEARCH}

    def add_document(self, doc_id: str, content: str):
        ev = make_test_evidence(doc_id, content, source_id=doc_id)
        self.evidence_pool[doc_id] = ev

    def add_canned_response(self, query_substr: str, items: List[Evidence]):
        self.canned_responses[query_substr.lower()] = items
        for item in items:
            self.evidence_pool[item.evidence_id] = item

    def search(self, query: str, k: int = 5, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Tuple[Evidence, float]], float]:
        self.query_log.append(query)
        q_low = query.lower()

        # Check canned responses first
        for key, items in self.canned_responses.items():
            if key in q_low:
                return [(item, 10.0 - (0.5 * idx)) for idx, item in enumerate(items[:k])], 1.0

        # Substring / keyword match over evidence pool
        matched = []
        import re
        tokens = [t for t in re.findall(r"\b[A-Za-z0-9\-_]+\b", q_low) if len(t) > 2]
        for item in self.evidence_pool.values():
            content_low = f"{item.source_id} {item.content}".lower()
            score = sum(1.0 for t in tokens if t in content_low)
            if score > 0:
                matched.append((item, score))

        matched.sort(key=lambda x: x[1], reverse=True)
        return matched[:k], 1.0

    def search_provider(self, query: str, k: int = 4, filters: Optional[Dict[str, Any]] = None) -> List[ProviderSearchResult]:
        return []

    def health_check(self) -> bool:
        return True


def make_test_evidence(
    evidence_id: str,
    content: str,
    source_id: str = "DOC-TEST",
    created_at: str = "2026-10-24T09:00:00Z",
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source_id=source_id,
        source_type="markdown",
        uri=f"file:///{source_id}",
        content=content,
        content_hash=f"hash_{evidence_id}",
        source_path=f"path/{source_id}",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content.encode("utf-8")),
        created_at=created_at,
    )


# =============================================================================
# 1. CROSS-ENTITY EVIDENCE LEAKAGE ISOLATION
# =============================================================================

def test_cross_entity_evidence_leakage_isolation():
    """
    PRIORITY 0.1: A chunk containing facts for multiple entities must not allow
    facts of Entity A to resolve a gap targeting Entity B.
    """
    evaluator = EntityScopedEvaluator()
    shared_chunk = make_test_evidence(
        evidence_id="EV-MULTI-01",
        content=(
            "Cluster Operation Log:\n"
            "Component Redis: emergency rollback completed and verified.\n"
            "Component Kafka: version upgrade completed successfully."
        ),
    )

    # Gap targeting Kafka rollback (which did NOT happen - Kafka was upgraded, Redis rolled back)
    gap_kafka_rollback = InformationGap(
        gap_id="GAP-KAFKA-RB",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Kafka rollback completion",
        target_entity="Kafka",
        required_information="Kafka rollback completed and verified",
        status=GapStatus.OPEN,
    )

    res_kafka = evaluator.evaluate_chunk(gap_kafka_rollback, shared_chunk)
    assert not res_kafka.chunk_satisfies, "Kafka gap must NOT be satisfied by Redis rollback fact in the same chunk!"

    # Gap targeting Redis rollback (which DID happen)
    gap_redis_rollback = InformationGap(
        gap_id="GAP-REDIS-RB",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Redis rollback completion",
        target_entity="Redis",
        required_information="Redis rollback completed and verified",
        status=GapStatus.OPEN,
    )

    res_redis = evaluator.evaluate_chunk(gap_redis_rollback, shared_chunk)
    assert res_redis.chunk_satisfies, "Redis gap must be satisfied by Redis rollback clause."
    assert "EV-MULTI-01" in [shared_chunk.evidence_id]


# =============================================================================
# 2. INCIDENTAL TOKEN OVERLAP REJECTION
# =============================================================================

def test_incidental_token_overlap_rejection():
    """
    PRIORITY 0.2: Generic token overlap ('system', 'service', 'status', 'architecture')
    must NEVER resolve a substantive information gap.
    """
    evaluator = EntityScopedEvaluator()
    generic_chunk = make_test_evidence(
        evidence_id="EV-GEN-01",
        content=(
            "The corporate IT architecture incorporates modern service deployment pipelines "
            "and standard status monitoring for all enterprise systems."
        ),
    )

    gap_payment = InformationGap(
        gap_id="GAP-PAYMENT-MTLS",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway mutual TLS configuration",
        target_entity="Payment Gateway",
        required_information="Payment Gateway mutual TLS 1.3 encryption status",
        status=GapStatus.OPEN,
    )

    result = evaluator.evaluate_chunk(gap_payment, generic_chunk)
    assert not result.chunk_satisfies, "Generic token overlap must not resolve a substantive gap."


# =============================================================================
# 3. NON-STANDARD SEMANTIC OPPOSITION DETECTION
# =============================================================================

def test_semantic_opposition_non_standard_vocabulary():
    """
    PRIORITY 0.3: Strengthen contradiction detection with domain-aware polarity opposition
    (e.g., ACTIVE ↔ CANCELLED, ENABLED ↔ DISABLED, PASSED ↔ FAILED, APPROVED ↔ DENIED).
    """
    engine = OppositionEngine()

    pairs = [
        ("Deployment status is ACTIVE on main.", "Deployment status is CANCELLED on main."),
        ("Mutual TLS 1.3 is ENABLED in config.", "Mutual TLS 1.3 is DISABLED in config."),
        ("Verification suite PASSED with zero defects.", "Verification suite FAILED with critical errors."),
        ("Production change request is APPROVED.", "Production change request is DENIED by infosec."),
        ("Feature branch is DEPLOYED to production.", "Feature branch is ROLLED BACK immediately."),
        ("Signature certificate is VALID.", "Signature certificate is INVALID."),
    ]

    for text_a, text_b in pairs:
        opp = engine.detect_opposition(text_a, text_b)
        assert opp is not None, f"Failed to detect opposition between:\n'{text_a}' and\n'{text_b}'"
        assert opp.confidence >= 0.85

    # Non-opposing statements should return None
    neutral = engine.detect_opposition(
        "Redis database is active on port 6379.",
        "Kafka cluster is active on port 9092."
    )
    assert neutral is None, "Distinct entities with neutral assertions must not trigger opposition."


# =============================================================================
# 4. CONTROLLER AUTHORITY: ROOT-GAP BYPASS REJECTION
# =============================================================================

def test_controller_authority_rejects_direct_root_gap_actions():
    """
    PRIORITY 0.4: Controller deterministically rejects any LLM action directly
    targeting GAP-ROOT-1, OBJECTIVE_ROOT, or attempting to resolve root objective directly.
    """
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(
        session_id="s_auth_root",
        objective="Determine whether Phoenix is safe to launch",
        hop_count=1,
    )
    root_gap = InformationGap(
        gap_id="GAP-ROOT-1",
        gap_type=GapType.OBJECTIVE_ROOT,
        is_blocking=True,
        description="Root objective",
        status=GapStatus.OPEN,
    )
    session.gaps[root_gap.gap_id] = root_gap

    # Direct action targeting GAP-ROOT-1
    act_direct_root = InvestigationAction(
        action_id="ACT-BYPASS-01",
        gap_id="GAP-ROOT-1",
        action_type=ActionType.SEARCH,
        query="Phoenix safe to launch",
        reason="Direct root objective search",
        status=ActionStatus.PROPOSED,
    )
    is_valid, reject_reason = controller.validate_action(act_direct_root, session)
    assert not is_valid, "Controller must reject direct action targeting GAP-ROOT-1"
    assert "GAP-ROOT-1" in reject_reason or "OBJECTIVE_ROOT" in reject_reason

    # Direct action targeting OBJECTIVE_ROOT type
    act_root_type = InvestigationAction(
        action_id="ACT-BYPASS-02",
        gap_id="GAP-CUSTOM-ROOT",
        action_type=ActionType.SEARCH,
        query="Determine whether Phoenix is safe to launch",
        reason="Echo root objective",
        status=ActionStatus.PROPOSED,
    )
    session.gaps["GAP-CUSTOM-ROOT"] = InformationGap(
        gap_id="GAP-CUSTOM-ROOT",
        gap_type=GapType.OBJECTIVE_ROOT,
        is_blocking=True,
        description="Custom root",
        status=GapStatus.OPEN,
    )
    is_valid_type, reject_type = controller.validate_action(act_root_type, session)
    assert not is_valid_type, "Controller must reject actions targeting OBJECTIVE_ROOT gap type"


# =============================================================================
# 5. CONTROLLER AUTHORITY: REJECTION OF DEPENDENCY-UNSATISFIED ACTIONS
# =============================================================================

def test_controller_authority_rejects_unsatisfied_dependency_actions():
    """
    PRIORITY 0.4 & 1.7: Controller rejects actions targeting gaps whose prerequisites
    are not yet satisfied (DEPENDENCY_UNSATISFIED).
    """
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(
        session_id="s_dep_act",
        objective="Verify cluster readiness",
        hop_count=1,
    )

    gap_blocked = InformationGap(
        gap_id="GAP-DOWNSTREAM-EXEC",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Execute migration",
        status=GapStatus.DEPENDENCY_UNSATISFIED,
        unsatisfied_prerequisites=["GAP-UPSTREAM-AUTH"],
    )
    session.gaps[gap_blocked.gap_id] = gap_blocked

    action = InvestigationAction(
        action_id="ACT-PREMATURE",
        gap_id="GAP-DOWNSTREAM-EXEC",
        action_type=ActionType.SEARCH,
        query="Database migration execution output",
        reason="Premature investigation before prerequisite approval",
        status=ActionStatus.PROPOSED,
    )

    is_valid, reject_reason = controller.validate_action(action, session)
    assert not is_valid, "Controller must reject actions on DEPENDENCY_UNSATISFIED gaps."
    assert "DEPENDENCY_UNSATISFIED" in reject_reason or "unsatisfied" in reject_reason.lower()


# =============================================================================
# 6. INVESTIGATION BUDGET: FAST-PATH HOP COUNTING & MAX HOPS CEILING
# =============================================================================

def test_fast_path_budget_enforcement_max_hops():
    """
    PRIORITY 1.5: Fast-path reference hops must increment hop count and strictly
    enforce the max_hops ceiling, preventing budget bypass.
    """
    retriever = MockMemoryRetriever()
    # Setup chain of 6 change requests
    for i in range(1, 6):
        retriever.add_document(
            f"DOC-CR-{i}",
            f"Change request CR-{i} requires evaluation of CR-{i+1}."
        )
    retriever.add_document("DOC-CR-6", "Terminal change request CR-6.")
    retriever.add_document("DOC-START", "System deployment depends on CR-1.")

    budget = InvestigationBudget(max_hops=3, max_llm_calls=5, max_queries=20)
    controller = InvestigationController(retriever=retriever, budget=budget)

    package = controller.run_investigation(
        objective="System deployment",
        reasoning_agent_fn=lambda s: (False, "Continuing search", [], []),
    )

    assert package.budget_summary["hops_used"] <= 3, "Fast-path must strictly respect max_hops budget!"
    assert "MAX_HOPS" in package.termination_reason, f"Expected MAX_HOPS termination, got {package.termination_reason}"


# =============================================================================
# 7. GAP PRIORITIZATION: BLOCKING-GAP STARVATION IMMUNITY
# =============================================================================

def test_blocking_gap_starvation_immunity():
    """
    PRIORITY 1.6: An unresolved critical blocking gap must NEVER be starved by
    a flood of non-blocking exploratory gaps, even after accumulating multiple failed attempts.
    """
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s_starve", objective="Critical launch check")

    # Critical blocking gap with 4 failed attempts (under max_attempts=5)
    critical_gap = InformationGap(
        gap_id="GAP-CRITICAL-AUTH",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Critical security signoff",
        attempt_count=4,
        max_attempts=5,
        status=GapStatus.OPEN,
    )
    session.gaps[critical_gap.gap_id] = critical_gap

    # 100 non-blocking exploratory gaps with 0 attempts
    for i in range(100):
        gid = f"GAP-NONBLOCK-{i:03d}"
        session.gaps[gid] = InformationGap(
            gap_id=gid,
            gap_type=GapType.PREREQUISITE,
            is_blocking=False,
            description=f"Optional background info #{i}",
            attempt_count=0,
            status=GapStatus.OPEN,
        )

    prioritized = controller.get_prioritized_open_gaps(session)
    assert len(prioritized) == 101
    top_gap = prioritized[0]
    assert top_gap.gap_id == "GAP-CRITICAL-AUTH", (
        f"Critical blocker starved! Top gap was {top_gap.gap_id} with score {top_gap.priority_score}, "
        f"while critical gap scored {critical_gap.priority_score}."
    )
    assert critical_gap.priority_score >= 950.0, "Blocking gaps must remain in Tier 1 (>950.0)."


# =============================================================================
# 8. DAG PREREQUISITE DEPENDENCY INVALIDATION (SINGLE HOP)
# =============================================================================

def test_dag_dependency_invalidation_single_hop():
    """
    PRIORITY 1.7: When Gap A is invalidated, Gap B (which depends on A) must
    be transitioned to DEPENDENCY_UNSATISFIED.
    """
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s_dag_1", objective="Database deployment")

    gap_a = InformationGap(
        gap_id="GAP-A-APPROVAL",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Migration approval",
        status=GapStatus.RESOLVED,
    )
    gap_b = InformationGap(
        gap_id="GAP-B-EXECUTION",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Migration execution",
        status=GapStatus.OPEN,
    )
    session.gaps[gap_a.gap_id] = gap_a
    session.gaps[gap_b.gap_id] = gap_b

    # Register B depends on A
    controller.register_gap_dependency(session, "GAP-B-EXECUTION", ["GAP-A-APPROVAL"])
    assert "GAP-B-EXECUTION" in gap_a.dependent_gap_ids
    assert "GAP-A-APPROVAL" in gap_b.depends_on_gap_ids

    # Invalidate A (e.g. late contradiction)
    gap_a.status = GapStatus.REOPENED
    controller.propagate_dependency_invalidation(
        session=session,
        invalidated_gap_id="GAP-A-APPROVAL",
        reason="Late contradiction revoked approval",
    )

    assert gap_b.status == GapStatus.DEPENDENCY_UNSATISFIED, "Gap B must become DEPENDENCY_UNSATISFIED"
    assert "GAP-A-APPROVAL" in gap_b.unsatisfied_prerequisites


# =============================================================================
# 9. DAG PREREQUISITE DEPENDENCY INVALIDATION (CHAINED MULTI-HOP)
# =============================================================================

def test_dag_dependency_invalidation_chained_multi_hop():
    """
    PRIORITY 1.7: Deep topological cascade: A -> B -> C -> D.
    Invalidating A must cascade down to B, C, and D, while independent E is untouched.
    """
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s_dag_chain", objective="Pipeline readiness")

    chain_ids = ["GAP-A", "GAP-B", "GAP-C", "GAP-D"]
    for gid in chain_ids:
        session.gaps[gid] = InformationGap(
            gap_id=gid,
            gap_type=GapType.PREREQUISITE,
            is_blocking=True,
            description=f"Stage {gid}",
            status=GapStatus.RESOLVED,
        )

    # Independent gap
    session.gaps["GAP-E-INDEPENDENT"] = InformationGap(
        gap_id="GAP-E-INDEPENDENT",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Independent stage E",
        status=GapStatus.RESOLVED,
    )

    # Register chain: B depends on A; C depends on B; D depends on C
    controller.register_gap_dependency(session, "GAP-B", ["GAP-A"])
    controller.register_gap_dependency(session, "GAP-C", ["GAP-B"])
    controller.register_gap_dependency(session, "GAP-D", ["GAP-C"])

    # Invalidate GAP-A
    session.gaps["GAP-A"].status = GapStatus.BLOCKED
    controller.propagate_dependency_invalidation(
        session=session,
        invalidated_gap_id="GAP-A",
        reason="Upstream prerequisite blocked",
    )

    # B, C, D must all be DEPENDENCY_UNSATISFIED
    assert session.gaps["GAP-B"].status == GapStatus.DEPENDENCY_UNSATISFIED
    assert session.gaps["GAP-C"].status == GapStatus.DEPENDENCY_UNSATISFIED
    assert session.gaps["GAP-D"].status == GapStatus.DEPENDENCY_UNSATISFIED

    # Independent GAP-E must remain RESOLVED
    assert session.gaps["GAP-E-INDEPENDENT"].status == GapStatus.RESOLVED


# =============================================================================
# 10. DAG DEPENDENCY RESTORATION CASCADE
# =============================================================================

def test_dag_dependency_restoration_cascade():
    """
    PRIORITY 1.7: When an upstream prerequisite is reconciled and re-resolved,
    immediate downstream dependents whose prerequisites are now satisfied
    must be restored to OPEN/PLANNED, while further downstream gaps wait for their
    direct parent to be resolved.
    """
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s_dag_restore", objective="Cluster restoration")

    gap_a = InformationGap(
        gap_id="GAP-A",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Prerequisite A",
        status=GapStatus.DEPENDENCY_UNSATISFIED,
        unsatisfied_prerequisites=["GAP-A"],
    )
    gap_b = InformationGap(
        gap_id="GAP-B",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Prerequisite B",
        status=GapStatus.DEPENDENCY_UNSATISFIED,
        unsatisfied_prerequisites=["GAP-A"],
    )
    gap_c = InformationGap(
        gap_id="GAP-C",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Prerequisite C",
        status=GapStatus.DEPENDENCY_UNSATISFIED,
        unsatisfied_prerequisites=["GAP-B"],
    )
    session.gaps["GAP-A"] = gap_a
    session.gaps["GAP-B"] = gap_b
    session.gaps["GAP-C"] = gap_c

    controller.register_gap_dependency(session, "GAP-B", ["GAP-A"])
    controller.register_gap_dependency(session, "GAP-C", ["GAP-B"])

    # Resolve GAP-A
    gap_a.status = GapStatus.RESOLVED
    gap_a.unsatisfied_prerequisites.clear()

    controller.propagate_dependency_restoration(session=session, resolved_gap_id="GAP-A")

    # GAP-B had only GAP-A as prerequisite -> now unblocked and ready for investigation (OPEN or PLANNED)
    assert gap_b.status in [GapStatus.OPEN, GapStatus.PLANNED]
    assert len(gap_b.unsatisfied_prerequisites) == 0

    # GAP-C still depends on GAP-B (which is OPEN, not yet RESOLVED) -> remains DEPENDENCY_UNSATISFIED
    assert gap_c.status == GapStatus.DEPENDENCY_UNSATISFIED
    assert "GAP-B" in gap_c.unsatisfied_prerequisites


# =============================================================================
# 11. END-TO-END VERTICAL INTEGRATION TEST
# =============================================================================

def test_vertical_e2e_investigation_hardening_lifecycle():
    """
    COMPLETE VERTICAL INTEGRATION TEST:
    QUESTION
    -> PLAN
    -> MULTIPLE GAPS
    -> DEPENDENCIES
    -> EVIDENCE
    -> CONTRADICTION
    -> GAP REOPENING / BLOCKING
    -> TARGETED REINVESTIGATION
    -> SUFFICIENCY
    -> VERIFIED TERMINATION.
    """
    retriever = MockMemoryRetriever()

    ev_init = make_test_evidence(
        "DOC-INIT",
        "Project Phoenix Launch Overview: Launch requires Security CAB authorization CR-888 "
        "and Database migration MIG-200.",
        created_at="2026-10-24T08:00:00Z",
    )
    ev_app = make_test_evidence(
        "DOC-CR-888-APP",
        "Security CAB Meeting #88: Change request CR-888 is APPROVED for Friday launch.",
        created_at="2026-10-24T09:00:00Z",
    )
    ev_mig = make_test_evidence(
        "DOC-MIG-200",
        "Database Migration Log: MIG-200 schema update executed successfully and verified.",
        created_at="2026-10-24T09:30:00Z",
    )
    ev_revoke = make_test_evidence(
        "DOC-CR-888-REVOKE",
        "EMERGENCY SECURITY NOTICE: Change request CR-888 is DENIED and CANCELLED due to audit findings.",
        created_at="2026-10-24T10:00:00Z",
    )
    ev_reauth = make_test_evidence(
        "DOC-CR-888-REAUTH",
        "Security CAB Special Session DECISION: CR-888 audit findings addressed; re-authorization APPROVED and VALID. SUPERSEDES earlier revocation.",
        created_at="2026-10-24T11:00:00Z",
    )
    ev_smoke = make_test_evidence(
        "DOC-VAL-SMOKE",
        "Phoenix End-to-End Validation: Automated smoke test suite PASSED with 100% success rate.",
        created_at="2026-10-24T12:00:00Z",
    )

    retriever.add_canned_response("phoenix readiness", [ev_init])
    retriever.add_canned_response("cr-888 decision", [ev_app])
    retriever.add_canned_response("cr-888 approval", [ev_app])
    retriever.add_canned_response("mig-200", [ev_mig])
    retriever.add_canned_response("emergency security notice", [ev_revoke])
    retriever.add_canned_response("security cab special session", [ev_reauth])
    retriever.add_canned_response("reconcile cr-888", [ev_reauth])
    retriever.add_canned_response("phoenix smoke", [ev_smoke])

    budget = InvestigationBudget(max_hops=6, max_llm_calls=8, max_queries=30)
    controller = InvestigationController(retriever=retriever, budget=budget)

    # Guided reasoning agent simulating real multi-turn investigation loop
    def guided_reasoning_agent(state: InvestigationState) -> Tuple[bool, str, List[InformationGap], List[EvidenceEdge]]:
        accum_ids = set(state.accumulated_evidence.keys())

        # Check what evidence we currently have
        has_auth_app = "DOC-CR-888-APP" in accum_ids
        has_mig = "DOC-MIG-200" in accum_ids
        has_revoke = "DOC-CR-888-REVOKE" in accum_ids
        has_reauth = "DOC-CR-888-REAUTH" in accum_ids
        has_smoke = "DOC-VAL-SMOKE" in accum_ids

        # Turn 1: Retrieve CAB authorization CR-888
        if not has_auth_app:
            gap_auth = InformationGap(
                gap_id="GAP-AUTH",
                gap_type=GapType.AUTHORITY_RESOLUTION,
                is_blocking=True,
                description="Verify CAB authorization CR-888",
                target_entity="CR-888",
                required_information="CR-888 approval status",
                targeted_query="CR-888 approval",
            )
            return False, "Searching for CAB authorization", [gap_auth], []

        # Turn 2: Retrieve migration MIG-200
        if not has_mig:
            gap_mig = InformationGap(
                gap_id="GAP-MIG",
                gap_type=GapType.PREREQUISITE,
                is_blocking=True,
                description="Verify database migration MIG-200",
                target_entity="MIG-200",
                required_information="MIG-200 execution status",
                targeted_query="MIG-200 schema update",
            )
            return False, "Searching for migration execution", [gap_mig], []

        # Turn 3: Introduce contradictory security revocation
        if not has_revoke:
            gap_contra = InformationGap(
                gap_id="GAP-AUDIT",
                gap_type=GapType.CONTRADICTION_RECONCILIATION,
                is_blocking=True,
                description="Check latest security audit notices",
                target_entity="CR-888",
                required_information="CR-888 security audit notices",
                targeted_query="EMERGENCY SECURITY NOTICE CR-888",
            )
            return False, "Checking security audit notices", [gap_contra], []

        # Turn 4: Contradiction active; targeted reinvestigation for resolution
        if not has_reauth:
            gap_resolve = InformationGap(
                gap_id="GAP-RECONCILE",
                gap_type=GapType.CONTRADICTION_RECONCILIATION,
                is_blocking=True,
                description="Reconcile CR-888 disposition",
                target_entity="CR-888",
                required_information="CR-888 Special Session re-authorization",
                targeted_query="Security CAB Special Session CR-888",
            )
            return False, "Investigating contradiction reconciliation", [gap_resolve], []

        # Turn 5: Retrieve smoke test validation
        if not has_smoke:
            gap_smoke = InformationGap(
                gap_id="GAP-SMOKE",
                gap_type=GapType.PREREQUISITE,
                is_blocking=True,
                description="Verify end-to-end smoke test suite",
                target_entity="Phoenix",
                required_information="Automated smoke test suite PASSED",
                targeted_query="Phoenix smoke test suite",
            )
            return False, "Gathering final smoke test validation", [gap_smoke], []

        # Turn 6: Declare sufficiency
        return True, "All prerequisites gathered, contradiction reconciled, validation passed.", [], []

    package = controller.run_investigation(
        objective="Verify Project Phoenix readiness for Friday launch",
        reasoning_agent_fn=guided_reasoning_agent,
        initial_k=1,
    )

    # Verify complete investigation lifecycle outcome
    assert package is not None
    assert package.controller_verified is True, f"Investigation not verified: {package.termination_reason}"
    assert package.termination_reason == "SUFFICIENT"

    # Verify evidence collection
    collected_ids = {e.evidence_id for e in package.evidence_items}
    assert "DOC-INIT" in collected_ids
    assert "DOC-CR-888-APP" in collected_ids
    assert "DOC-MIG-200" in collected_ids
    assert "DOC-CR-888-REVOKE" in collected_ids
    assert "DOC-CR-888-REAUTH" in collected_ids
    assert "DOC-VAL-SMOKE" in collected_ids

    # Verify investigation trace records all key state transitions
    event_types = [e.event_type for e in package.investigation_trace]
    assert "INVESTIGATION_PLANNED" in event_types
    assert "INITIAL_RETRIEVAL" in event_types
    assert "ACTIONABLE_GAP_EXECUTED" in event_types
    assert "CONTROLLER_VERIFIED_SUFFICIENT" in event_types
    assert "INVESTIGATION_TERMINATED" in event_types

    # Provenance integrity: lengths and offsets are verified
    for ev in package.evidence_items:
        assert len(ev.content) > 0
        assert ev.end_offset >= ev.start_offset
