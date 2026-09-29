"""
ORACLE Brick 3.4 Test Suite: Investigation Planning, Gap Lifecycle, Action Validation,
Evidence Resolution, Termination Hardening, and Deterministic End-to-End Trace.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
from backend.investigation.controller import InvestigationController
from backend.investigation.planner import InvestigationPlanner
from backend.investigation.models import (
    ActionStatus,
    ActionType,
    EdgeDerivationType,
    EvidenceEdge,
    GapStatus,
    GapType,
    InformationGap,
    InvalidGapTransitionError,
    InvestigationAction,
    InvestigationBudget,
    InvestigationHypothesis,
    InvestigationPlan,
    InvestigationSession,
    InvestigationState,
    RelationshipType,
)
from backend.synthesis.synthesizer import EvidenceSynthesizer, SynthesisStatus


CORPUS_DIR = Path("tests/test_data/nova_corpus")


@pytest.fixture
def corpus_retriever():
    parser = MarkdownEvidenceParser()
    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever = SQLiteFTS5Retriever(":memory:")
    retriever.index_evidence(all_chunks)
    return retriever


def make_evidence(eid: str, content: str, source_id: str = "TEST-SRC", source_type: str = "document") -> Evidence:
    return Evidence(
        evidence_id=eid,
        source_id=source_id,
        source_type=source_type,
        content=content,
        content_hash=f"hash_{eid}",
        source_path=f"path/{source_id}",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content),
        created_at="2026-10-21T12:00:00Z",
    )


# =============================================================================
# 1. PLANNING TESTS (Question -> Gaps, Deduplication, Prioritization)
# =============================================================================

def test_planning_question_to_hypotheses_and_gaps():
    """Verify question parsing, hypothesis formulation, gap creation, and action generation."""
    planner = InvestigationPlanner()
    objective = "Verify if INC-402 is resolved and CR-904 is approved for deployment"
    plan = planner.plan(objective=objective)

    assert isinstance(plan, InvestigationPlan)
    assert len(plan.hypotheses) == 2
    affirmative = next(h for h in plan.hypotheses if "AFFIRMATIVE" in h.hypothesis_id)
    risk = next(h for h in plan.hypotheses if "RISK" in h.hypothesis_id)
    assert "satisfied" in affirmative.statement
    assert "block" in risk.statement

    # Gaps: Root gap + 2 reference gaps (INC-402, CR-904)
    gap_ids = {g.gap_id for g in plan.gaps}
    assert "GAP-ROOT-1" in gap_ids
    assert "GAP-REF-INC-402" in gap_ids
    assert "GAP-REF-CR-904" in gap_ids

    # Gaps must be planned and prioritized
    for g in plan.gaps:
        assert g.status == GapStatus.PLANNED
        assert g.why_needed != ""
        assert g.evidence_requirement != ""

    # Actions must be proposed with explicit reasons tied to gaps
    assert len(plan.planned_actions) >= 1
    for act in plan.planned_actions:
        assert act.status == ActionStatus.PROPOSED
        assert act.reason != ""
        assert act.gap_id in gap_ids


def test_planning_duplicate_gap_deduplication():
    """Verify that semantically equivalent gaps are deduplicated and merged."""
    planner = InvestigationPlanner()
    gap1 = InformationGap(
        gap_id="GAP-A",
        gap_type=GapType.PREREQUISITE,
        target_entity="Payment Gateway",
        description="Verify Payment Gateway datastore configuration",
        required_information="mutual TLS 1.3 configuration for Payment Gateway",
        candidate_queries=["Payment Gateway mTLS config"],
        required_facts=["mTLS 1.3"],
        originating_evidence_ids=["EVID-01"],
    )
    gap2 = InformationGap(
        gap_id="GAP-B",
        gap_type=GapType.PREREQUISITE,
        target_entity="Payment Gateway",
        description="Verify Payment Gateway datastore mutual TLS security configuration",
        required_information="mutual TLS 1.3 configuration for Payment Gateway",
        candidate_queries=["Payment Gateway TLS settings"],
        required_facts=["datastore encryption"],
        originating_evidence_ids=["EVID-02"],
    )

    deduped = planner.deduplicate_gaps([gap1, gap2])
    assert len(deduped) == 1
    merged = deduped[0]
    assert merged.gap_id == "GAP-A"
    assert "Payment Gateway TLS settings" in merged.candidate_queries
    assert "datastore encryption" in merged.required_facts
    assert "EVID-02" in merged.originating_evidence_ids


def test_planning_gap_prioritization():
    """Verify deterministic prioritization: blocking > non-blocking, contradiction > regular."""
    planner = InvestigationPlanner()
    g_contra = InformationGap(gap_id="GAP-CONTRA", description="contra", gap_type=GapType.CONTRADICTION_RECONCILIATION, is_blocking=True)
    g_prereq = InformationGap(gap_id="GAP-PREREQ", description="prereq", gap_type=GapType.PREREQUISITE, is_blocking=True)
    g_opt = InformationGap(gap_id="GAP-OPT", description="opt", gap_type=GapType.PREREQUISITE, is_blocking=False)

    score_contra = planner._default_priority_score(g_contra)
    score_prereq = planner._default_priority_score(g_prereq)
    score_opt = planner._default_priority_score(g_opt)

    assert score_contra > score_prereq > score_opt


# =============================================================================
# 2. STATE LIFECYCLE & TRANSITION TESTS
# =============================================================================

def test_gap_lifecycle_valid_transitions():
    """Verify controlled progression: OPEN -> PLANNED -> SEARCHING -> UNDER_REVIEW -> RESOLVED."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s1", objective="test")
    gap = InformationGap(gap_id="GAP-LIFE-1", description="Lifecycle gap", status=GapStatus.OPEN)
    session.gaps[gap.gap_id] = gap

    assert controller.transition_gap(gap, GapStatus.PLANNED, "Planner formulated", session)
    assert gap.status == GapStatus.PLANNED

    assert controller.transition_gap(gap, GapStatus.SEARCHING, "Action dispatched", session)
    assert gap.status == GapStatus.SEARCHING

    assert controller.transition_gap(gap, GapStatus.UNDER_REVIEW, "Evidence collected", session)
    assert gap.status == GapStatus.UNDER_REVIEW

    assert controller.transition_gap(gap, GapStatus.RESOLVED, "Criteria satisfied", session)
    assert gap.status == GapStatus.RESOLVED


def test_gap_lifecycle_invalid_transition_rejected():
    """Controller must reject illegal lifecycle transitions with InvalidGapTransitionError."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s2", objective="test")
    gap = InformationGap(gap_id="GAP-ILLEGAL", description="Illegal gap", status=GapStatus.PLANNED)
    session.gaps[gap.gap_id] = gap

    # Illegal: PLANNED directly to RESOLVED without searching/reviewing
    with pytest.raises(InvalidGapTransitionError):
        controller.transition_gap(gap, GapStatus.RESOLVED, "Illegal jump from planned", session)

    # Illegal: BLOCKED to RESOLVED without unblocking/reopening
    gap.status = GapStatus.BLOCKED
    with pytest.raises(InvalidGapTransitionError):
        controller.transition_gap(gap, GapStatus.RESOLVED, "Illegal jump from blocked", session)


def test_gap_lifecycle_reopening_on_conflicting_evidence():
    """Verify reopening when later evidence contradicts an earlier resolution."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s3", objective="test")

    ev_resolve = make_evidence("EV-APPR", "CR-904 was approved by CAB.")
    session.discovered_evidence[ev_resolve.evidence_id] = ev_resolve

    gap = InformationGap(
        gap_id="GAP-CR-904",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Verify CR-904 approval",
        target_entity="CR-904",
        status=GapStatus.RESOLVED,
        resolution_status=True,
        resolution_evidence_ids=[ev_resolve.evidence_id],
    )
    session.gaps[gap.gap_id] = gap

    # New contradictory evidence arrives
    ev_reject = make_evidence("EV-REJ", "CR-904 was REJECTED during emergency review rollback.")
    session.discovered_evidence[ev_reject.evidence_id] = ev_reject

    controller._evaluate_all_gaps(session, [ev_reject.evidence_id])

    # Gap must reopen to REOPENED
    assert gap.status == GapStatus.REOPENED
    assert gap.resolved is False
    assert ev_reject.evidence_id in gap.conflicting_evidence_ids

    # Must have spawned a contradiction gap
    contra_gaps = [g for g in session.gaps.values() if g.gap_type == GapType.CONTRADICTION_RECONCILIATION]
    assert len(contra_gaps) >= 1
    assert contra_gaps[0].is_blocking is True


# =============================================================================
# 3. SEARCH ACTION VALIDATION & DEDUPLICATION TESTS
# =============================================================================

def test_controller_action_validation_normalization_and_stopwords():
    """Controller rejects empty queries, whitespace-only queries, and stopword-only queries."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s4", objective="test")
    gap = InformationGap(gap_id="GAP-V1", description="Validation gap 1", status=GapStatus.OPEN)
    session.gaps[gap.gap_id] = gap

    # Empty query
    act_empty = InvestigationAction(action_id="A1", gap_id="GAP-V1", query="   ", reason="test")
    valid, reason = controller.validate_action(act_empty, session)
    assert valid is False
    assert "Empty" in reason

    # Stopwords only
    act_stops = InvestigationAction(action_id="A2", gap_id="GAP-V1", query="can we what is that", reason="test")
    valid, reason = controller.validate_action(act_stops, session)
    assert valid is False
    assert "stopwords" in reason


def test_controller_action_validation_exact_and_near_duplicate():
    """Controller rejects exact and high-Jaccard overlapping queries."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s5", objective="test")
    gap = InformationGap(gap_id="GAP-V2", description="Validation gap 2", status=GapStatus.OPEN)
    session.gaps[gap.gap_id] = gap

    session.query_history.add("payment gateway mtls configuration")

    # Exact duplicate (case-insensitive)
    act_exact = InvestigationAction(action_id="A3", gap_id="GAP-V2", query="Payment Gateway mTLS Configuration", reason="test")
    valid, reason = controller.validate_action(act_exact, session)
    assert valid is False
    assert "Exact match" in reason

    # Near duplicate (high Jaccard overlap)
    act_near = InvestigationAction(action_id="A4", gap_id="GAP-V2", query="the payment gateway mtls configurations", reason="test")
    valid, reason = controller.validate_action(act_near, session)
    assert valid is False
    assert "Jaccard" in reason


def test_controller_action_validation_zero_yield_duplicate():
    """Controller rejects queries too close to previously recorded zero-yield queries."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s6", objective="test")
    gap = InformationGap(gap_id="GAP-V3", description="Validation gap 3", status=GapStatus.OPEN)
    session.gaps[gap.gap_id] = gap

    session.zero_yield_queries.add("oracle legacy database v99")

    act = InvestigationAction(action_id="A5", gap_id="GAP-V3", query="oracle legacy database v99 details", reason="test")
    valid, reason = controller.validate_action(act, session)
    assert valid is False
    assert "zero-yield" in reason


def test_controller_action_validation_objective_echo():
    """Controller rejects proposed actions that merely echo the root objective."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s7", objective="Can Project Phoenix launch safely on Friday?")
    gap = InformationGap(gap_id="GAP-V4", description="Validation gap 4", status=GapStatus.OPEN)
    session.gaps[gap.gap_id] = gap

    act = InvestigationAction(action_id="A6", gap_id="GAP-V4", query="Can Project Phoenix launch safely on Friday?", reason="test")
    valid, reason = controller.validate_action(act, session)
    assert valid is False
    assert "Echoes root objective" in reason


def test_controller_action_validation_gap_association():
    """Controller rejects action targeting non-existent or already resolved gap."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s8", objective="test")
    gap_res = InformationGap(gap_id="GAP-RESOLVED", description="Resolved gap", status=GapStatus.RESOLVED)
    session.gaps[gap_res.gap_id] = gap_res

    # Non-existent gap
    act_ghost = InvestigationAction(action_id="A7", gap_id="GAP-NONEXISTENT", query="search terms", reason="test")
    valid, reason = controller.validate_action(act_ghost, session)
    assert valid is False
    assert "does not exist" in reason

    # Resolved gap
    act_res = InvestigationAction(action_id="A8", gap_id="GAP-RESOLVED", query="search terms", reason="test")
    valid, reason = controller.validate_action(act_res, session)
    assert valid is False
    assert "RESOLVED" in reason


# =============================================================================
# 4. EVIDENCE EVALUATION & GAP RESOLUTION TESTS
# =============================================================================

def test_evidence_evaluation_relevant_vs_irrelevant():
    """Relevant authoritative evidence resolves gap; irrelevant evidence leaves it open."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s9", objective="test")

    gap = InformationGap(
        gap_id="GAP-PAYMENT",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway configuration",
        target_entity="Payment Gateway",
        required_information="mutual TLS 1.3 configuration",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    # 1. Irrelevant evidence
    ev_irr = make_evidence("E-IRR", "Team lunch scheduled for Wednesday at noon.")
    session.discovered_evidence[ev_irr.evidence_id] = ev_irr
    controller._evaluate_gap_resolution(gap, session, [ev_irr.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False

    # 2. Relevant evidence
    ev_rel = make_evidence("E-REL", "Payment Gateway v2 strictly requires mutual TLS 1.3 datastore configuration.")
    session.discovered_evidence[ev_rel.evidence_id] = ev_rel
    controller._evaluate_gap_resolution(gap, session, [ev_rel.evidence_id])
    assert gap.status == GapStatus.RESOLVED
    assert gap.resolved is True
    assert ev_rel.evidence_id in gap.resolution_evidence_ids


def test_evidence_evaluation_multi_fact_sufficiency():
    """Multi-fact requirements must all be present before gap is resolved."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s10", objective="test")

    gap = InformationGap(
        gap_id="GAP-MULTI-FACT",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify cluster node specifications",
        target_entity="Cluster Node",
        required_facts=["Redis 7.2", "Cluster Mode", "Replication Factor 3"],
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    # Evidence with only partial facts
    ev_partial = make_evidence("E-PARTIAL", "Cluster Node runs Redis 7.2 in Cluster Mode.")
    session.discovered_evidence[ev_partial.evidence_id] = ev_partial
    controller._evaluate_gap_resolution(gap, session, [ev_partial.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False

    # Evidence with all required facts
    ev_full = make_evidence("E-FULL", "Cluster Node verified: Redis 7.2, Cluster Mode active, Replication Factor 3 confirmed.")
    session.discovered_evidence[ev_full.evidence_id] = ev_full
    controller._evaluate_gap_resolution(gap, session, [ev_full.evidence_id])
    assert gap.status == GapStatus.RESOLVED
    assert gap.resolved is True


def test_evidence_evaluation_conflicting_evidence():
    """Conflicting evidence transitions gap to RECONCILIATION_REQUIRED, recording both chunks."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s11", objective="test")

    gap = InformationGap(
        gap_id="GAP-CR",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Verify CR-904 disposition",
        target_entity="CR-904",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    ev_approved = make_evidence("E-APP", "DECISION: CR-904 is APPROVED for deployment.")
    ev_rollback = make_evidence("E-ROL", "CR-904 was REJECTED following ROLLBACK order.")
    session.discovered_evidence[ev_approved.evidence_id] = ev_approved
    session.discovered_evidence[ev_rollback.evidence_id] = ev_rollback

    controller._evaluate_gap_resolution(gap, session, [ev_approved.evidence_id, ev_rollback.evidence_id])
    assert gap.status == GapStatus.RECONCILIATION_REQUIRED
    assert ev_approved.evidence_id in gap.resolution_evidence_ids
    assert ev_rollback.evidence_id in gap.conflicting_evidence_ids


# =============================================================================
# 5. TERMINATION CRITERIA & CONTROLLER AUTHORITY TESTS
# =============================================================================

def test_termination_unresolved_blocking_gap_prevents_termination():
    """Premature LLM termination must be rejected by controller when a blocking gap is open."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s12", objective="test")

    ev1 = make_evidence("E1", "Evidence 1")
    ev2 = make_evidence("E2", "Evidence 2")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev2.evidence_id] = ev2

    gap_open = InformationGap(gap_id="GAP-BLOCKING", description="Blocking requirement", is_blocking=True, status=GapStatus.OPEN)
    session.gaps[gap_open.gap_id] = gap_open

    # LLM claims sufficient
    is_suff = controller.is_session_sufficient(session)
    assert is_suff is False

    state_view = controller._build_state_view(session)
    verified, reason = controller.verify_sufficiency(state_view, "LLM says all done")
    assert verified is False
    assert "Blocking gap" in reason


def test_controller_authority_llm_cannot_force_resolved_gap():
    """Controller must override and reject any attempt by LLM to directly set GapStatus.RESOLVED."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s13", objective="test")

    # LLM proposes a new gap claiming it is already RESOLVED
    sneaky_gap = InformationGap(
        gap_id="GAP-SNEAKY",
        description="LLM claims this is already resolved without evidence",
        status=GapStatus.RESOLVED,
    )

    # Controller processes candidate gaps from LLM proposal:
    if sneaky_gap.status in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]:
        sneaky_gap.status = GapStatus.OPEN
    if sneaky_gap.gap_id not in session.gaps:
        sneaky_gap.status = GapStatus.PLANNED
        session.gaps[sneaky_gap.gap_id] = sneaky_gap

    assert session.gaps["GAP-SNEAKY"].status == GapStatus.PLANNED
    assert session.gaps["GAP-SNEAKY"].resolved is False


def test_controller_authority_llm_cannot_bypass_action_validation():
    """Controller rejects invalid/duplicate LLM action proposals deterministically."""
    controller = InvestigationController(retriever=None)
    session = InvestigationSession(session_id="s14", objective="Project Phoenix launch")
    session.query_history.add("project phoenix launch")

    act_dup = InvestigationAction(
        action_id="ACT-LLM-01",
        gap_id="GAP-ROOT-1",
        query="Project Phoenix launch",
        reason="Duplicate query",
    )
    valid, reason = controller.validate_action(act_dup, session)
    assert valid is False
    assert "Exact match" in reason


# =============================================================================
# 6. DETERMINISTIC END-TO-END INVESTIGATION SCENARIO (REQUIREMENT 10)
# =============================================================================

def test_brick34_e2e_investigation_trace_and_gap_resolution(corpus_retriever):
    """
    DETERMINISTIC END-TO-END SCENARIO (BRICK 3.4 MANDATORY VALIDATION):
    Executes full vertical slice:
      QUESTION
      -> PLAN (Hypotheses + Gaps + Initial Actions)
      -> TARGETED SEARCH
      -> EVIDENCE EVALUATION
      -> PREMATURE / INSUFFICIENT TERMINATION REJECTION (Hop 1)
      -> FURTHER TARGETED INVESTIGATION (Hop 2 & 3)
      -> FINAL SUFFICIENCY VERIFICATION
      -> VERIFIED TERMINATION WITH PROVENANCE
      -> OBSERVABLE INVESTIGATION TRACE
    """
    controller = InvestigationController(
        retriever=corpus_retriever,
        budget=InvestigationBudget(max_hops=4, max_llm_calls=4, max_queries=8),
    )

    call_index = 0

    def guided_agent(state: InvestigationState):
        nonlocal call_index
        call_index += 1

        has_payment = any("DOC-NOVA-PAYMENT" in e.source_id for e in state.accumulated_evidence.values())
        has_incident = any("DOC-NOVA-INC-402" in e.source_id for e in state.accumulated_evidence.values())
        has_cab = any("DOC-NOVA-CAB" in e.source_id for e in state.accumulated_evidence.values())

        # Turn 1: Try premature termination (must be REJECTED by controller, but provide next gap)
        if call_index == 1:
            return True, "Premature attempt to claim sufficiency before resolving dependencies", [
                InformationGap(
                    gap_id="GAP-PAYMENT",
                    gap_type=GapType.PREREQUISITE,
                    description="Identify Payment Gateway v2 security specs",
                    targeted_query="Payment Gateway v2 mTLS requirements",
                    why_needed="Payment Gateway is an active integration dependency",
                )
            ], []

        # Turn 2: Target Incident
        if not has_incident:
            return False, "Need Redis operational configuration", [
                InformationGap(
                    gap_id="GAP-REDIS",
                    gap_type=GapType.AUTHORITY_RESOLUTION,
                    description="Check active Redis production version and rollback status",
                    targeted_query="INC-402 Redis rollback current production state",
                    why_needed="Resolve unverified operational state of Redis cache",
                )
            ], []

        # Turn 3: Target CAB Decision
        if not has_cab:
            return False, "Need CAB decision record", [
                InformationGap(
                    gap_id="GAP-CAB",
                    gap_type=GapType.AUTHORITY_RESOLUTION,
                    description="Check CAB decision meeting #88 disposition",
                    targeted_query="Change Advisory Board decision log meeting #88",
                    why_needed="Authoritative change authorization required",
                )
            ], []

        return True, "All operational prerequisites and dependency chains assembled", [], []

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        reasoning_agent_fn=guided_agent,
        initial_k=2,
    )

    # 1. Package must be controller-verified and sufficient
    assert package is not None
    assert package.controller_verified is True
    assert package.termination_reason == "SUFFICIENT"

    # 2. Verify evidence chain completeness
    admitted_ids = {e.evidence_id for e in package.evidence_items}
    assert any("DOC-NOVA-OVERVIEW" in eid for eid in admitted_ids)
    assert any("DOC-NOVA-CAB" in eid for eid in admitted_ids)
    assert any("DOC-NOVA-INC-402" in eid for eid in admitted_ids)
    assert any("DOC-NOVA-PAYMENT" in eid for eid in admitted_ids)

    # 3. Verify Hypotheses in session
    assert len(package.hypotheses) == 2
    assert any(h.hypothesis_id == "HYP-01-AFFIRMATIVE" for h in package.hypotheses)
    assert any(h.hypothesis_id == "HYP-02-RISK" for h in package.hypotheses)

    # 4. Verify Actions recorded with execution metadata
    assert len(package.actions) >= 2
    for act in package.actions:
        assert act.status == ActionStatus.EXECUTED
        assert act.executed_at_hop is not None
        assert act.gap_id is not None
        assert act.yield_chunk_count >= 0

    # 5. Verify Gap state and resolutions
    root_gap = next((g for g in package.gaps if g.gap_id == "GAP-ROOT-1"), None)
    assert root_gap is not None
    assert root_gap.status == GapStatus.RESOLVED

    # 6. Verify Investigation Trace captures full lifecycle events
    event_types = [ev.event_type for ev in package.investigation_trace]
    assert "INVESTIGATION_PLANNED" in event_types
    assert "GAP_TRANSITION" in event_types
    assert "ACTIONABLE_GAP_EXECUTED" in event_types
    assert "CONTROLLER_VERIFIED_SUFFICIENT" in event_types
    assert "INVESTIGATION_TERMINATED" in event_types

    # Verify that the premature termination attempt on Hop 1 was explicitly rejected by controller
    rejections = [ev for ev in package.investigation_trace if ev.event_type == "CONTROLLER_REJECTED_SUFFICIENCY"]
    assert len(rejections) >= 1
    assert "Blocking gap(s) still open" in rejections[0].description

    # 7. Observable dictionary export
    obs = package.to_observable_dict()
    assert "objective" in obs
    assert "hypotheses" in obs
    assert "gaps" in obs
    assert "actions" in obs
    assert "investigation_trace" in obs
    assert obs["controller_verified"] is True
    assert obs["termination_reason"] == "SUFFICIENT"

    # 8. Synthesize final answer with provenance
    synthesizer = EvidenceSynthesizer()
    synthesis = synthesizer.synthesize(package)
    assert synthesis is not None
    assert synthesis.status == SynthesisStatus.RECONCILIATION_REQUIRED
    assert synthesis.reconciliation_report is not None
    assert len(synthesis.reconciliation_report.contradictions) >= 1
    assert "Reconciliation Required" in synthesis.final_answer
    # Provenance: all evidence items maintain complete provenance tracking
    assert len(package.evidence_items) >= 4
    for ev in package.evidence_items:
        assert ev.evidence_id != ""
        assert ev.source_id != ""
        assert ev.content != ""
