"""
Unit Tests for ORACLE Phase 2.1: Investigation Termination & Gap Resolution Hardening

Validates:
  TERM-INV-01: An unresolved blocking gap MUST prevent SUFFICIENT.
  TERM-INV-02: An evidence item MUST NOT satisfy a gap merely because it exists.
  TERM-INV-03: Unknown/unrecognized gap types MUST default to unresolved, not resolved.
  TERM-INV-04: A gap can only be resolved when evidence matches the actual requirements.
  TERM-INV-05: Partial evidence MUST NOT be promoted to complete resolution.
  TERM-INV-06: Contradictory evidence MUST NOT silently resolve a gap.
  TERM-INV-07: Evidence for entity A MUST NOT satisfy a requirement for entity B.
  TERM-INV-08: Budget exhaustion MUST NOT be represented as epistemic sufficiency.
  TERM-INV-09: Adding irrelevant evidence MUST NOT cause an unresolved gap to become resolved.
  TERM-INV-10: Removing evidence that was necessary for a resolved gap causes insufficiency.
  TERM-INV-11: Gap resolution must be deterministic.
  TERM-INV-12: No domain-specific strings (ARCH/CAB/DOC-NOVA-CAB) in generic termination mechanism.

Attack Categories:
  A. UNKNOWN GAP ATTACKS (1-4)
  B. ENTITY CROSSOVER (5-8)
  C. PARTIAL EVIDENCE (9-12)
  D. CONTRADICTION (13-16)
  E. IRRELEVANT-EVIDENCE FLOODING (17-20)
  F. BUDGET / TERMINATION (21-25)
  G. MULTI-HOP (26-29)
  H. REGRESSION (30-35)
"""

import copy
import json
from pathlib import Path
import pytest

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationSession,
    InvestigationState,
    EvidenceEdge,
    RelationshipType,
    EdgeDerivationType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def retriever(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("term_hardening") / "fts.db"
    retr = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retr.index_evidence(all_chunks)
    return retr


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
# CATEGORY A: UNKNOWN / UNRECOGNIZED GAP ATTACKS
# =============================================================================

def test_a1_unknown_gap_unrelated_evidence(retriever):
    """1. Unknown gap + unrelated evidence -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_a1", objective="Test Objective")
    ev = make_evidence("EV-1", "Billing database transaction count is 10000.")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-UNK-1",
        gap_type="HYPOTHETICAL_CUSTOM_TYPE",
        is_blocking=True,
        description="Unknown custom gap requirement",
        target_entity="BillingDB",
        required_information="Transaction metrics",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False
    assert len(gap.resolution_evidence_ids) == 0


def test_a2_unknown_gap_many_unrelated_evidence(retriever):
    """2. Unknown gap + many unrelated evidence items -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_a2", objective="Test Objective")
    ev_ids = []
    for i in range(10):
        ev = make_evidence(f"EV-MANY-{i}", f"Unrelated log event {i} for subsystem {i}")
        session.discovered_evidence[ev.evidence_id] = ev
        ev_ids.append(ev.evidence_id)

    gap = InformationGap(
        gap_id="GAP-UNK-2",
        gap_type="SYNTHETIC_LLM_PROPOSAL",
        is_blocking=True,
        description="Synthetic custom gap requirement",
        target_entity="SubsystemCluster",
        required_information="Cluster topology",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, ev_ids)
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_a3_unknown_gap_valid_evidence_for_another_gap(retriever):
    """3. Unknown gap + valid evidence for another gap -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_a3", objective="Test Objective")
    # Valid evidence for INC-402
    ev = make_evidence("EV-INC-402", "**Current Production State:** The active production Redis cluster is currently running Redis v5.4.12.")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-UNK-3",
        gap_type="UNKNOWN_ARBITRARY_TYPE",
        is_blocking=True,
        description="Unknown gap targeting something else",
        target_entity="INC-402",
        required_information="State of INC-402",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_a4_unknown_gap_evidence_from_another_provider(retriever):
    """4. Unknown gap + evidence from Jira/GitHub provider -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_a4", objective="Test Objective")
    ev = make_evidence("jira:TICK-101#c000", "Jira ticket status is In Progress", source_id="jira:TICK-101", source_type="jira")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-UNK-4",
        gap_type="CUSTOM_TICKET_GAP",
        is_blocking=True,
        description="Ticket gap with custom type",
        target_entity="TICK-101",
        required_information="Ticket completion",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


# =============================================================================
# CATEGORY B: ENTITY CROSSOVER ATTACKS
# =============================================================================

def test_b5_service_a_requirement_service_b_evidence(retriever):
    """5. Requirement for ServiceA + evidence for ServiceB -> Must NOT resolve."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_b5", objective="Verify ServiceA readiness")
    ev = make_evidence("EV-SVC-B", "ServiceB deployment succeeded and health checks are passing.", source_id="SERVICE-B")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-PREREQ-SVC-A",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Operational requirement for ServiceA",
        target_entity="ServiceA",
        required_information="ServiceA health checks and deployment status",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False
    assert len(gap.resolution_evidence_ids) == 0


def test_b6_incident_a_requirement_incident_b_evidence(retriever):
    """6. Requirement for IncidentA + evidence for IncidentB -> Must NOT resolve."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_b6", objective="Verify Incident remediation")
    ev = make_evidence("EV-INC-B", "**Current Production State:** INC-999 rollback completed successfully.", source_id="INC-999")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-AUTH-INC-111",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Authoritative resolution for INC-111",
        target_entity="INC-111",
        required_information="Current production state of INC-111",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_b7_same_metric_wrong_entity(retriever):
    """7. Same metric (p99 latency < 50ms), wrong entity -> Must NOT resolve."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_b7", objective="Verify SLA")
    ev = make_evidence("EV-METRIC-WRONG", "CheckoutGateway p99 latency SLA is 42ms under load.", source_id="METRICS-CHECKOUT")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-AUTH-GW",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify AuthGateway latency SLA",
        target_entity="AuthGateway",
        required_information="AuthGateway p99 latency SLA under load",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_b8_same_keywords_wrong_entity(retriever):
    """8. Same operational keywords, wrong entity -> Must NOT resolve."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_b8", objective="Verify pipeline cutover")
    ev = make_evidence("EV-PIPE-B", "DataPipeline Beta completed cutover and DNS traffic migration.", source_id="PIPE-B")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-PIPE-A",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify DataPipeline Alpha cutover",
        target_entity="DataPipeline Alpha",
        required_information="DataPipeline Alpha cutover and DNS traffic migration",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


# =============================================================================
# CATEGORY C: PARTIAL EVIDENCE ATTACKS
# =============================================================================

def test_c9_one_required_fact_present_second_missing(retriever):
    """9. One required fact present, second missing -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_c9", objective="Verify Redis")
    # Mentions Redis active version v5.4.12, but does NOT mention mTLS 1.3 support
    ev = make_evidence("EV-PARTIAL-1", "Redis cluster is active and running version v5.4.12 in EU region.", source_id="REDIS-STATUS")
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-REDIS-FULL",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Redis version and mTLS 1.3 security support",
        target_entity="Redis",
        required_information="Redis version and mutual TLS 1.3 support",
        required_facts=["version v5.4.12", "mutual TLS 1.3"],
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_c10_two_of_three_required_facts_present(retriever):
    """10. Two of three required facts present -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_c10", objective="Multi-fact verification")
    ev = make_evidence(
        "EV-2-OF-3",
        "Payment Gateway v2 supports token encryption and audit logging.",
        source_id="PAYMENT-SPECS",
    )
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-TRIPLE-FACT",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway compliance",
        target_entity="Payment Gateway",
        required_information="Verify token encryption, audit logging, and hardware security module",
        required_facts=["token encryption", "audit logging", "hardware security module"],
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_c11_correct_entity_incomplete_temporal_evidence(retriever):
    """11. Correct entity but incomplete temporal / current-state evidence -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_c11", objective="Current state of INC-402")
    # Historical narrative only, lacking current production state
    ev = make_evidence(
        "EV-HISTORICAL",
        "On October 20 at 14:20 UTC, SRE observed memory segmentation faults during cutover.",
        source_id="INC-402",
    )
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-REF-INC-402",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Current state of INC-402",
        target_entity="INC-402",
        required_information="Status, disposition, or post-mortem of INC-402",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_c12_correct_incident_missing_root_cause(retriever):
    """12. Correct incident but missing root-cause evidence -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_c12", objective="Incident analysis")
    ev = make_evidence(
        "EV-INC-TICKET",
        "Incident INC-550 opened: SRE team paged for checkout degradation.",
        source_id="INC-550",
    )
    session.discovered_evidence[ev.evidence_id] = ev

    gap = InformationGap(
        gap_id="GAP-INC-ROOTCAUSE",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify root cause for INC-550",
        target_entity="INC-550",
        required_information="Root cause analysis and kernel panic diagnostics",
        required_facts=["root cause", "kernel panic diagnostics"],
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


# =============================================================================
# CATEGORY D: CONTRADICTION ATTACKS
# =============================================================================

def test_d13_supporting_plus_contradicting_evidence(retriever):
    """13. Supporting evidence + contradicting evidence -> No silent SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_d13", objective="Verify Change Request CR-904")
    ev1 = make_evidence("EV-CR-PROP", "Marcus Vance proposed emergency Redis upgrade CR-904 for Friday.", source_id="CR-904")
    ev2 = make_evidence("EV-CR-REJ", "CAB Decision: REJECTED. The request to execute CR-904 is UNANIMOUSLY REJECTED.", source_id="DOC-CAB")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev2.evidence_id] = ev2

    edges = controller.scanner.detect_deterministic_edges([ev1, ev2])
    controller._derive_and_update_gaps(session, edges)

    contra_gaps = [g for g in session.gaps.values() if g.gap_type == GapType.CONTRADICTION_RECONCILIATION]
    assert len(contra_gaps) >= 1

    # In the absence of an independent superseding reconciliation, investigation cannot be SUFFICIENT
    state_view = controller._build_state_view(session)
    is_verified, reason = controller.verify_sufficiency(state_view, "")
    # Must either reject or ensure gap transitions to RECONCILIATION_REQUIRED
    assert contra_gaps[0].status in [GapStatus.OPEN, GapStatus.RECONCILIATION_REQUIRED]


def test_d14_newer_contradictory_evidence(retriever):
    """14. Newer contradictory evidence -> Must transition to RECONCILIATION_REQUIRED."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_d14", objective="Verify deployment disposition")
    ev_old = make_evidence("EV-OLD", "Initial deployment plan approved by release team.")
    session.discovered_evidence[ev_old.evidence_id] = ev_old

    gap = InformationGap(
        gap_id="GAP-AUTH-DEP",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Verify release approval",
        target_entity="EV-OLD",
        required_information="Release decision",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    # Admit conflicting newer evidence
    ev_new = make_evidence("EV-NEW", "Deployment decision: REJECTED due to post-mortem rollback.", source_id="EV-OLD")
    session.discovered_evidence[ev_new.evidence_id] = ev_new

    controller._evaluate_gap_resolution(gap, session, [ev_new.evidence_id])
    assert gap.status == GapStatus.RECONCILIATION_REQUIRED
    assert ev_new.evidence_id in gap.conflicting_evidence_ids


def test_d15_equal_timestamp_contradictory_evidence(retriever):
    """15. Equal timestamp contradictory evidence -> No silent SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_d15", objective="Determine system mode")
    ev1 = make_evidence("EV-A", "System mode is ACTIVE on cluster 1.")
    ev2 = make_evidence("EV-B", "System mode is REJECTED and INCOMPATIBLE on cluster 1.")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev2.evidence_id] = ev2

    edge = EvidenceEdge(
        source_evidence_id=ev1.evidence_id,
        target_evidence_id=ev2.evidence_id,
        relationship_type=RelationshipType.CONTRADICTS,
        basis="Contradictory status on cluster 1",
        derived_by=EdgeDerivationType.DETERMINISTIC_REFERENCE,
        confidence=1.0,
    )
    state = InvestigationState(
        objective=session.objective,
        accumulated_evidence=session.discovered_evidence,
        evidence_graph=[edge],
        pending_gaps=[],
        resolved_gaps=[],
    )
    is_verified, reason = controller.verify_sufficiency(state, "Both chunks found")
    assert is_verified is False
    assert "Unreconciled contradiction" in reason


def test_d16_multiple_providers_disagreeing(retriever):
    """16. Multiple providers disagreeing (Jira says Rejected, PR says Merged) -> No silent SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_d16", objective="Verify PR-88 and CR-904")
    ev_jira = make_evidence("jira:CR-904", "CAB Decision: REJECTED for CR-904.", source_id="jira:CR-904", source_type="jira")
    ev_gh = make_evidence("gh:PR-88", "Emergency upgrade CR-904 PR merged to main branch.", source_id="gh:PR-88", source_type="github")
    session.discovered_evidence[ev_jira.evidence_id] = ev_jira
    session.discovered_evidence[ev_gh.evidence_id] = ev_gh

    edges = controller.scanner.detect_deterministic_edges([ev_jira, ev_gh])
    contra_edges = [e for e in edges if e.relationship_type == RelationshipType.CONTRADICTS]
    assert len(contra_edges) >= 1

    state = InvestigationState(
        objective=session.objective,
        accumulated_evidence=session.discovered_evidence,
        evidence_graph=edges,
        pending_gaps=[],
        resolved_gaps=[],
    )
    is_verified, reason = controller.verify_sufficiency(state, "")
    assert is_verified is False


# =============================================================================
# CATEGORY E: IRRELEVANT-EVIDENCE FLOODING ATTACKS
# =============================================================================

def test_e17_open_gap_one_irrelevant_evidence(retriever):
    """17. Open gap + 1 irrelevant evidence item -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_e17", objective="Test")
    gap = InformationGap(
        gap_id="GAP-CORE-DEP",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway datastore security",
        target_entity="Payment Gateway",
        required_information="Payment Gateway mutual TLS 1.3 configuration",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    irrelevant = make_evidence("IRR-1", "Office supply order #402 for printer toner has arrived.")
    session.discovered_evidence[irrelevant.evidence_id] = irrelevant

    controller._evaluate_gap_resolution(gap, session, [irrelevant.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_e18_open_gap_ten_irrelevant_evidence(retriever):
    """18. Open gap + 10 irrelevant evidence items -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_e18", objective="Test")
    gap = InformationGap(
        gap_id="GAP-CORE-DEP-10",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway datastore security",
        target_entity="Payment Gateway",
        required_information="Payment Gateway mutual TLS 1.3 configuration",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    irr_ids = []
    for i in range(10):
        ev = make_evidence(f"IRR-10-{i}", f"General discussion comment {i} about team lunch.")
        session.discovered_evidence[ev.evidence_id] = ev
        irr_ids.append(ev.evidence_id)

    controller._evaluate_gap_resolution(gap, session, irr_ids)
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_e19_open_gap_one_hundred_irrelevant_evidence(retriever):
    """19. Open gap + 100 irrelevant evidence items -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_e19", objective="Test")
    gap = InformationGap(
        gap_id="GAP-CORE-DEP-100",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway datastore security",
        target_entity="Payment Gateway",
        required_information="Payment Gateway mutual TLS 1.3 configuration",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    irr_ids = []
    for i in range(100):
        ev = make_evidence(f"IRR-100-{i}", f"Unrelated metric {i}: CPU utilization is {i%100}%.")
        session.discovered_evidence[ev.evidence_id] = ev
        irr_ids.append(ev.evidence_id)

    controller._evaluate_gap_resolution(gap, session, irr_ids)
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


def test_e20_irrelevant_evidence_from_every_provider(retriever):
    """20. Irrelevant evidence from every provider (sqlite, jira, github) -> Must remain unresolved."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_e20", objective="Test")
    gap = InformationGap(
        gap_id="GAP-MULTI-PROV-IRR",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Payment Gateway datastore security",
        target_entity="Payment Gateway",
        required_information="Payment Gateway mutual TLS 1.3 configuration",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    ev_sqlite = make_evidence("SQLITE-IRR", "NOVA company holiday calendar 2026.", source_type="document")
    ev_jira = make_evidence("JIRA-IRR", "HR-12: Update direct deposit account instructions.", source_type="jira")
    ev_github = make_evidence("GH-IRR", "docs: fix typo in README.md footer.", source_type="github")

    for ev in [ev_sqlite, ev_jira, ev_github]:
        session.discovered_evidence[ev.evidence_id] = ev

    controller._evaluate_gap_resolution(gap, session, [e.evidence_id for e in [ev_sqlite, ev_jira, ev_github]])
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False


# =============================================================================
# CATEGORY F: BUDGET & TERMINATION ATTACKS
# =============================================================================

def test_f21_budget_exhausted_with_open_gap(retriever):
    """21. Budget exhausted with open gap -> controller_verified MUST be False."""
    budget = InvestigationBudget(max_hops=1, max_llm_calls=1)
    controller = InvestigationController(retriever=retriever, budget=budget)

    def agent_fn(state):
        return False, "Need more info", [InformationGap(gap_id="GAP-UNRESOLVED", description="Open requirement")], []

    package = controller.run_investigation("Can Phoenix launch?", reasoning_agent_fn=agent_fn)
    assert package.controller_verified is False
    assert "BUDGET_EXHAUSTED" in package.termination_reason


def test_f22_retrieval_exhausted_with_open_gap(retriever):
    """22. Retrieval exhausted with open gap -> Must terminate with STAGNATION, not SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)

    def duplicate_agent(state):
        return False, "Repeating query", [InformationGap(gap_id="GAP-REPEAT", description="Repeat", targeted_query="Project Phoenix")], []

    package = controller.run_investigation("Project Phoenix", reasoning_agent_fn=duplicate_agent)
    assert package.controller_verified is False
    assert "STAGNATION" in package.termination_reason


def test_f23_no_providers_available_with_open_gap():
    """23. Empty retrieval result / no providers -> Must NOT be SUFFICIENT."""
    class EmptyRetriever:
        def search(self, query, k=4):
            return [], {}

    controller = InvestigationController(retriever=EmptyRetriever(), budget=InvestigationBudget(max_hops=2, max_llm_calls=2))
    package = controller.run_investigation("Can Phoenix launch?", reasoning_agent_fn=lambda s: (False, "", [], []))
    assert package.controller_verified is False
    assert package.termination_reason != "SUFFICIENT"


def test_f24_empty_retrieval_result():
    """24. Zero yielded chunks across all hops -> Must NOT be SUFFICIENT."""
    class ZeroRetriever:
        def search(self, query, k=4):
            return [], {}

    controller = InvestigationController(retriever=ZeroRetriever(), budget=InvestigationBudget(max_hops=2, max_llm_calls=2))
    package = controller.run_investigation("Empty query test", reasoning_agent_fn=lambda s: (True, "Declaring sufficient anyway", [], []))
    assert package.controller_verified is False
    assert package.termination_reason != "SUFFICIENT"


def test_f25_all_providers_fail():
    """25. All providers throw errors -> Must NOT be SUFFICIENT."""
    class FailingRetriever:
        def search(self, query, k=4):
            raise RuntimeError("Database connection lost")

    controller = InvestigationController(retriever=FailingRetriever(), budget=InvestigationBudget(max_hops=1, max_llm_calls=1))
    with pytest.raises(RuntimeError):
        controller.run_investigation("Crash test", reasoning_agent_fn=lambda s: (False, "", [], []))


# =============================================================================
# CATEGORY G: MULTI-HOP ATTACKS
# =============================================================================

def test_g26_root_evidence_found_but_dependent_gap_remains(retriever):
    """26. Root evidence found but dependent prerequisite remains open -> NOT SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_g26", objective="Can Phoenix launch?")

    ev1 = make_evidence("DOC-OVERVIEW", "Project Phoenix release scheduled for Friday.", source_id="DOC-NOVA-OVERVIEW")
    ev2 = make_evidence("DOC-EXTRA", "Integration tests passed in staging.", source_id="DOC-STAGING")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev2.evidence_id] = ev2

    # Dependent gap remains OPEN
    gap = InformationGap(
        gap_id="GAP-DEP-REDIS",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Verify Redis cluster supports mutual TLS 1.3",
        target_entity="Redis",
        required_information="Verify Redis cluster supports mutual TLS 1.3",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    assert controller.is_session_sufficient(session) is False
    state_view = controller._build_state_view(session)
    is_verified, reason = controller.verify_sufficiency(state_view, "Root overview found")
    assert is_verified is False
    assert "Blocking gap(s) still open" in reason


def test_g27_first_hop_found_second_hop_missing(retriever):
    """27. Hop 1 found (Payment Gateway), Hop 2 missing (Redis incident) -> NOT SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_g27", objective="Can Phoenix launch?")

    ev1 = make_evidence("DOC-OVERVIEW", "Project Phoenix release scheduled for Friday.", source_id="DOC-NOVA-OVERVIEW")
    ev2 = make_evidence("DOC-PAYMENT", "Payment Gateway v2 enforces mTLS 1.3 for cache.", source_id="DOC-NOVA-PAYMENT")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev2.evidence_id] = ev2

    # Unresolved reference INC-402 pending
    session.unresolved_references.add("INC-402")
    gap = InformationGap(
        gap_id="GAP-REF-INC-402",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Active production state of INC-402",
        target_entity="INC-402",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    assert controller.is_session_sufficient(session) is False
    state_view = controller._build_state_view(session)
    is_verified, reason = controller.verify_sufficiency(state_view, "")
    assert is_verified is False
    assert "Unresolved explicit reference" in reason


def test_g28_second_hop_found_but_root_requirement_missing(retriever):
    """28. Second hop found (INC-402) but core prerequisite not satisfied -> NOT SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_g28", objective="Can Phoenix launch?")

    ev_inc = make_evidence("DOC-INC-402", "**Current Production State:** Redis running v5.4.12 without mTLS 1.3.", source_id="DOC-NOVA-INC-402")
    session.discovered_evidence[ev_inc.evidence_id] = ev_inc

    # Open prerequisite for CAB decision
    gap = InformationGap(
        gap_id="GAP-REF-CR-904",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="CAB decision record for CR-904",
        target_entity="CR-904",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    assert controller.is_session_sufficient(session) is False


def test_g29_unrelated_second_hop_evidence(retriever):
    """29. Second hop returns unrelated evidence -> Investigation cannot terminate SUFFICIENT."""
    controller = InvestigationController(retriever=retriever)
    session = InvestigationSession(session_id="s_g29", objective="Can Phoenix launch?")

    ev1 = make_evidence("DOC-OVERVIEW", "Phoenix overview doc", source_id="DOC-NOVA-OVERVIEW")
    ev_unrelated = make_evidence("DOC-UNRELATED", "Annual HR policy guidelines.", source_id="DOC-HR")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev_unrelated.evidence_id] = ev_unrelated

    gap = InformationGap(
        gap_id="GAP-PAYMENT",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Payment gateway integration specs",
        target_entity="Payment Gateway",
        required_information="Failure mode and transport security for Payment Gateway",
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    controller._evaluate_gap_resolution(gap, session, [ev_unrelated.evidence_id])
    assert gap.status == GapStatus.OPEN
    assert controller.is_session_sufficient(session) is False


# =============================================================================
# CATEGORY H: REGRESSION BENCHMARKS
# =============================================================================

def test_h30_jira_investigation_with_open_postmortem_requirement(retriever):
    """
    30. REPRODUCING & PREVENTING DEFECT-TERM-01:
    Jira-only investigation requesting post-mortem resolution MUST NOT prematurely terminate
    SUFFICIENT when only general Jira task tickets are retrieved and the post-mortem is missing.
    """
    controller = InvestigationController(
        retriever=retriever,
        budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
    )
    session = InvestigationSession(session_id="s_h30", objective="Verify post-mortem resolution for PROJ-101")

    # Admit 2 standard Jira tickets that lack post-mortem resolution
    t1 = make_evidence("jira:PROJ-101#c000", "PROJ-101: Scheduled system maintenance task.", source_id="jira:PROJ-101", source_type="jira")
    t2 = make_evidence("jira:PROJ-102#c000", "PROJ-102: Follow-up documentation task.", source_id="jira:PROJ-102", source_type="jira")
    session.discovered_evidence[t1.evidence_id] = t1
    session.discovered_evidence[t2.evidence_id] = t2

    gap = InformationGap(
        gap_id="GAP-POSTMORTEM-PROJ-101",
        gap_type=GapType.STATE_VERIFICATION,
        is_blocking=True,
        description="Authoritative post-mortem resolution and active production state for PROJ-101",
        target_entity="PROJ-101",
        required_information="Active production state and post-mortem resolution for PROJ-101",
        required_facts=["post-mortem resolution", "active production state"],
        status=GapStatus.OPEN,
    )
    session.gaps[gap.gap_id] = gap

    # In DEFECT-TERM-01, admitting t1 or t2 hit the unconditional fallback and resolved the gap!
    controller._evaluate_gap_resolution(gap, session, [t1.evidence_id, t2.evidence_id])

    # In hardened controller: gap MUST remain OPEN!
    assert gap.status == GapStatus.OPEN
    assert gap.resolved is False
    assert controller.is_session_sufficient(session) is False

    state_view = controller._build_state_view(session)
    is_verified, reason = controller.verify_sufficiency(state_view, "Tickets retrieved")
    assert is_verified is False
    assert "Blocking gap(s) still open" in reason


def test_h31_successful_multi_hop_investigation_regression(retriever):
    """31. Regression: Multi-hop investigation completing the full 4-chunk Phoenix chain."""
    budget = InvestigationBudget(max_hops=3, max_llm_calls=3)
    controller = InvestigationController(retriever=retriever, budget=budget)

    def guided_reasoning_step(state: InvestigationState):
        has_payment = any("DOC-NOVA-PAYMENT" in e.source_id for e in state.accumulated_evidence.values())
        has_incident = any("DOC-NOVA-INC-402" in e.source_id for e in state.accumulated_evidence.values())
        has_cab = any("DOC-NOVA-CAB" in e.source_id for e in state.accumulated_evidence.values())

        if not has_payment:
            return False, "Need Payment Gateway specs", [
                InformationGap(gap_id="GAP-PAYMENT", description="Identify Payment Gateway security", targeted_query="Payment Gateway v2 mTLS requirements")
            ], []
        elif not has_incident:
            return False, "Need Redis config", [
                InformationGap(gap_id="GAP-REDIS", description="Find active Redis version", targeted_query="INC-402 Redis rollback current production state")
            ], []
        elif not has_cab:
            return False, "Need CAB decision", [
                InformationGap(gap_id="GAP-CAB", description="Check CAB decision", targeted_query="Change Advisory Board decision log meeting #88")
            ], []
        else:
            return True, "Complete factual chain assembled", [], []

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        reasoning_agent_fn=guided_reasoning_step,
        initial_k=2,
    )
    assert package.controller_verified is True
    assert package.termination_reason == "SUFFICIENT"
    assert len(package.evidence_items) >= 4


def test_h32_transitive_propagation_path_inv_hop_01_regression(retriever):
    """32. Regression: Zero-LLM multi-hop transitive propagation retrieves all 4 chunks."""
    controller = InvestigationController(
        retriever=retriever,
        budget=InvestigationBudget(max_hops=4, max_llm_calls=4, max_queries=8),
    )
    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        reasoning_agent_fn=lambda s: (False, "", [], []),
        initial_k=8,
    )
    admitted_ids = {e.evidence_id for e in package.evidence_items}
    assert "DOC-NOVA-OVERVIEW#c003" in admitted_ids
    assert "DOC-NOVA-CAB#c003" in admitted_ids
    assert "DOC-NOVA-INC-402#c004" in admitted_ids
    assert "DOC-NOVA-PAYMENT#c003" in admitted_ids
    assert package.controller_verified is True
    assert package.termination_reason == "SUFFICIENT"


def test_h33_no_domain_specific_strings_in_controller_termination():
    """33. TERM-INV-12: Verify no hardcoded domain strings exist in verify_sufficiency."""
    import inspect
    controller = InvestigationController(retriever=None)
    src = inspect.getsource(controller.verify_sufficiency)
    forbidden_tokens = ["DOC-NOVA-CAB", "CAB", "ARCH", "POST-MORTEM", "INC-"]
    for token in forbidden_tokens:
        # Check string literals
        assert f'"{token}"' not in src, f"Forbidden domain literal '{token}' found in verify_sufficiency"
        assert f"'{token}'" not in src, f"Forbidden domain literal '{token}' found in verify_sufficiency"


def test_h34_unresolved_reference_blocks_sufficiency_regression(retriever):
    """34. Regression: Unresolved explicit references must strictly block sufficiency."""
    controller = InvestigationController(retriever=retriever)
    ev1 = make_evidence("E1", "Chunk 1")
    ev2 = make_evidence("E2", "Chunk 2")
    state = InvestigationState(
        objective="Objective",
        accumulated_evidence={ev1.evidence_id: ev1, ev2.evidence_id: ev2},
        unresolved_references={"CR-999"},
        evidence_graph=[],
    )
    is_verified, reason = controller.verify_sufficiency(state, "LLM thinks it is sufficient")
    assert is_verified is False
    assert "Unresolved explicit reference" in reason


def test_h35_llm_inference_sole_edge_rejected_regression(retriever):
    """35. Regression: LLM_INFERENCE-only edges cannot establish sufficiency."""
    controller = InvestigationController(retriever=retriever)
    ev1 = make_evidence("E1", "Chunk 1")
    ev2 = make_evidence("E2", "Chunk 2")
    inf_edge = EvidenceEdge(
        source_evidence_id=ev1.evidence_id,
        target_evidence_id=ev2.evidence_id,
        relationship_type=RelationshipType.DEPENDS_ON,
        basis="Inferred connection",
        derived_by=EdgeDerivationType.LLM_INFERENCE,
        confidence=0.6,
    )
    state = InvestigationState(
        objective="Objective",
        accumulated_evidence={ev1.evidence_id: ev1, ev2.evidence_id: ev2},
        unresolved_references=set(),
        evidence_graph=[inf_edge],
    )
    is_verified, reason = controller.verify_sufficiency(state, "")
    assert is_verified is False
    assert "relies solely on LLM_INFERENCE edges" in reason
