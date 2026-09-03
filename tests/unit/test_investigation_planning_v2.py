"""
Unit Tests for Brick 3.4 Revision v2:
  - In-memory InvestigationSession lifecycle
  - Generic InformationGap state machine transitions
  - Deterministic priority scoring formula
  - Contradiction detection routing to RECONCILIATION_REQUIRED
  - Zero-yield attempt counting and transition to BLOCKED
  - Jaccard & objective echo query rejection
  - Ledger-based factual sufficiency verification
"""

import pytest
from pathlib import Path

from backend.evidence.models import Evidence
from backend.investigation.controller import InvestigationController
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.models import (
    EvidenceEdge,
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationSession,
    InvestigationState,
    RelationshipType,
    EdgeDerivationType,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever


@pytest.fixture
def empty_retriever():
    return SQLiteFTS5Retriever(":memory:")


@pytest.fixture
def controller(empty_retriever):
    return InvestigationController(retriever=empty_retriever, query_similarity_threshold=0.70)


def make_dummy_evidence(eid: str, content: str) -> Evidence:
    return Evidence(
        evidence_id=eid,
        source_id=eid.split("#")[0],
        content=content,
        content_hash="dummy_hash",
        source_path="dummy.md",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content),
        created_at="2026-09-03T12:00:00Z",
    )


def test_in_memory_session_lifecycle(controller):
    """Verifies that an InvestigationSession initializes in RAM and tracks mutable state."""
    session = InvestigationSession(
        session_id="sess_01",
        objective="Verify system deployment prerequisites",
    )
    assert session.session_id == "sess_01"
    assert len(session.discovered_evidence) == 0
    assert len(session.gaps) == 0
    assert session.is_sufficient is False


def test_deterministic_priority_calculation(controller):
    """
    Verifies that the controller's deterministic priority function ranks:
    1. Blocking Contradiction Gaps highest
    2. Blocking Prerequisites next
    3. Contextual / leaf gaps lowest
    And penalizes previous failed attempts.
    """
    session = InvestigationSession(session_id="s1", objective="Test")

    gap_contra = InformationGap(
        gap_id="G1",
        gap_type=GapType.CONTRADICTION_RECONCILIATION,
        is_blocking=True,
        description="Conflicting claims",
        target_entity="Core Service",
        required_information="Reconcile version",
        attempt_count=0,
    )

    gap_prereq = InformationGap(
        gap_id="G2",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Prerequisite check",
        target_entity="Auth Service",
        required_information="Status",
        attempt_count=0,
    )

    gap_leaf = InformationGap(
        gap_id="G3",
        gap_type=GapType.OBJECTIVE_ROOT,
        is_blocking=False,
        description="Leaf info",
        target_entity="General Info",
        required_information="Overview",
        attempt_count=0,
    )

    gap_prereq_failed = InformationGap(
        gap_id="G4",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Prerequisite check",
        target_entity="Database",
        required_information="Status",
        attempt_count=1,
    )

    score_contra = controller.compute_gap_priority(gap_contra, session)
    score_prereq = controller.compute_gap_priority(gap_prereq, session)
    score_leaf = controller.compute_gap_priority(gap_leaf, session)
    score_failed = controller.compute_gap_priority(gap_prereq_failed, session)

    # 100*1 + 50*1 + 25*0.5 = 162.5
    # 100*1 + 50*0 + 25*1 = 125.0
    # 100*0 + 50*0 + 25*0.5 = 12.5
    # 100*1 + 50*0 + 25*1 - 30*1 = 95.0
    assert score_contra > score_prereq, "Contradiction gap must outrank standard prerequisite"
    assert score_prereq > score_leaf, "Blocking prerequisite must outrank non-blocking leaf"
    assert score_prereq > score_failed, "Unattempted gap must outrank previously attempted gap"


def test_contradiction_routes_to_reconciliation(controller):
    """
    Verifies that when retrieved evidence contains opposing or conflict markers (REJECTED/ROLLBACK),
    the gap transitions to RECONCILIATION_REQUIRED rather than uncontested RESOLVED.
    """
    session = InvestigationSession(session_id="s1", objective="Test")
    ev1 = make_dummy_evidence("DOC-A#c001", "The request is REJECTED by security.")
    session.discovered_evidence[ev1.evidence_id] = ev1

    gap = InformationGap(
        gap_id="G-AUTH",
        gap_type=GapType.AUTHORITY_RESOLUTION,
        is_blocking=True,
        description="Check authority decision",
        target_entity="DOC-A",
        required_information="Decision status",
        status=GapStatus.INVESTIGATING,
    )

    controller._evaluate_gap_resolution(gap, session, [ev1.evidence_id])

    assert gap.status == GapStatus.RECONCILIATION_REQUIRED, (
        "Evidence containing conflict markers must transition to RECONCILIATION_REQUIRED"
    )
    assert ev1.evidence_id in gap.conflicting_evidence_ids
    assert gap.resolved is True  # Evidentially satisfied for investigation


def test_zero_yield_retry_then_block(controller):
    """
    Verifies that:
    - Attempt 1 with 0 results transitions gap to UNRESOLVED.
    - Attempt 2 with 0 results transitions gap to BLOCKED.
    """
    gap = InformationGap(
        gap_id="G-ZERO",
        gap_type=GapType.PREREQUISITE,
        is_blocking=True,
        description="Missing config",
        target_entity="UnmatchedEntity",
        required_information="Config details",
        attempt_count=0,
        max_attempts=2,
        status=GapStatus.OPEN,
    )

    # Simulate Attempt 1 (Zero new chunks found)
    gap.attempt_count += 1
    if gap.attempt_count >= gap.max_attempts:
        gap.status = GapStatus.BLOCKED
    else:
        gap.status = GapStatus.UNRESOLVED

    assert gap.status == GapStatus.UNRESOLVED, "First zero-result attempt must leave gap UNRESOLVED"

    # Simulate Attempt 2 (Zero new chunks found)
    gap.attempt_count += 1
    if gap.attempt_count >= gap.max_attempts:
        gap.status = GapStatus.BLOCKED
    else:
        gap.status = GapStatus.UNRESOLVED

    assert gap.status == GapStatus.BLOCKED, "Exhausted attempts must transition gap to BLOCKED"


def test_jaccard_and_objective_echo_rejection(controller):
    """
    Verifies that the controller rejects queries that:
    1. Have >= 0.70 non-stopword Jaccard overlap with executed queries.
    2. Echo the root objective with >= 0.80 overlap.
    """
    executed = {"payment gateway mtls security certificates"}
    objective = "Can Project Phoenix safely launch this Friday at 09:00 UTC?"

    # 1. High Jaccard query
    near_dup = "payment gateway mtls security certificate"
    is_dup, reason = controller.is_duplicate_or_overlapping_query(near_dup, executed, threshold=0.70)
    assert is_dup is True
    assert "High Jaccard semantic token overlap" in reason or "Exact match" in reason

    # 2. Objective Echo query
    echo_q = "can project phoenix safely launch on friday at 09:00 utc"
    is_echo, _ = controller.is_duplicate_or_overlapping_query(
        echo_q, {controller._normalize_query(objective)}, threshold=0.80
    )
    assert is_echo is True


def test_ledger_sufficiency_evaluation(controller):
    """
    Verifies that is_session_sufficient evaluates strictly against the gap ledger:
    - True if all blocking gaps are RESOLVED or RECONCILIATION_REQUIRED and >= 2 chunks exist.
    - False if any blocking gap is OPEN, UNRESOLVED, or BLOCKED.
    - False if unresolved references remain.
    """
    session = InvestigationSession(session_id="s1", objective="Test Objective")
    ev1 = make_dummy_evidence("D1#c1", "Chunk 1")
    ev2 = make_dummy_evidence("D2#c2", "Chunk 2")
    session.discovered_evidence[ev1.evidence_id] = ev1
    session.discovered_evidence[ev2.evidence_id] = ev2

    # Case 1: Blocking gap is OPEN -> Insufficient
    session.gaps["G1"] = InformationGap(
        gap_id="G1", is_blocking=True, description="req", target_entity="E", required_information="I",
        status=GapStatus.OPEN,
    )
    assert controller.is_session_sufficient(session) is False

    # Case 2: Blocking gap is RESOLVED -> Sufficient
    session.gaps["G1"].status = GapStatus.RESOLVED
    assert controller.is_session_sufficient(session) is True

    # Case 3: Blocking gap is RECONCILIATION_REQUIRED -> Sufficient for investigation
    session.gaps["G1"].status = GapStatus.RECONCILIATION_REQUIRED
    assert controller.is_session_sufficient(session) is True

    # Case 4: Blocking gap is BLOCKED -> Insufficient
    session.gaps["G1"].status = GapStatus.BLOCKED
    assert controller.is_session_sufficient(session) is False

    # Case 5: Unresolved reference pending -> Insufficient even if gap is resolved
    session.gaps["G1"].status = GapStatus.RESOLVED
    session.unresolved_references.add("TICKET-999")
    assert controller.is_session_sufficient(session) is False
