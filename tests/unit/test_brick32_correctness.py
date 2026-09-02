"""
Unit Tests for ORACLE Brick 3.2 Correctness Fixes:
  - P1: Dependency-directed investigation prompting
  - P2: Jaccard semantic similarity duplicate query rejection
  - P3: Zero-yield query tracking and failure feedback
  - P4: Proposal vs authoritative resolution distinction (CR-904 & INC-402)
  - First-class InvestigationGap lifecycle tracking
"""

import pytest
from pathlib import Path

from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.entity_scanner import EntityScanner
from backend.investigation.engine import InvestigationEngine
from backend.investigation.models import (
    InvestigationBudget,
    InvestigationGap,
    InvestigationState,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"


@pytest.fixture
def parser():
    return MarkdownEvidenceParser()


@pytest.fixture
def scanner():
    return EntityScanner()


@pytest.fixture
def empty_retriever():
    return SQLiteFTS5Retriever(":memory:")


def test_p4_proposal_vs_authoritative_resolution(parser, scanner):
    """
    P4 AUDIT TEST:
    Verifies that discovering a ticket proposal (CR-904 in CAB#c002) leaves it UNRESOLVED,
    and only ingesting the authoritative decision record (CAB#c003) marks it resolved.
    Also verifies that citing INC-402 (CAB#c004) leaves INC-402 UNRESOLVED until the incident post-mortem is ingested.
    """
    cab_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-CAB.md")
    cab_proposal = cab_chunks[2]   # DOC-NOVA-CAB#c002 (Marcus Vance proposal)
    cab_decision = cab_chunks[3]   # DOC-NOVA-CAB#c003 (CAB Decision: REJECTED)
    cab_rationale = cab_chunks[4]  # DOC-NOVA-CAB#c004 (Cites INC-402)

    # Step 1: Ingest only the proposal chunk
    state_proposal_only = {cab_proposal.evidence_id: cab_proposal}
    unresolved_1 = scanner.find_unresolved_references(state_proposal_only)

    assert "CR-904" in unresolved_1, (
        "CR-904 must remain UNRESOLVED when only proposal evidence (c002) is present!"
    )

    # Step 2: Now add the authoritative decision chunk (c003) and rationale (c004)
    state_with_decision = {
        cab_proposal.evidence_id: cab_proposal,
        cab_decision.evidence_id: cab_decision,
        cab_rationale.evidence_id: cab_rationale,
    }
    unresolved_2 = scanner.find_unresolved_references(state_with_decision)

    # CR-904 must now be resolved
    assert "CR-904" not in unresolved_2, (
        "CR-904 must be marked RESOLVED once decision record (c003) is ingested!"
    )
    # But c004 introduces INC-402, which must now be UNRESOLVED!
    assert "INC-402" in unresolved_2, (
        "INC-402 cited in decision record must now be flagged as UNRESOLVED!"
    )

    # Step 3: Now ingest INC-402 post-mortem chunk (c004)
    inc_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-INC-402.md")
    state_with_inc = dict(state_with_decision)
    state_with_inc[inc_chunks[4].evidence_id] = inc_chunks[4]
    unresolved_3 = scanner.find_unresolved_references(state_with_inc)

    assert "INC-402" not in unresolved_3, (
        "INC-402 must be marked RESOLVED once authoritative post-mortem chunk is ingested!"
    )


def test_p2_jaccard_duplicate_query_rejection(empty_retriever):
    """
    P2 AUDIT TEST:
    Verifies that minor syntactic variations of previously executed queries
    are detected via Jaccard token overlap and rejected before execution.
    """
    controller = InvestigationController(retriever=empty_retriever, query_similarity_threshold=0.70)
    executed_queries = {
        "can project phoenix safely launch on october 24 at 09:00 utc",
        "redis v7.2 deployment status",
    }

    # Query differing only by a preposition ('on' omitted)
    near_duplicate = "can project phoenix safely launch october 24 at 09:00 utc"
    is_dup, reason = controller.is_duplicate_or_overlapping_query(near_duplicate, executed_queries)
    assert is_dup is True
    assert "High Jaccard semantic token overlap" in reason or "Exact match" in reason

    # Truly distinct query targeting an operational subsystem
    distinct_query = "payment gateway mtls certificate configuration"
    is_dup_distinct, _ = controller.is_duplicate_or_overlapping_query(distinct_query, executed_queries)
    assert is_dup_distinct is False


def test_p3_zero_yield_query_tracking(parser):
    """
    P3 AUDIT TEST:
    Verifies that queries returning 0 new chunks are recorded in zero_yield_queries
    and documented as failed in the investigation trace.
    """
    overview_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-OVERVIEW.md")
    retriever = SQLiteFTS5Retriever(":memory:")
    retriever.index_evidence(overview_chunks)

    budget = InvestigationBudget(max_hops=2, max_llm_calls=2)
    controller = InvestigationController(retriever=retriever, budget=budget)

    def zero_yield_agent(state: InvestigationState):
        return (
            False,
            "",
            [
                InvestigationGap(
                    gap_id="GAP-NONEXISTENT",
                    priority=1,
                    description="Searching for term not in index",
                    targeted_query="unmatched term query that returns zero hits",
                )
            ],
            [],
        )

    package = controller.run_investigation(
        objective="Project Phoenix overview",
        reasoning_agent_fn=zero_yield_agent,
    )

    # Must be recorded in budget summary and state
    assert package.budget_summary["zero_yield_queries_count"] >= 1
    # Trace must document the actionable gap execution with is_zero_yield=True
    gap_events = [e for e in package.investigation_trace if e.event_type == "ACTIONABLE_GAP_EXECUTED"]
    assert len(gap_events) > 0
    assert gap_events[0].details["is_zero_yield"] is True


def test_first_class_investigation_gap_lifecycle(parser):
    """
    INVESTIGATION GAP TEST:
    Verifies that InvestigationGap tracks originating evidence IDs, attempted queries,
    resolution status, and resolution evidence IDs.
    """
    all_chunks = parser.parse_file(CORPUS_DIR / "DOC-NOVA-CAB.md")
    retriever = SQLiteFTS5Retriever(":memory:")
    retriever.index_evidence(all_chunks)

    budget = InvestigationBudget(max_hops=2, max_llm_calls=2)
    controller = InvestigationController(retriever=retriever, budget=budget)

    def gap_agent(state: InvestigationState):
        return (
            False,
            "",
            [
                InvestigationGap(
                    gap_id="GAP-CAB-DECISION",
                    priority=1,
                    description="Find CAB Meeting #88 decision record",
                    targeted_query="Meeting #88 Decision Record CR-904",
                    originating_evidence_ids=list(state.accumulated_evidence.keys()),
                )
            ],
            [],
        )

    package = controller.run_investigation(
        objective="Change Request Log",
        reasoning_agent_fn=gap_agent,
    )

    resolved_gaps = [g for g in package.gaps if g.gap_id == "GAP-CAB-DECISION"]
    assert len(resolved_gaps) == 1
    gap = resolved_gaps[0]
    assert gap.resolution_status is True
    assert len(gap.attempted_queries) >= 1
    assert "Meeting #88 Decision Record CR-904" in gap.attempted_queries
    assert len(gap.resolution_evidence_ids) > 0


def test_p1_dependency_directed_prompt_structure():
    """
    P1 AUDIT TEST:
    Verifies that _build_compact_prompt explicitly warns against restating the objective
    and includes failed zero-yield queries.
    """
    state = InvestigationState(
        objective="Can Project Phoenix safely launch Friday?",
        accumulated_evidence={},
        zero_yield_queries={"can project phoenix safely launch on friday"},
        unresolved_references={"CR-904"},
        executed_queries={"can project phoenix safely launch friday"},
    )
    retriever = SQLiteFTS5Retriever(":memory:")
    from backend.inference.mock_provider import MockProvider
    engine = InvestigationEngine(retriever=retriever, llm_provider=MockProvider())

    prompt = engine._build_compact_prompt(state)

    assert "DO NOT restate or paraphrase the overall objective" in prompt
    assert "CRITICAL INVESTIGATION DIRECTIVES (P1)" in prompt
    assert "FAILED QUERIES (RETURNED 0 RESULTS - DO NOT RETRY OR PARAPHRASE)" in prompt
    assert "can project phoenix safely launch on friday" in prompt
    assert "CR-904" in prompt
