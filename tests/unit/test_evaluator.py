"""
Unit Tests for Brick 3.3 Investigation Evaluator
Verifies deterministic set math, failure taxonomy classification,
premature termination detection, and unsupported claim safeguards.
Zero LLM calls.
"""

import pytest
from backend.evidence.models import Evidence
from backend.investigation.evaluator import FailureClass, InvestigationEvaluator
from backend.investigation.models import EvidencePackage, InvestigationEvent


@pytest.fixture
def evaluator():
    return InvestigationEvaluator()


def make_dummy_package(
    evidence_ids,
    controller_verified=False,
    termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
    hops=2,
    llm_calls=2,
    trace=None,
):
    items = [
        Evidence(
            evidence_id=eid,
            source_id=eid.split("#")[0],
            content=f"Content for {eid}",
            content_hash="abc",
            source_path="dummy.md",
            chunk_index=0,
            start_offset=0,
            end_offset=10,
            created_at="2026-09-02T12:00:00Z",
        )
        for eid in evidence_ids
    ]
    return EvidencePackage(
        objective="Test Objective",
        termination_reason=termination_reason,
        controller_verified=controller_verified,
        budget_summary={
            "hops_used": hops,
            "llm_calls_used": llm_calls,
            "queries_executed": 3,
            "zero_yield_queries_count": 0,
            "total_chunks_collected": len(items),
            "elapsed_wall_time_ms": 100.0,
        },
        evidence_items=items,
        graph_edges=[],
        gap_history=[],
        investigation_trace=trace or [],
        gaps=[],
    )


def test_evaluator_success_classification(evaluator):
    spec = {
        "scenario_id": "TEST-01",
        "archetype": "direct_investigation",
        "objective": "Test objective",
        "expected_answerable": True,
        "required_evidence_ids": ["DOC-NOVA-INC-402#c004"],
        "contradictory_evidence_ids": [],
        "distractor_evidence_ids": [],
    }
    package = make_dummy_package(
        evidence_ids=["DOC-NOVA-INC-402#c004", "DOC-NOVA-OVERVIEW#c000"],
        controller_verified=True,
        termination_reason="SUFFICIENT",
    )

    result = evaluator.evaluate_scenario(spec, package, elapsed_seconds=5.0, ram_rss_mb=42.0)
    assert result.failure_class == FailureClass.SUCCESS
    assert result.required_evidence_recall == 100.0
    assert result.successful_termination is True
    assert result.premature_termination is False
    assert result.unsupported_claim is False


def test_evaluator_detects_premature_controller_termination(evaluator):
    """If controller declares verified=True but ground-truth chunks are missing, flag CONTROLLER_FAILURE."""
    spec = {
        "scenario_id": "TEST-02",
        "archetype": "multi_hop_investigation",
        "objective": "Test objective",
        "expected_answerable": True,
        "required_evidence_ids": ["DOC-NOVA-INC-402#c004", "DOC-NOVA-PAYMENT#c003"],
        "contradictory_evidence_ids": [],
        "distractor_evidence_ids": [],
    }
    # Package only found INC-402, missing PAYMENT#c003, but controller falsely verified
    package = make_dummy_package(
        evidence_ids=["DOC-NOVA-INC-402#c004"],
        controller_verified=True,
        termination_reason="SUFFICIENT",
    )

    result = evaluator.evaluate_scenario(spec, package, elapsed_seconds=5.0, ram_rss_mb=42.0)
    assert result.failure_class == FailureClass.CONTROLLER_FAILURE
    assert result.required_evidence_recall == 50.0
    assert result.premature_termination is True
    assert result.unsupported_claim is True


def test_evaluator_unanswerable_question_handling(evaluator):
    """Unanswerable questions must terminate unverified without being marked as failures."""
    spec = {
        "scenario_id": "TEST-03",
        "archetype": "unanswerable_question",
        "objective": "Non-existent Kubernetes config",
        "expected_answerable": False,
        "required_evidence_ids": [],
        "contradictory_evidence_ids": [],
        "distractor_evidence_ids": ["DOC-NOVA-OVERVIEW#c000"],
    }
    package = make_dummy_package(
        evidence_ids=["DOC-NOVA-OVERVIEW#c000"],
        controller_verified=False,
        termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
    )

    result = evaluator.evaluate_scenario(spec, package, elapsed_seconds=8.0, ram_rss_mb=42.0)
    assert result.failure_class == FailureClass.INSUFFICIENT_CORPUS_CORRECT
    assert result.successful_termination is True
    assert result.premature_termination is False


def test_evaluator_detects_investigation_exhaustion(evaluator):
    """Answerable scenario that ran out of hops without reaching required evidence is an INVESTIGATION_FAILURE."""
    spec = {
        "scenario_id": "TEST-04",
        "archetype": "multi_hop_investigation",
        "objective": "Complex multi-hop",
        "expected_answerable": True,
        "required_evidence_ids": ["DOC-NOVA-CAB#c003", "DOC-NOVA-INC-402#c004"],
        "contradictory_evidence_ids": [],
        "distractor_evidence_ids": [],
    }
    package = make_dummy_package(
        evidence_ids=["DOC-NOVA-CAB#c002"],
        controller_verified=False,
        termination_reason="BUDGET_EXHAUSTED_MAX_HOPS",
    )

    result = evaluator.evaluate_scenario(spec, package, elapsed_seconds=29.0, ram_rss_mb=42.0)
    assert result.failure_class == FailureClass.INVESTIGATION_FAILURE
    assert result.required_evidence_recall == 0.0
    assert result.max_hop_termination is True
