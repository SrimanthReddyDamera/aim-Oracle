"""
Unit Tests for Brick 3.7: Adaptive Retrieval Policy & Telemetry
Verifies:
  1. flat-tail expansion
  2. min-score rejection
  3. source-monopolization expansion
  4. reference-affinity expansion
  5. no-expansion case (stable window)
  6. multiple triggers firing simultaneously
  7. maximum expansion limit
  8. configuration overrides
  9. deterministic decisions & telemetry verification
"""

import pytest
from backend.evidence.models import Evidence
from backend.investigation.controller import InvestigationController
from backend.investigation.models import AdaptiveRetrievalConfig, RetrievalDecisionTelemetry
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever


def make_dummy_chunk(eid: str, source_id: str, content: str = "some content") -> Evidence:
    return Evidence(
        evidence_id=eid,
        source_id=source_id,
        content=content,
        content_hash=f"hash_{eid}",
        source_path=f"docs/{source_id}.md",
        chunk_index=0,
        start_offset=0,
        end_offset=len(content),
        created_at="2026-09-03T12:00:00Z",
        metadata={"section": "Test"},
    )


@pytest.fixture
def mock_controller():
    retriever = SQLiteFTS5Retriever(":memory:")
    cfg = AdaptiveRetrievalConfig(
        initial_k=8,
        expansion_k=10,
        decay_threshold=0.50,
        min_score=2.40,
        source_concentration_threshold=0.625,
        max_expansions=1,
    )
    return InvestigationController(retriever=retriever, adaptive_retrieval_config=cfg)


def test_flat_tail_expansion(mock_controller):
    """Fires when decay_ratio >= 0.50 and rank_8_score >= 2.40."""
    custom_scores = [10.0, 8.0, 6.0, 5.0, 4.5, 4.0, 3.5, 3.0, 2.5, 2.0]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", f"SRC_{i}"), custom_scores[i])
        for i in range(10)
    ]
    # Rank 4 (idx 3) = 5.0, Rank 8 (idx 7) = 3.0 -> ratio = 0.60, score = 3.0 >= 2.40

    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references=set(),
        expansion_count=0,
    )

    assert should_expand is True
    assert telemetry.expanded is True
    assert telemetry.final_k == 10
    assert any("FLAT_TAIL" in t for t in telemetry.expansion_triggers)
    assert telemetry.decay_ratio == 0.60
    assert telemetry.rank_8_score == 3.0


def test_min_score_rejection(mock_controller):
    """Rejects expansion if decay_ratio is high (e.g. 0.80) but score is below min_score (e.g. 1.6 < 2.40)."""
    custom_scores = [2.5, 2.3, 2.1, 2.0, 1.9, 1.8, 1.7, 1.6, 1.5, 1.4]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", f"SRC_{i}"), custom_scores[i])
        for i in range(10)
    ]
    # Rank 4 (idx 3) = 2.0, Rank 8 (idx 7) = 1.6 -> ratio = 1.6/2.0 = 0.80 >= 0.50, BUT score 1.6 < 2.40!

    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references=set(),
        expansion_count=0,
    )

    assert should_expand is False
    assert telemetry.expanded is False
    assert telemetry.final_k == 8
    assert not any("FLAT_TAIL" in t for t in telemetry.expansion_triggers)


def test_source_monopolization_expansion(mock_controller):
    """Fires when >= 62.5% of top-8 chunks originate from the same source_id."""
    # Steep decay so flat tail does not fire: Rank 4 = 10.0, Rank 8 = 2.0 -> ratio = 0.20
    custom_scores = [20.0, 18.0, 15.0, 10.0, 8.0, 6.0, 4.0, 2.0, 1.5, 1.0]
    # 6 out of 8 chunks from SRC_MONOPOLY -> 6/8 = 75% >= 62.5%
    sources = ["SRC_MONOPOLY"] * 6 + ["SRC_A", "SRC_B", "SRC_C", "SRC_D"]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", sources[i]), custom_scores[i])
        for i in range(10)
    ]

    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references=set(),
        expansion_count=0,
    )

    assert should_expand is True
    assert telemetry.expanded is True
    assert telemetry.final_k == 10
    assert any("SOURCE_MONOPOLIZATION" in t for t in telemetry.expansion_triggers)
    assert telemetry.source_concentration == 0.75


def test_reference_affinity_expansion(mock_controller):
    """Fires when ranks 9-10 contain an exact unresolved reference token."""
    # Steep decay (ratio 0.20) and balanced sources
    custom_scores = [20.0, 18.0, 15.0, 10.0, 8.0, 6.0, 4.0, 2.0, 1.5, 1.0]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", f"SRC_{i}", f"Standard text {i}"), custom_scores[i])
        for i in range(10)
    ]
    # Inject unresolved reference into candidate rank 9 (index 8)
    candidate_pool[8] = (
        make_dummy_chunk("E8", "SRC_8", "This record resolves ticket TICKET-999 formally."),
        1.5,
    )

    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references={"TICKET-999"},
        expansion_count=0,
    )

    assert should_expand is True
    assert telemetry.expanded is True
    assert telemetry.final_k == 10
    assert telemetry.reference_affinity is True
    assert any("REFERENCE_AFFINITY" in t for t in telemetry.expansion_triggers)


def test_no_expansion_case(mock_controller):
    """Retains initial_k when decay is steep, score is low, sources are diverse, and no refs match."""
    custom_scores = [20.0, 15.0, 12.0, 10.0, 6.0, 4.0, 3.0, 2.0, 1.0, 0.5]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", f"SRC_{i}", "Normal text"), custom_scores[i])
        for i in range(10)
    ]

    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references={"UNMATCHED-REF"},
        expansion_count=0,
    )

    assert should_expand is False
    assert telemetry.expanded is False
    assert telemetry.final_k == 8
    assert len(telemetry.expansion_triggers) == 0


def test_multiple_triggers_simultaneous(mock_controller):
    """Aggregates all active triggers when multiple conditions fire simultaneously."""
    # Flat tail (ratio 0.60, score 3.0) + Source monopolization (6/8 = 75%) + Ref affinity
    custom_scores = [10.0, 8.0, 6.0, 5.0, 4.5, 4.0, 3.5, 3.0, 2.5, 2.0]
    sources = ["SRC_HEAVY"] * 6 + ["SRC_A", "SRC_B", "SRC_C", "SRC_D"]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", sources[i], "Content"), custom_scores[i])
        for i in range(10)
    ]
    candidate_pool[9] = (
        make_dummy_chunk("E9", "SRC_D", "Reference token CR-1234 details"),
        2.0,
    )

    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references={"CR-1234"},
        expansion_count=0,
    )

    assert should_expand is True
    assert telemetry.expanded is True
    assert len(telemetry.expansion_triggers) == 3
    assert any("FLAT_TAIL" in t for t in telemetry.expansion_triggers)
    assert any("SOURCE_MONOPOLIZATION" in t for t in telemetry.expansion_triggers)
    assert any("REFERENCE_AFFINITY" in t for t in telemetry.expansion_triggers)


def test_maximum_expansion_limit(mock_controller):
    """Blocks expansion if expansion_count >= max_expansions."""
    custom_scores = [10.0, 8.0, 6.0, 5.0, 4.5, 4.0, 3.5, 3.0, 2.5, 2.0]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", f"SRC_{i}"), custom_scores[i])
        for i in range(10)
    ]

    # expansion_count = 1 >= max_expansions (1)
    should_expand, telemetry = mock_controller.evaluate_adaptive_expansion(
        candidate_pool=candidate_pool,
        unresolved_references=set(),
        expansion_count=1,
    )

    assert should_expand is False
    assert telemetry.expanded is False
    assert telemetry.final_k == 8
    # Triggers are still logged in telemetry for observability
    assert any("FLAT_TAIL" in t for t in telemetry.expansion_triggers)


def test_configuration_overrides():
    """Verifies that custom thresholds and configurations are strictly honored."""
    custom_cfg = AdaptiveRetrievalConfig(
        initial_k=6,
        expansion_k=8,
        decay_threshold=0.80,
        min_score=5.0,
        source_concentration_threshold=0.50,
        max_expansions=2,
    )
    retriever = SQLiteFTS5Retriever(":memory:")
    ctrl = InvestigationController(retriever=retriever, adaptive_retrieval_config=custom_cfg)

    assert ctrl.adaptive_config.initial_k == 6
    assert ctrl.adaptive_config.expansion_k == 8
    assert ctrl.adaptive_config.decay_threshold == 0.80
    assert ctrl.adaptive_config.min_score == 5.0
    assert ctrl.adaptive_config.source_concentration_threshold == 0.50
    assert ctrl.adaptive_config.max_expansions == 2


def test_deterministic_reproducibility(mock_controller):
    """Verifies that calling evaluate_adaptive_expansion repeatedly produces identical outputs."""
    custom_scores = [10.0, 8.0, 6.0, 5.0, 4.5, 4.0, 3.5, 3.0, 2.5, 2.0]
    candidate_pool = [
        (make_dummy_chunk(f"E{i}", f"SRC_{i}"), custom_scores[i])
        for i in range(10)
    ]

    res1, telem1 = mock_controller.evaluate_adaptive_expansion(candidate_pool, {"REF-1"}, 0)
    res2, telem2 = mock_controller.evaluate_adaptive_expansion(candidate_pool, {"REF-1"}, 0)

    assert res1 == res2
    assert telem1.model_dump() == telem2.model_dump()
