"""
Unit Tests for Brick 3.4 Adversarial Evaluation Suite (25 Attack Vectors)
"""

import pytest
from experiments.run_brick34_adversarial_evaluation import AdversarialEvaluationHarness


@pytest.fixture(scope="module")
def harness_runner():
    harness = AdversarialEvaluationHarness()
    harness.run_all()
    # Map results by test_id
    return {r["test_id"]: r for r in harness.results}


VALID_SUBSYSTEMS = {
    "controller",
    "state machine",
    "planner",
    "retrieval/action validation",
    "evidence evaluation",
    "contradiction handling",
    "termination",
    "provenance",
    "LLM boundary",
    "evaluation harness",
}


def _assert_scenario(runner, test_id: int):
    result = runner.get(test_id)
    assert result is not None, f"Scenario {test_id} not executed"
    assert "actual_behavior" in result and result["actual_behavior"], f"Scenario {test_id} missing actual_behavior"
    assert result["subsystem"] in VALID_SUBSYSTEMS, f"Scenario {test_id} invalid subsystem: {result['subsystem']}"
    assert result["severity_if_failed"] in {"P0", "P1", "P2", "P3", "P4"}, f"Scenario {test_id} invalid severity"
    if not result["passed"]:
        assert result["root_cause"] is not None and len(result["root_cause"]) > 10, f"Failed scenario {test_id} missing root cause"


def test_adv_01_branching_explosion(harness_runner):
    _assert_scenario(harness_runner, 1)

def test_adv_02_large_amounts_irrelevant_evidence(harness_runner):
    _assert_scenario(harness_runner, 2)

def test_adv_03_multiple_layers_contradictory_evidence(harness_runner):
    _assert_scenario(harness_runner, 3)

def test_adv_04_contradiction_chains(harness_runner):
    _assert_scenario(harness_runner, 4)

def test_adv_05_resolution_invalidation(harness_runner):
    _assert_scenario(harness_runner, 5)

def test_adv_06_reopened_gaps_stability(harness_runner):
    _assert_scenario(harness_runner, 6)

def test_adv_07_impossible_to_resolve_gaps(harness_runner):
    _assert_scenario(harness_runner, 7)

def test_adv_08_missing_evidence(harness_runner):
    _assert_scenario(harness_runner, 8)

def test_adv_09_empty_retrieval_results(harness_runner):
    _assert_scenario(harness_runner, 9)

def test_adv_10_repeated_near_repeated_queries(harness_runner):
    _assert_scenario(harness_runner, 10)

def test_adv_11_investigation_loops(harness_runner):
    _assert_scenario(harness_runner, 11)

def test_adv_12_query_variations_evading_dedup(harness_runner):
    _assert_scenario(harness_runner, 12)

def test_adv_13_disguised_objective_echoing(harness_runner):
    _assert_scenario(harness_runner, 13)

def test_adv_14_premature_llm_sufficiency_proposals(harness_runner):
    _assert_scenario(harness_runner, 14)

def test_adv_15_llm_attempts_bypass_controller_authority(harness_runner):
    _assert_scenario(harness_runner, 15)

def test_adv_16_unsupported_claims(harness_runner):
    _assert_scenario(harness_runner, 16)

def test_adv_17_evidence_attached_to_incorrect_gaps(harness_runner):
    _assert_scenario(harness_runner, 17)

def test_adv_18_conflicting_provenance(harness_runner):
    _assert_scenario(harness_runner, 18)

def test_adv_19_ambiguous_user_questions(harness_runner):
    _assert_scenario(harness_runner, 19)

def test_adv_20_multiple_defensible_conclusions(harness_runner):
    _assert_scenario(harness_runner, 20)

def test_adv_21_very_deep_investigations(harness_runner):
    _assert_scenario(harness_runner, 21)

def test_adv_22_many_simultaneous_gaps(harness_runner):
    _assert_scenario(harness_runner, 22)

def test_adv_23_non_blocking_gaps_overwhelming_blocking(harness_runner):
    _assert_scenario(harness_runner, 23)

def test_adv_24_late_breaking_contradictions(harness_runner):
    _assert_scenario(harness_runner, 24)

def test_adv_25_unprovable_requested_conclusion(harness_runner):
    _assert_scenario(harness_runner, 25)
