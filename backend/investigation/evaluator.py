"""
ORACLE Brick 3.3: Deterministic Investigation Evaluation Harness
Evaluates autonomous investigation runs against explicit ground-truth expectations
without ANY LLM involvement (pure deterministic set math and contract auditing).

Failure Taxonomy:
  - SUCCESS: Investigation gathered complete evidence and terminated with verified sufficiency.
  - INSUFFICIENT_CORPUS_CORRECT: Unanswerable/insufficient question correctly terminated unverified.
  - RETRIEVAL_FAILURE: Targeted query failed to yield required chunk from retriever index.
  - INVESTIGATION_FAILURE: Search strategy exhausted hops without discovering required dependencies.
  - REASONING_FAILURE: LLM proposed premature sufficiency when requirements were incomplete.
  - CONTROLLER_FAILURE: Controller granted sufficiency without satisfying factual requirements.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from backend.investigation.models import EvidencePackage


class FailureClass(str, Enum):
    SUCCESS                     = "SUCCESS"
    INSUFFICIENT_CORPUS_CORRECT = "INSUFFICIENT_CORPUS_CORRECT"
    RETRIEVAL_FAILURE           = "RETRIEVAL_FAILURE"
    INVESTIGATION_FAILURE       = "INVESTIGATION_FAILURE"
    REASONING_FAILURE           = "REASONING_FAILURE"
    CONTROLLER_FAILURE          = "CONTROLLER_FAILURE"


class ScenarioEvaluationResult(BaseModel):
    scenario_id: str
    archetype: str
    objective: str
    expected_answerable: bool
    
    # Ground-truth evidence metrics
    required_evidence_recall: float
    required_evidence_found: List[str]
    required_evidence_missing: List[str]
    contradictory_evidence_discovered: Optional[float] = None
    contradictory_evidence_found: List[str] = Field(default_factory=list)
    irrelevant_evidence_ratio: float
    distractors_found: List[str] = Field(default_factory=list)
    
    # Controller contract metrics
    controller_verified: bool
    termination_reason: str
    successful_termination: bool
    premature_termination: bool
    unsupported_claim: bool
    max_hop_termination: bool
    stagnation_detected: bool
    
    # Resource metrics
    hops_used: int
    llm_calls_used: int
    queries_executed: int
    zero_yield_queries: int
    elapsed_seconds: float
    ram_rss_mb: float
    
    # Failure taxonomy
    failure_class: FailureClass
    failure_diagnosis: str


class InvestigationEvaluator:
    """
    100% Deterministic Evaluator for ORACLE investigations.
    Uses set operations and event trace audits. Zero LLM calls.
    """

    def evaluate_scenario(
        self,
        scenario_spec: Dict[str, Any],
        package: EvidencePackage,
        elapsed_seconds: float,
        ram_rss_mb: float,
    ) -> ScenarioEvaluationResult:
        retrieved_ids = set(e.evidence_id for e in package.evidence_items)
        req_set = set(scenario_spec.get("required_evidence_ids", []))
        contra_set = set(scenario_spec.get("contradictory_evidence_ids", []))
        distract_set = set(scenario_spec.get("distractor_evidence_ids", []))
        expected_answerable = scenario_spec.get("expected_answerable", True)

        found_req = req_set.intersection(retrieved_ids)
        missing_req = req_set - retrieved_ids
        found_contra = contra_set.intersection(retrieved_ids)
        found_distract = distract_set.intersection(retrieved_ids)

        # 1. Recall & Precision Metrics
        recall = (len(found_req) / len(req_set)) * 100.0 if req_set else 100.0
        contra_recall = (len(found_contra) / len(contra_set)) * 100.0 if contra_set else None

        # Noise / Irrelevant evidence ratio
        valid_set = req_set.union(contra_set)
        irrelevant_count = len(retrieved_ids - valid_set)
        irrelevant_ratio = (irrelevant_count / len(retrieved_ids)) * 100.0 if retrieved_ids else 0.0

        # 2. Controller Correctness Metrics
        max_hop_term = "MAX_HOPS" in package.termination_reason
        stagnation_term = "STAGNATION" in package.termination_reason

        # Premature termination: Controller declared verified=True when required evidence was missing
        premature_term = (package.controller_verified is True) and (recall < 100.0)
        unsupported_claim = premature_term

        # Successful termination logic:
        # - If answerable: Success requires 100% recall AND verified=True
        # - If unanswerable/insufficient: Success requires verified=False AND halted cleanly on budget/stagnation
        if expected_answerable:
            successful_term = (package.controller_verified is True) and (recall == 100.0)
        else:
            successful_term = (package.controller_verified is False) and not premature_term

        # 3. Deterministic Failure Taxonomy Classification
        failure_class = FailureClass.SUCCESS
        diagnosis = "Investigation completed successfully with verified evidence completeness."

        if not expected_answerable:
            if package.controller_verified is False:
                failure_class = FailureClass.INSUFFICIENT_CORPUS_CORRECT
                diagnosis = "Corpus lacks necessary facts; controller correctly refused to verify sufficiency."
            else:
                failure_class = FailureClass.CONTROLLER_FAILURE
                diagnosis = "CRITICAL: Controller verified sufficiency for an unanswerable/insufficient question!"
        else:
            if premature_term:
                failure_class = FailureClass.CONTROLLER_FAILURE
                diagnosis = f"Controller granted sufficiency despite missing ground-truth chunks: {list(missing_req)}"
            elif recall < 100.0:
                # Check trace to see if reasoning or retrieval failed
                llm_proposals = [e for e in package.investigation_trace if e.event_type == "LLM_PROPOSAL_RECEIVED"]
                had_premature_llm_proposal = any(e.details.get("proposed_sufficient") for e in llm_proposals)

                if had_premature_llm_proposal:
                    failure_class = FailureClass.REASONING_FAILURE
                    diagnosis = "LLM proposed sufficiency prematurely before all required evidence was collected."
                elif package.budget_summary.get("zero_yield_queries_count", 0) > 1:
                    failure_class = FailureClass.RETRIEVAL_FAILURE
                    diagnosis = "Targeted search queries repeatedly yielded zero new chunks from retriever index."
                else:
                    failure_class = FailureClass.INVESTIGATION_FAILURE
                    diagnosis = f"Investigation budget exhausted before discovering missing dependencies: {list(missing_req)}"
            else:
                failure_class = FailureClass.SUCCESS

        return ScenarioEvaluationResult(
            scenario_id=scenario_spec["scenario_id"],
            archetype=scenario_spec["archetype"],
            objective=scenario_spec["objective"],
            expected_answerable=expected_answerable,
            required_evidence_recall=round(recall, 1),
            required_evidence_found=sorted(list(found_req)),
            required_evidence_missing=sorted(list(missing_req)),
            contradictory_evidence_discovered=round(contra_recall, 1) if contra_recall is not None else None,
            contradictory_evidence_found=sorted(list(found_contra)),
            irrelevant_evidence_ratio=round(irrelevant_ratio, 1),
            distractors_found=sorted(list(found_distract)),
            controller_verified=package.controller_verified,
            termination_reason=package.termination_reason,
            successful_termination=successful_term,
            premature_termination=premature_term,
            unsupported_claim=unsupported_claim,
            max_hop_termination=max_hop_term,
            stagnation_detected=stagnation_term,
            hops_used=package.budget_summary["hops_used"],
            llm_calls_used=package.budget_summary["llm_calls_used"],
            queries_executed=package.budget_summary["queries_executed"],
            zero_yield_queries=package.budget_summary.get("zero_yield_queries_count", 0),
            elapsed_seconds=round(elapsed_seconds, 2),
            ram_rss_mb=round(ram_rss_mb, 1),
            failure_class=failure_class,
            failure_diagnosis=diagnosis,
        )
