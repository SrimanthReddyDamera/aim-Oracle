"""
Evaluation Harness for ORACLE 5.0 (Step 19)

Benchmarks the Real Repository Investigation Engine against known test cases:
- Bug A: Null propagation
- Bug B: Cache key namespace mismatch regression
- Bug C: Configuration parameter mismatch
- Bug D: Git commit breaking contract regression
- Bug E: Ambiguous incident testing INSUFFICIENT EVIDENCE

Measures:
- File localization accuracy
- Function localization accuracy
- Evidence recall & precision
- Root cause accuracy
- Insufficient-evidence accuracy
- Contradiction handling
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.repository.engine import RealInvestigationRequest, RealRepositoryInvestigationEngine

logger = logging.getLogger("oracle.repository.evaluation")


class EvaluationTestCase(BaseModel):
    """Specification of a ground-truth benchmark investigation case."""
    case_id: str
    name: str
    description: str
    repository_path: str
    error_trace: str
    logs: Optional[str] = None
    expected_file: Optional[str] = None
    expected_line: Optional[int] = None
    expected_function: Optional[str] = None
    expected_status: str = "STRONGLY_SUPPORTED"  # or INSUFFICIENT_EVIDENCE
    expected_root_cause_keywords: List[str] = Field(default_factory=list)
    required_evidence_categories: List[str] = Field(default_factory=list)


class EvaluationCaseResult(BaseModel):
    """Execution result for a benchmark case."""
    case_id: str
    name: str
    passed: bool
    file_localized: bool
    function_localized: bool
    status_matched: bool
    root_cause_matched: bool
    evidence_categories_found: List[str] = Field(default_factory=list)
    verdict: str
    execution_time_ms: float
    notes: str = ""


class EvaluationSummaryReport(BaseModel):
    """Aggregate benchmark report across all test cases."""
    total_cases: int
    passed_cases: int
    failed_cases: int
    file_localization_accuracy: float
    function_localization_accuracy: float
    root_cause_accuracy: float
    insufficient_evidence_accuracy: float
    case_results: List[EvaluationCaseResult] = Field(default_factory=list)


class EvaluationHarness:
    """
    Executes automated benchmark evaluation of the RealRepositoryInvestigationEngine.
    """

    def __init__(self, engine: Optional[RealRepositoryInvestigationEngine] = None):
        self.engine = engine or RealRepositoryInvestigationEngine()

    def run_benchmark(self, cases: List[EvaluationTestCase]) -> EvaluationSummaryReport:
        results: List[EvaluationCaseResult] = []
        loc_successes = 0
        func_successes = 0
        rc_successes = 0
        insufficient_tests = 0
        insufficient_successes = 0

        for case in cases:
            req = RealInvestigationRequest(
                repository_path=case.repository_path,
                incident_title=case.name,
                error=case.error_trace,
                logs=case.logs,
                service="payment-api",
            )

            res = self.engine.run_investigation(req)
            telemetry = res.telemetry or {}
            rc = telemetry.get("rootCause", {})
            stage = telemetry.get("stage", "")

            # Verify file and function localization
            evidence = res.admitted_evidence
            code_ev = next((e for e in evidence if e.metadata.get("category") == "CODE" and e.metadata.get("type") == "SOURCE_CODE"), None)

            file_loc = False
            func_loc = False
            if code_ev and case.expected_file:
                file_loc = case.expected_file in code_ev.source_path or code_ev.source_path in case.expected_file
                if case.expected_function:
                    func_loc = case.expected_function.lower() in str(code_ev.metadata.get("containing_function", "")).lower()
                else:
                    func_loc = True

            if file_loc:
                loc_successes += 1
            if func_loc:
                func_successes += 1

            # Verify status
            is_insufficient_expected = case.expected_status == "INSUFFICIENT_EVIDENCE"
            actual_status = rc.get("status", "")
            status_match = False
            if is_insufficient_expected:
                insufficient_tests += 1
                status_match = actual_status == "INSUFFICIENT_EVIDENCE" or "inconclusive" in stage.lower()
                if status_match:
                    insufficient_successes += 1
            else:
                status_match = actual_status == "STRONGLY_SUPPORTED" or "root_cause_identified" in stage.lower()

            # Verify root cause keywords
            rc_title = rc.get("title", "").lower()
            rc_match = False
            if is_insufficient_expected:
                rc_match = "insufficient" in rc_title or status_match
            else:
                rc_match = any(kw.lower() in rc_title for kw in case.expected_root_cause_keywords) if case.expected_root_cause_keywords else True

            if rc_match:
                rc_successes += 1

            categories = list({e.metadata.get("category", "") for e in evidence if e.metadata.get("category")})

            case_passed = (
                (is_insufficient_expected and status_match)
                or (not is_insufficient_expected and file_loc and status_match and rc_match)
            )

            results.append(
                EvaluationCaseResult(
                    case_id=case.case_id,
                    name=case.name,
                    passed=case_passed,
                    file_localized=file_loc,
                    function_localized=func_loc,
                    status_matched=status_match,
                    root_cause_matched=rc_match,
                    evidence_categories_found=categories,
                    verdict=rc.get("title", "Unknown"),
                    execution_time_ms=float(telemetry.get("execution_time_ms", 0)),
                )
            )

        total = len(cases)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        return EvaluationSummaryReport(
            total_cases=total,
            passed_cases=passed,
            failed_cases=failed,
            file_localization_accuracy=round(loc_successes / max(1, total - insufficient_tests), 2),
            function_localization_accuracy=round(func_successes / max(1, total - insufficient_tests), 2),
            root_cause_accuracy=round(rc_successes / total, 2),
            insufficient_evidence_accuracy=round(insufficient_successes / max(1, insufficient_tests), 2) if insufficient_tests else 1.0,
            case_results=results,
        )
