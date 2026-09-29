"""
Integration Benchmark Tests for ORACLE 5.0 Evaluation Cases (Bugs A - E)

Validates the Real Repository Investigation Engine against ground-truth bugs:
- Bug A: Null propagation
- Bug B: Cache key namespace mismatch regression
- Bug C: Configuration timeout mismatch
- Bug D: Git commit breaking contract regression
- Bug E: Ambiguous incident testing INSUFFICIENT EVIDENCE
"""

from pathlib import Path
import pytest

from backend.repository.engine import RealInvestigationRequest, RealRepositoryInvestigationEngine
from backend.repository.evaluation import EvaluationHarness, EvaluationTestCase


EVAL_REPO_PATH = str((Path(__file__).resolve().parent.parent / "test_repos" / "evaluation_repo").resolve())


def test_bug_a_null_propagation():
    """Bug A: Null propagation causing TypeError in process_payment."""
    engine = RealRepositoryInvestigationEngine()
    req = RealInvestigationRequest(
        repository_path=EVAL_REPO_PATH,
        incident_title="Null pointer dereference during VIP payment processing",
        error="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable""",
        service="payment-api",
        environment="production",
    )

    res = engine.run_investigation(req)
    telemetry = res.telemetry or {}
    rc = telemetry.get("rootCause", {})

    assert rc.get("status") == "STRONGLY_SUPPORTED"
    assert "Null" in rc.get("title", "") or "subscript" in rc.get("title", "").lower() or "cache" in rc.get("title", "").lower()

    # Ensure evidence contains code and AST
    evidence = res.admitted_evidence
    categories = [e.metadata.get("category") for e in evidence]
    assert "CODE" in categories
    assert "CONFIG" in categories

    # Ensure resolution affected files include payment_service.py
    resolution = telemetry.get("resolution", {})
    assert any("payment_service.py" in f for f in resolution.get("affectedFiles", []))


def test_bug_b_cache_key_regression():
    """Bug B: Redis cache key namespace mismatch regression."""
    engine = RealRepositoryInvestigationEngine()
    req = RealInvestigationRequest(
        repository_path=EVAL_REPO_PATH,
        incident_title="Customer cache misses causing 500 errors after deployment",
        error="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
KeyError: 'Customer record missing from active cache session'
during handling of the above exception:
TypeError: 'NoneType' object is not subscriptable""",
        logs="""2026-09-14T08:24:11.402Z [ERROR] payment-api payment_service.py:184: get_customer() returned None
2026-09-14T08:24:11.403Z [WARN] payment-api Redis MISS customers:8472
2026-09-14T08:24:11.404Z [ERROR] payment-api TypeError: 'NoneType' object is not subscriptable""",
        service="payment-api",
        environment="production",
    )

    res = engine.run_investigation(req)
    telemetry = res.telemetry or {}
    rc = telemetry.get("rootCause", {})

    assert rc.get("status") == "STRONGLY_SUPPORTED"
    assert "cache" in rc.get("title", "").lower() or "namespace" in rc.get("title", "").lower() or "subscript" in rc.get("title", "").lower()

    # Git diff evidence must be admitted
    git_ev = next((e for e in res.admitted_evidence if e.metadata.get("category") == "GIT"), None)
    assert git_ev is not None
    assert "Commit" in git_ev.content or "diff" in git_ev.content


def test_bug_c_config_timeout_mismatch():
    """Bug C: Configuration parameter mismatch / timeout."""
    engine = RealRepositoryInvestigationEngine()
    req = RealInvestigationRequest(
        repository_path=EVAL_REPO_PATH,
        incident_title="Upstream connection timeout during transaction settlement",
        error="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
TimeoutError: Redis connection timed out after 50ms""",
        service="payment-api",
        environment="production",
    )

    res = engine.run_investigation(req)
    telemetry = res.telemetry or {}
    rc = telemetry.get("rootCause", {})

    assert rc.get("status") == "STRONGLY_SUPPORTED"
    assert "timeout" in rc.get("title", "").lower() or "circuit" in rc.get("title", "").lower()


def test_bug_d_commit_regression():
    """Bug D: Regression introduced by specific Git commit."""
    engine = RealRepositoryInvestigationEngine()
    req = RealInvestigationRequest(
        repository_path=EVAL_REPO_PATH,
        incident_title="Regression on checkout after commit 8f31a2",
        error="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable""",
        service="payment-api",
        environment="production",
    )

    res = engine.run_investigation(req)
    telemetry = res.telemetry or {}
    rc = telemetry.get("rootCause", {})

    # Check that commit history is reflected in the explanation chain
    chain = " ".join(rc.get("explanationChain", []))
    assert "payment_service.py:184" in chain
    assert "commit" in chain.lower()


def test_bug_e_insufficient_evidence():
    """Bug E: Ambiguous incident where evidence is insufficient -> must return INSUFFICIENT EVIDENCE."""
    engine = RealRepositoryInvestigationEngine()
    req = RealInvestigationRequest(
        repository_path=EVAL_REPO_PATH,
        incident_title="Ambiguous transient degradation in unknown upstream caller",
        error="""Traceback (most recent call last):
  File "src/payment/nonexistent_gateway.py", line 99, in handle_call
    return dispatch()
RuntimeError: Network failure""",
        service="payment-api",
        environment="production",
    )

    res = engine.run_investigation(req)
    telemetry = res.telemetry or {}
    rc = telemetry.get("rootCause", {})

    # MUST return INSUFFICIENT_EVIDENCE
    assert rc.get("status") == "INSUFFICIENT_EVIDENCE"
    assert "INSUFFICIENT EVIDENCE" in rc.get("title", "").upper()
    assert len(rc.get("missingEvidence", [])) >= 1
    assert len(rc.get("recommendedNextActions", [])) >= 1


def test_evaluation_harness_benchmark():
    """Run the complete EvaluationHarness benchmark across all cases."""
    cases = [
        EvaluationTestCase(
            case_id="CASE-BUG-A",
            name="Null Propagation in Payment Service",
            description="NoneType dereference on customer tier subscript",
            repository_path=EVAL_REPO_PATH,
            error_trace="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable""",
            expected_file="src/payment/payment_service.py",
            expected_line=184,
            expected_function="process_payment",
            expected_status="STRONGLY_SUPPORTED",
            expected_root_cause_keywords=["null", "subscript", "cache"],
        ),
        EvaluationTestCase(
            case_id="CASE-BUG-B",
            name="Cache Key Namespace Mismatch",
            description="Redis key namespace changed from customer to customers",
            repository_path=EVAL_REPO_PATH,
            error_trace="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable""",
            logs="Redis MISS customer:8472",
            expected_file="src/payment/payment_service.py",
            expected_line=184,
            expected_function="process_payment",
            expected_status="STRONGLY_SUPPORTED",
            expected_root_cause_keywords=["cache", "namespace", "null", "subscript"],
        ),
        EvaluationTestCase(
            case_id="CASE-BUG-C",
            name="Connection Timeout Configuration Mismatch",
            description="Aggressive timeout threshold configuration",
            repository_path=EVAL_REPO_PATH,
            error_trace="""Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
TimeoutError: Redis connection timed out after 50ms""",
            expected_file="src/payment/payment_service.py",
            expected_line=184,
            expected_status="STRONGLY_SUPPORTED",
            expected_root_cause_keywords=["timeout", "circuit"],
        ),
        EvaluationTestCase(
            case_id="CASE-BUG-E",
            name="Ambiguous Upstream Gateway Fault",
            description="Missing code location and missing telemetry requires INSUFFICIENT EVIDENCE",
            repository_path=EVAL_REPO_PATH,
            error_trace="RuntimeError: Uncorrelated network drop",
            expected_status="INSUFFICIENT_EVIDENCE",
        ),
    ]

    harness = EvaluationHarness()
    report = harness.run_benchmark(cases)

    assert report.total_cases == 4
    assert report.passed_cases == 4
    assert report.failed_cases == 0
    assert report.file_localization_accuracy == 1.0
    assert report.insufficient_evidence_accuracy == 1.0
    assert report.root_cause_accuracy == 1.0
