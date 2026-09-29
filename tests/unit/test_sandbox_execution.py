"""
ORACLE 5.1 — Sandbox Verification & Proof Engine Test Suite

Implements the mandatory 8-case test matrix:
1. Case 1: Known-good patch -> VERIFIED, deployment cleared, attestation sealed.
2. Case 2: Bad patch (does not fix reproducer) -> NEGATIVE_PROOF_FAILED, REJECTED.
3. Case 3: Regression patch (breaks another test) -> REGRESSION_FAILED, REJECTED.
4. Case 4: Out-of-scope patch (modifies unauthorized file) -> SCOPE_VIOLATION, REJECTED.
5. Case 5: Tampered attestation manifest -> ATTESTATION_INVALID, signature verification fails.
6. Case 6: Timeout execution -> Watchdog termination, sandbox destroyed.
7. Case 7: Sandbox isolation & credential protection -> Credentials stripped, traversal blocked.
8. Case 8: Guaranteed cleanup -> Ephemeral directory completely removed even on failure.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from backend.sandbox.attestation import AttestationAuthority
from backend.sandbox.engine import SandboxVerificationEngine
from backend.sandbox.isolation import IsolatedSandboxWorkspace
from backend.sandbox.models import (
    FailureReason,
    SandboxStage,
    VerificationManifest,
)
from backend.sandbox.patch import PatchApplier
from backend.sandbox.scope import ScopeValidator


REPO_PATH = Path(__file__).resolve().parent.parent / "test_repos" / "evaluation_repo"

GOOD_PATCH = """diff --git a/src/payment/payment_service.py b/src/payment/payment_service.py
--- a/src/payment/payment_service.py
+++ b/src/payment/payment_service.py
@@ -181,4 +181,4 @@ class PaymentService:
-        customer_tier = customer["tier"]
+        customer_tier = customer["tier"] if customer else "STANDARD"
diff --git a/tests/test_payment.py b/tests/test_payment.py
--- a/tests/test_payment.py
+++ b/tests/test_payment.py
@@ -47,2 +47,2 @@ def test_process_payment_failure_null_propagation():
-    with pytest.raises(TypeError):
-        service.process_payment({"customer_id": "cust_unknown", "amount": 50.0})
+    res = service.process_payment({"customer_id": "cust_unknown", "amount": 50.0})
+    assert res["status"] == "SUCCESS"
"""

BAD_PATCH = """diff --git a/src/payment/payment_service.py b/src/payment/payment_service.py
--- a/src/payment/payment_service.py
+++ b/src/payment/payment_service.py
@@ -181,4 +181,4 @@ class PaymentService:
-        customer_tier = customer["tier"]
+        customer_tier = None["tier"]
"""

REGRESSION_PATCH = """diff --git a/src/payment/payment_service.py b/src/payment/payment_service.py
--- a/src/payment/payment_service.py
+++ b/src/payment/payment_service.py
@@ -181,4 +181,4 @@ class PaymentService:
-        customer_tier = customer["tier"]
+        customer_tier = customer["tier"] if customer else "STANDARD"
@@ -18,2 +18,2 @@ def test_payment_service_initialization():
-    def get_service_health(self) -> str:
-        return "UP"
+    def get_service_health(self) -> str:
+        return "DOWN"
diff --git a/tests/test_payment.py b/tests/test_payment.py
--- a/tests/test_payment.py
+++ b/tests/test_payment.py
@@ -47,2 +47,2 @@ def test_process_payment_failure_null_propagation():
-    with pytest.raises(TypeError):
-        service.process_payment({"customer_id": "cust_unknown", "amount": 50.0})
+    res = service.process_payment({"customer_id": "cust_unknown", "amount": 50.0})
+    assert res["status"] == "SUCCESS"
"""

OUT_OF_SCOPE_PATCH = """diff --git a/src/payment/payment_service.py b/src/payment/payment_service.py
--- a/src/payment/payment_service.py
+++ b/src/payment/payment_service.py
@@ -181,4 +181,4 @@ class PaymentService:
-        customer_tier = customer["tier"]
+        customer_tier = customer["tier"] if customer else "STANDARD"
diff --git a/src/unauthorized_admin.py b/src/unauthorized_admin.py
new file mode 100644
--- /dev/null
+++ b/src/unauthorized_admin.py
@@ -0,0 +1,2 @@
+def backdoor():
+    pass
"""

REPRODUCER_SCRIPT = """
import pytest
from src.payment.cache import CacheClient
from src.payment.payment_service import PaymentService

def test_reproduce_null_subscript():
    cache = CacheClient()
    service = PaymentService(cache=cache)
    res = service.process_payment({"customer_id": "cust_unknown", "amount": 50.0})
    assert res["status"] == "SUCCESS"
"""


def test_case_1_known_good_patch():
    """Case 1: Valid patch fixes reproducer, passes regression & scope, seals attestation."""
    engine = SandboxVerificationEngine()
    res = engine.verify(
        investigation_id="ORC-TEST-001",
        repository_path=REPO_PATH,
        git_patch=GOOD_PATCH,
        allowed_files=["src/payment/payment_service.py", "tests/test_payment.py"],
        reproducer_cmd="pytest tests/reproduce_issue.py -v",
        reproducer_script=REPRODUCER_SCRIPT,
        regression_cmd="pytest tests/test_payment.py -v",
    )

    assert res.status == "VERIFIED"
    assert res.stage == SandboxStage.VERIFIED
    assert res.deployment_cleared is True
    assert res.original_error_eliminated is True
    assert res.regression_tests_passed is True
    assert res.scope_contained is True
    assert res.attestation is not None
    assert res.attestation.is_valid is True
    assert res.attestation.signature_hex != ""


def test_case_2_bad_patch():
    """Case 2: Patch does not fix reproducer -> NEGATIVE_PROOF_FAILED, REJECTED."""
    engine = SandboxVerificationEngine()
    res = engine.verify(
        investigation_id="ORC-TEST-002",
        repository_path=REPO_PATH,
        git_patch=BAD_PATCH,
        allowed_files=["src/payment/payment_service.py"],
        reproducer_cmd="pytest tests/reproduce_issue.py -v",
        reproducer_script=REPRODUCER_SCRIPT,
        regression_cmd="pytest tests/test_payment.py -v",
    )

    assert res.status == "FAILED"
    assert res.stage == SandboxStage.REJECTED
    assert res.failure_reason == FailureReason.NEGATIVE_PROOF_FAILED
    assert res.deployment_cleared is False
    assert res.original_error_eliminated is False


def test_case_3_regression_patch():
    """Case 3: Bug fixed but breaks another test -> REGRESSION_FAILED, REJECTED."""
    engine = SandboxVerificationEngine()
    res = engine.verify(
        investigation_id="ORC-TEST-003",
        repository_path=REPO_PATH,
        git_patch=REGRESSION_PATCH,
        allowed_files=["src/payment/payment_service.py", "tests/test_payment.py"],
        reproducer_cmd="pytest tests/reproduce_issue.py -v",
        reproducer_script=REPRODUCER_SCRIPT,
        regression_cmd="pytest tests/test_payment.py -v",
    )

    assert res.status == "FAILED"
    assert res.stage == SandboxStage.REJECTED
    assert res.failure_reason == FailureReason.REGRESSION_FAILED
    assert res.deployment_cleared is False
    assert res.regression_tests_passed is False


def test_case_4_out_of_scope_patch():
    """Case 4: Modifies unauthorized file -> SCOPE_VIOLATION, REJECTED."""
    engine = SandboxVerificationEngine()
    res = engine.verify(
        investigation_id="ORC-TEST-004",
        repository_path=REPO_PATH,
        git_patch=OUT_OF_SCOPE_PATCH,
        allowed_files=["src/payment/payment_service.py"],
        reproducer_cmd="pytest tests/reproduce_issue.py -v",
        reproducer_script=REPRODUCER_SCRIPT,
        regression_cmd="pytest tests/test_payment.py -v",
    )

    assert res.status == "FAILED"
    assert res.stage == SandboxStage.REJECTED
    assert res.failure_reason == FailureReason.SCOPE_VIOLATION
    assert res.deployment_cleared is False
    assert res.scope_contained is False
    assert "src/unauthorized_admin.py" in res.scope_report.unauthorized_files


def test_case_5_tampered_attestation():
    """Case 5: Modifying any field in signed manifest causes signature verification failure."""
    authority = AttestationAuthority()
    manifest = VerificationManifest(
        verification_id="vfy_test_123",
        investigation_id="ORC-TEST-005",
        repository="tests/test_repos/evaluation_repo",
        repository_head="abc1234",
        patch_sha256="deadbeef" * 8,
        sandbox_id="sbx_test",
        runtime="Python 3.12 (Isolated Sandbox)",
        scope_result="PASSED",
        negative_proof_result="PASSED",
        regression_result="PASSED",
        artifact_digests={"stdout": "11223344"},
        started_at="2026-09-14T00:00:00Z",
        completed_at="2026-09-14T00:01:00Z",
    )

    seal = authority.sign_manifest(manifest)
    # Valid initial verification
    assert authority.verify_manifest(manifest, seal.signature_hex, seal.public_key_hex) is True

    # Tamper with manifest field (e.g. patch digest altered)
    tampered_manifest = manifest.model_copy(deep=True)
    tampered_manifest.patch_sha256 = "attacker_modified_digest"

    # Must fail verification
    assert authority.verify_manifest(tampered_manifest, seal.signature_hex, seal.public_key_hex) is False

    # Tamper with regression result (passed -> failed or altered text)
    tampered_manifest_2 = manifest.model_copy(deep=True)
    tampered_manifest_2.regression_result = "FAILED"
    assert authority.verify_manifest(tampered_manifest_2, seal.signature_hex, seal.public_key_hex) is False


def test_case_6_timeout_execution():
    """Case 6: Infinite / slow reproducer is terminated by watchdog timeout."""
    with IsolatedSandboxWorkspace() as sandbox:
        # Run command with 1 second timeout
        record = sandbox.run_command(
            command="python -c \"import time; time.sleep(10)\"",
            timeout=1.0,
        )
        assert record.exit_code == -1
        assert "timed out after 1.0 seconds" in record.stderr


def test_case_7_sandbox_isolation_and_credentials(monkeypatch):
    """Case 7: Credentials are stripped and path traversal escapes are rejected."""
    # Set fake credentials in environment using monkeypatch so other tests are not affected
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIA_FAKE_SECRET_KEY")
    monkeypatch.setenv("DATABASE_URL", "postgres://admin:secret@prod.internal/db")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_1234567890abcdef")

    with IsolatedSandboxWorkspace() as sandbox:
        clean_env = sandbox.sanitize_environment()
        # Ensure credentials stripped
        assert "AWS_SECRET_ACCESS_KEY" not in clean_env
        assert "DATABASE_URL" not in clean_env
        assert "GITHUB_TOKEN" not in clean_env
        assert clean_env.get("NETWORK_MODE") == "DISABLED"
        assert clean_env.get("HTTP_PROXY") == "http://127.0.0.1:9"

        # Traversal check
        with pytest.raises(PermissionError):
            sandbox.validate_path_confinement("../outside_dir")


def test_case_8_guaranteed_cleanup():
    """Case 8: Ephemeral workspace is guaranteed to be deleted upon context exit or failure."""
    created_dir = None
    with IsolatedSandboxWorkspace() as sandbox:
        created_dir = sandbox.workspace_dir
        assert created_dir.exists()
        # Write temporary artifact
        (created_dir / "test_file.txt").write_text("temporary content", encoding="utf-8")
        assert (created_dir / "test_file.txt").exists()

    # Must be deleted after exiting context
    assert not created_dir.exists()
