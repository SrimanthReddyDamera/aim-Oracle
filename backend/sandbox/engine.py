"""
ORACLE 5.1 — Real Sandbox Verification Engine

The authoritative orchestrator for empirical verification.
Enforces the central principle:
    "ORACLE must never confuse a proposed fix with a verified fix."
Only empirical sandbox execution may unlock the deployment gate.
"""

from __future__ import annotations

import datetime
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.sandbox.attestation import AttestationAuthority
from backend.sandbox.isolation import IsolatedSandboxWorkspace
from backend.sandbox.models import (
    AttestationSeal,
    ExecutionRecord,
    FailureReason,
    SandboxStage,
    SandboxVerificationResult,
    ScopeReport,
    VerificationManifest,
)
from backend.sandbox.patch import PatchApplier, PatchResult
from backend.sandbox.regression import RegressionRunner
from backend.sandbox.repository import RepositorySnapshotManager
from backend.sandbox.reproducer import ReproducerRunner
from backend.sandbox.scope import ScopeValidator


class SandboxVerificationEngine:
    """
    Empirically verifies candidate patches in quarantined workspaces.
    """

    def __init__(self, authority: Optional[AttestationAuthority] = None):
        self.authority = authority or AttestationAuthority()

    def verify(
        self,
        investigation_id: str,
        repository_path: str | Path,
        git_patch: str,
        allowed_files: Optional[List[str]] = None,
        reproducer_cmd: Optional[str] = None,
        reproducer_script: Optional[str] = None,
        regression_cmd: Optional[str] = None,
        expected_error: Optional[str] = None,
        timeout: float = 45.0,
    ) -> SandboxVerificationResult:
        """
        Executes the full ORACLE 5.1 empirical sandbox verification pipeline.
        """
        verification_id = f"vfy_{uuid.uuid4().hex[:10]}"
        start_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        repo_path = Path(repository_path)

        # Default commands if not supplied
        rep_cmd = reproducer_cmd or "pytest tests/ -k test_reproduce"
        reg_cmd = regression_cmd or "pytest tests/ -v"

        result = SandboxVerificationResult(
            verification_id=verification_id,
            investigation_id=investigation_id,
            status="FAILED",
            stage=SandboxStage.CREATED,
            is_real_sandbox=True,
            test_command=f"{rep_cmd} && {reg_cmd}",
            test_script=reproducer_script or "",
            git_patch=git_patch,
        )

        terminal_chunks: List[str] = [
            f"=== ORACLE 5.1 REAL SANDBOX VERIFICATION ===",
            f"Verification ID   : {verification_id}",
            f"Investigation ID  : {investigation_id}",
            f"Repository        : {repo_path}",
            f"Started At        : {start_time_iso}",
            f"Isolation Mode    : Ephemeral Workspace + Network Disabled",
            "----------------------------------------------------------------",
        ]

        # 1. Sandbox Booting
        result.stage = SandboxStage.SANDBOX_BOOTING
        sandbox_mgr = IsolatedSandboxWorkspace()

        try:
            with sandbox_mgr as sandbox:
                terminal_chunks.append(f"[SANDBOX BOOT] Created workspace: {sandbox.workspace_dir}")
                sandbox_id = sandbox.sandbox_id

                # 2. Repository Snapshot
                result.stage = SandboxStage.REPOSITORY_SNAPSHOT
                snap_mgr = RepositorySnapshotManager(repo_path)
                snapshot = snap_mgr.create_snapshot(sandbox.workspace_dir)

                terminal_chunks.append(
                    f"[SNAPSHOT] Copied repository snapshot (HEAD: {snapshot.head_commit[:10]}, "
                    f"Digest: {snapshot.tree_digest[:16]}...)"
                )

                # 3. Negative Proof: Step A (Pre-patch reproducer run)
                result.stage = SandboxStage.REPRODUCER_RUNNING
                terminal_chunks.append(f"\n[NEGATIVE PROOF: PRE-PATCH] Executing: {rep_cmd}")
                rep_runner = ReproducerRunner(command=rep_cmd, expected_error=expected_error, timeout=timeout)

                rep_before = rep_runner.run_pre_patch(
                    sandbox=sandbox,
                    reproducer_script=reproducer_script,
                )
                result.reproducer_before = rep_before
                terminal_chunks.append(
                    f"  Exit Code: {rep_before.exit_code} (Duration: {rep_before.duration_seconds}s)\n"
                    f"  Stdout:\n{rep_before.stdout}\n"
                    f"  Stderr:\n{rep_before.stderr}"
                )

                # 4. Patch Application
                result.stage = SandboxStage.PATCH_APPLYING
                terminal_chunks.append(f"\n[PATCH APPLICATION] Applying unified git diff ({len(git_patch)} bytes)...")
                patch_applier = PatchApplier()
                patch_result: PatchResult = patch_applier.apply(git_patch, sandbox.workspace_dir)

                if not patch_result.success:
                    result.stage = SandboxStage.REJECTED
                    result.failure_reason = FailureReason.PATCH_APPLICATION_FAILED
                    result.verdict_message = f"Patch application failed: {patch_result.error_message}"
                    terminal_chunks.append(f"[PATCH ERROR] {patch_result.error_message}")
                    return self._finalize_result(result, terminal_chunks, start_time_iso, snapshot, patch_result)

                result.stage = SandboxStage.PATCH_APPLIED
                terminal_chunks.append(
                    f"[PATCH APPLIED] SHA-256: {patch_result.patch_sha256[:16]}... | "
                    f"Files: {patch_result.files_modified} (+{patch_result.insertions}/-{patch_result.deletions})"
                )

                # 5. Scope & AST Validation
                result.stage = SandboxStage.SCOPE_VALIDATING
                terminal_chunks.append("\n[SCOPE VALIDATION] Checking file boundaries and Python AST...")
                scope_validator = ScopeValidator(allowed_files=allowed_files)
                scope_report: ScopeReport = scope_validator.validate_scope(sandbox.workspace_dir, patch_result)
                result.scope_report = scope_report

                if not scope_report.is_valid:
                    result.stage = SandboxStage.SCOPE_FAILED
                    if scope_report.unauthorized_files:
                        result.failure_reason = FailureReason.SCOPE_VIOLATION
                        result.verdict_message = f"Scope violation: Unauthorized files modified: {scope_report.unauthorized_files}"
                        terminal_chunks.append(f"[SCOPE VIOLATION] Unauthorized files: {scope_report.unauthorized_files}")
                    else:
                        result.failure_reason = FailureReason.AST_VALIDATION_FAILED
                        result.verdict_message = f"AST validation failed: {scope_report.ast_violations}"
                        terminal_chunks.append(f"[AST VIOLATION] {scope_report.ast_violations}")

                    result.stage = SandboxStage.REJECTED
                    return self._finalize_result(result, terminal_chunks, start_time_iso, snapshot, patch_result)

                result.stage = SandboxStage.SCOPE_PASSED
                result.scope_contained = True
                terminal_chunks.append(
                    f"[SCOPE PASSED] Bounded to {len(scope_report.modified_files)} file(s). AST syntax valid."
                )

                # 6. Negative Proof: Step B (Post-patch reproducer run)
                result.stage = SandboxStage.REPRODUCER_RUNNING
                terminal_chunks.append(f"\n[NEGATIVE PROOF: POST-PATCH] Re-running reproducer: {rep_cmd}")
                rep_after = rep_runner.run_post_patch(sandbox=sandbox)
                result.reproducer_after = rep_after
                terminal_chunks.append(
                    f"  Exit Code: {rep_after.exit_code} (Duration: {rep_after.duration_seconds}s)\n"
                    f"  Stdout:\n{rep_after.stdout}\n"
                    f"  Stderr:\n{rep_after.stderr}"
                )

                # Evaluate negative proof
                # We expect post-patch to have exit_code == 0
                if rep_after.exit_code != 0:
                    result.stage = SandboxStage.NEGATIVE_PROOF_FAILED
                    result.failure_reason = FailureReason.NEGATIVE_PROOF_FAILED
                    result.verdict_message = "Post-patch reproducer test still failed; bug not eliminated."
                    result.original_error_eliminated = False
                    terminal_chunks.append("[NEGATIVE PROOF FAILED] Failure condition persists after patch.")
                    result.stage = SandboxStage.REJECTED
                    return self._finalize_result(result, terminal_chunks, start_time_iso, snapshot, patch_result)

                result.stage = SandboxStage.NEGATIVE_PROOF_PASSED
                result.original_error_eliminated = True
                terminal_chunks.append("[NEGATIVE PROOF PASSED] Failure successfully eliminated.")

                # 7. Regression Suite
                result.stage = SandboxStage.REGRESSION_RUNNING
                terminal_chunks.append(f"\n[REGRESSION SUITE] Executing regression test suite: {reg_cmd}")
                reg_runner = RegressionRunner(command=reg_cmd, timeout=timeout)
                reg_record, reg_summary, reg_passed = reg_runner.run(sandbox=sandbox)
                result.regression_record = reg_record

                terminal_chunks.append(
                    f"  Exit Code: {reg_record.exit_code} (Duration: {reg_record.duration_seconds}s)\n"
                    f"  Summary  : {reg_summary}\n"
                    f"  Stdout:\n{reg_record.stdout}\n"
                    f"  Stderr:\n{reg_record.stderr}"
                )

                if not reg_passed:
                    result.stage = SandboxStage.REGRESSION_FAILED
                    result.failure_reason = FailureReason.REGRESSION_FAILED
                    result.verdict_message = f"Regression tests failed: {reg_summary}"
                    result.regression_tests_passed = False
                    terminal_chunks.append("[REGRESSION FAILED] Patch introduced regression breakage.")
                    result.stage = SandboxStage.REJECTED
                    return self._finalize_result(result, terminal_chunks, start_time_iso, snapshot, patch_result)

                result.stage = SandboxStage.REGRESSION_PASSED
                result.regression_tests_passed = True
                terminal_chunks.append(f"[REGRESSION PASSED] All tests green: {reg_summary.get('passed', 0)} passed.")

                # 8. Cryptographic Attestation
                result.stage = SandboxStage.ATTESTATION_CREATING
                terminal_chunks.append("\n[ATTESTATION] Computing artifact digests and signing with Ed25519...")

                end_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                artifact_digests = {
                    "repository_tree": snapshot.tree_digest,
                    "patch_sha256": patch_result.patch_sha256,
                    "reproducer_stdout": self.authority.compute_sha256(rep_after.stdout),
                    "regression_stdout": self.authority.compute_sha256(reg_record.stdout),
                }

                manifest = VerificationManifest(
                    verification_id=verification_id,
                    investigation_id=investigation_id,
                    repository=str(repo_path),
                    repository_head=snapshot.head_commit,
                    patch_sha256=patch_result.patch_sha256,
                    sandbox_id=sandbox_id,
                    runtime="Python 3.12 (Isolated Sandbox)",
                    scope_result="PASSED",
                    negative_proof_result="PASSED",
                    regression_result="PASSED",
                    artifact_digests=artifact_digests,
                    started_at=start_time_iso,
                    completed_at=end_time_iso,
                )
                result.manifest = manifest

                seal: AttestationSeal = self.authority.sign_manifest(manifest, gate_status="DEPLOYMENT_CLEARED")
                # Independently verify signature
                is_sig_valid = self.authority.verify_manifest(manifest, seal.signature_hex, seal.public_key_hex)

                if not is_sig_valid:
                    result.stage = SandboxStage.ATTESTATION_FAILED
                    result.failure_reason = FailureReason.ATTESTATION_INVALID
                    result.verdict_message = "Cryptographic attestation signature validation failed."
                    terminal_chunks.append("[ATTESTATION ERROR] Signature validation check failed.")
                    result.stage = SandboxStage.REJECTED
                    return self._finalize_result(result, terminal_chunks, start_time_iso, snapshot, patch_result)

                result.attestation = seal
                result.stage = SandboxStage.ATTESTATION_VALID
                terminal_chunks.append(
                    f"[ATTESTATION VALID] Signed by: {seal.signer}\n"
                    f"  Token: {seal.token}\n"
                    f"  Public Key: {seal.public_key_hex[:24]}...\n"
                    f"  Signature : {seal.signature_hex[:24]}..."
                )

                # 9. Deployment Gate Derivation
                result.deployment_cleared = (
                    result.scope_contained
                    and result.original_error_eliminated
                    and result.regression_tests_passed
                    and (result.attestation is not None and result.attestation.is_valid)
                )

                if result.deployment_cleared:
                    result.status = "VERIFIED"
                    result.stage = SandboxStage.VERIFIED
                    result.verdict_message = "All sandbox proof criteria satisfied. Deployment gate cleared."
                    terminal_chunks.append("\n================================================================")
                    terminal_chunks.append("VERDICT: VERIFIED — DEPLOYMENT GATE CLEARED")
                    terminal_chunks.append("================================================================")
                else:
                    result.status = "FAILED"
                    result.stage = SandboxStage.REJECTED
                    result.verdict_message = "Sandbox proof criteria not met. Deployment locked."
                    terminal_chunks.append("\n================================================================")
                    terminal_chunks.append("VERDICT: REJECTED — DEPLOYMENT GATE LOCKED")
                    terminal_chunks.append("================================================================")

                return self._finalize_result(result, terminal_chunks, start_time_iso, snapshot, patch_result)

        except Exception as exc:
            result.status = "FAILED"
            result.stage = SandboxStage.REJECTED
            result.failure_reason = FailureReason.SANDBOX_BOOT_FAILED
            result.verdict_message = f"Sandbox execution encountered unexpected exception: {exc}"
            terminal_chunks.append(f"\n[SANDBOX UNCAUGHT ERROR] {exc}")
            result.terminal_output = "\n".join(terminal_chunks)
            result.verified_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return result

    def _finalize_result(
        self,
        result: SandboxVerificationResult,
        terminal_chunks: List[str],
        start_time: str,
        snapshot: Any = None,
        patch_result: Any = None,
    ) -> SandboxVerificationResult:
        """Populates terminal output, timestamps, and returns the result."""
        result.terminal_output = "\n".join(terminal_chunks)
        result.verified_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return result
