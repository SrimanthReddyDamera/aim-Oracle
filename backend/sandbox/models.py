"""
ORACLE 5.1 — Sandbox Execution & Proof Engine Models

Defines strongly-typed schemas for sandbox verification, execution records,
scope containment, cryptographic attestation, and deployment gate derivation.
"""

from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SandboxStage(str, enum.Enum):
    CREATED = "CREATED"
    SANDBOX_BOOTING = "SANDBOX_BOOTING"
    REPOSITORY_SNAPSHOT = "REPOSITORY_SNAPSHOT"
    PATCH_APPLYING = "PATCH_APPLYING"
    PATCH_APPLIED = "PATCH_APPLIED"
    SCOPE_VALIDATING = "SCOPE_VALIDATING"
    SCOPE_PASSED = "SCOPE_PASSED"
    SCOPE_FAILED = "SCOPE_FAILED"
    REPRODUCER_RUNNING = "REPRODUCER_RUNNING"
    NEGATIVE_PROOF_PASSED = "NEGATIVE_PROOF_PASSED"
    NEGATIVE_PROOF_FAILED = "NEGATIVE_PROOF_FAILED"
    REGRESSION_RUNNING = "REGRESSION_RUNNING"
    REGRESSION_PASSED = "REGRESSION_PASSED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    ATTESTATION_CREATING = "ATTESTATION_CREATING"
    ATTESTATION_VALID = "ATTESTATION_VALID"
    ATTESTATION_FAILED = "ATTESTATION_FAILED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class FailureReason(str, enum.Enum):
    NONE = "NONE"
    SANDBOX_BOOT_FAILED = "SANDBOX_BOOT_FAILED"
    SANDBOX_ISOLATION_FAILED = "SANDBOX_ISOLATION_FAILED"
    REPOSITORY_SNAPSHOT_FAILED = "REPOSITORY_SNAPSHOT_FAILED"
    PATCH_APPLICATION_FAILED = "PATCH_APPLICATION_FAILED"
    PATCH_VALIDATION_FAILED = "PATCH_VALIDATION_FAILED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    AST_VALIDATION_FAILED = "AST_VALIDATION_FAILED"
    REPRODUCER_FAILED = "REPRODUCER_FAILED"
    NEGATIVE_PROOF_FAILED = "NEGATIVE_PROOF_FAILED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    TIMEOUT = "TIMEOUT"
    SANDBOX_CLEANUP_FAILED = "SANDBOX_CLEANUP_FAILED"
    ATTESTATION_FAILED = "ATTESTATION_FAILED"
    ATTESTATION_INVALID = "ATTESTATION_INVALID"
    CANCELLED = "CANCELLED"


class ExecutionRecord(BaseModel):
    """Execution telemetry captured from a command run inside the sandbox."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timestamp: str
    reproduced_failure: Optional[bool] = None


class ScopeReport(BaseModel):
    """Audited report of files modified by the patch vs authorized boundary."""
    is_valid: bool
    allowed_files: List[str] = Field(default_factory=list)
    modified_files: List[str] = Field(default_factory=list)
    unauthorized_files: List[str] = Field(default_factory=list)
    ast_valid: bool = True
    ast_violations: List[str] = Field(default_factory=list)
    files_changed_count: int = 0
    insertions: int = 0
    deletions: int = 0


class AttestationSeal(BaseModel):
    """Cryptographic seal confirming verification validity signed with Ed25519."""
    token: str
    digest: str
    signature_hex: str
    public_key_hex: str
    signer: str
    gate_status: str
    timestamp: str
    is_valid: bool = True


class VerificationManifest(BaseModel):
    """Immutable manifest containing hashes of all verification inputs and outputs."""
    verification_id: str
    investigation_id: str
    repository: str
    repository_head: str
    patch_sha256: str
    sandbox_id: str
    runtime: str
    scope_result: str
    negative_proof_result: str
    regression_result: str
    artifact_digests: Dict[str, str] = Field(default_factory=dict)
    started_at: str
    completed_at: str


class SandboxVerificationResult(BaseModel):
    """Full empirical verification result produced by SandboxVerificationEngine."""
    verification_id: str
    investigation_id: str
    status: str  # "VERIFIED" | "FAILED"
    stage: SandboxStage
    failure_reason: Optional[FailureReason] = None
    original_error_eliminated: bool = False
    regression_tests_passed: bool = False
    scope_contained: bool = False
    deployment_cleared: bool = False
    test_command: str = ""
    test_script: str = ""
    git_patch: str = ""
    terminal_output: str = ""
    scope_report: Optional[ScopeReport] = None
    reproducer_before: Optional[ExecutionRecord] = None
    reproducer_after: Optional[ExecutionRecord] = None
    regression_record: Optional[ExecutionRecord] = None
    attestation: Optional[AttestationSeal] = None
    manifest: Optional[VerificationManifest] = None
    is_real_sandbox: bool = True
    verified_at: str = ""
    verdict_message: str = ""

    def to_ui_dict(self) -> Dict[str, Any]:
        """Formats the result into the schema expected by the ORACLE UI."""
        diff_summary = {
            "filesChanged": self.scope_report.files_changed_count if self.scope_report else 0,
            "insertions": self.scope_report.insertions if self.scope_report else 0,
            "deletions": self.scope_report.deletions if self.scope_report else 0,
        }
        
        attest_dict = None
        if self.attestation:
            attest_dict = {
                "token": self.attestation.token,
                "digest": self.attestation.digest,
                "containerId": self.manifest.sandbox_id if self.manifest else "sandbox-isolated",
                "signer": self.attestation.signer,
                "gateStatus": self.attestation.gate_status,
                "timestamp": self.attestation.timestamp,
                "isMockDemo": not self.is_real_sandbox,
                "signatureHex": self.attestation.signature_hex,
                "publicKeyHex": self.attestation.public_key_hex,
            }

        return {
            "verificationId": self.verification_id,
            "status": self.status,
            "stage": self.stage.value if hasattr(self.stage, "value") else str(self.stage),
            "failureReason": self.failure_reason.value if self.failure_reason else None,
            "originalErrorReproduced": True if self.reproducer_before and self.reproducer_before.reproduced_failure else False,
            "originalErrorEliminated": self.original_error_eliminated,
            "regressionTestsPassed": self.regression_tests_passed,
            "scopeContained": self.scope_contained,
            "deploymentCleared": self.deployment_cleared,
            "unrelatedChangesDetected": len(self.scope_report.unauthorized_files) > 0 if self.scope_report else False,
            "changedFilesCount": diff_summary["filesChanged"],
            "diffSummary": diff_summary,
            "verdictMessage": self.verdict_message,
            "verifiedAt": self.verified_at,
            "testCommand": self.test_command,
            "testScript": self.test_script,
            "gitPatch": self.git_patch,
            "terminalOutput": self.terminal_output,
            "attestation": attest_dict,
            "isRealSandbox": self.is_real_sandbox,
        }
