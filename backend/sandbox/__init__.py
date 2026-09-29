"""
ORACLE 5.1 — Sandbox Verification & Proof Subsystem
"""

from backend.sandbox.attestation import AttestationAuthority
from backend.sandbox.engine import SandboxVerificationEngine
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
from backend.sandbox.repository import RepositorySnapshot, RepositorySnapshotManager
from backend.sandbox.reproducer import ReproducerRunner
from backend.sandbox.scope import ScopeValidator

__all__ = [
    "AttestationAuthority",
    "AttestationSeal",
    "ExecutionRecord",
    "FailureReason",
    "IsolatedSandboxWorkspace",
    "PatchApplier",
    "PatchResult",
    "RegressionRunner",
    "RepositorySnapshot",
    "RepositorySnapshotManager",
    "ReproducerRunner",
    "SandboxStage",
    "SandboxVerificationEngine",
    "SandboxVerificationResult",
    "ScopeReport",
    "ScopeValidator",
    "VerificationManifest",
]
