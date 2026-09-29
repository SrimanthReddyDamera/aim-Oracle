"""
Data Models for ORACLE Release Readiness Intelligence (Brick 4.0)

Domain-agnostic representations of:
1. ReleaseCandidate (software release/change candidate)
2. SecurityFinding (normalized cross-scanner vulnerability finding)
3. CIPipelineRun (CI/CD build, test, and deployment validation)
4. WorkItem (Jira/Linear issue, blocker, incident, or task)
5. PullRequestReview (Git code review, approval, and merge state)
6. ReleaseDecision & ReleaseRecommendation (provenance-backed decision model)
7. GovernedActionProposal (idempotent, authorized enterprise write actions)
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.investigation.models import ContradictionRecord, InformationGap


# -----------------------------------------------------------------------------
# 1. RELEASE CANDIDATE
# -----------------------------------------------------------------------------

class ReleaseCandidate(BaseModel):
    """
    Canonical normalized representation of a software release or deployment candidate.
    Represents the target under investigation without coupling to specific Git/CI vendor schemas.
    """
    release_id: str = Field(description="Unique release identifier (e.g. REL-PAYMENT-4.8)")
    service_name: str = Field(description="Target service or microservice name (e.g. payment-service)")
    version: str = Field(description="Semantic release version tag (e.g. v4.8)")
    repository: str = Field(description="Canonical repository URI (e.g. github.com/org/payment-service)")
    branch: str = Field(default="main", description="Source branch for the release")
    commit: str = Field(description="Exact git commit hash being released (e.g. sha256 or 40-char SHA-1)")
    target_environment: str = Field(default="production", description="Target deployment environment")
    artifact_digest: Optional[str] = Field(default=None, description="Exact container or build artifact SHA-256 digest")
    deployment_id: Optional[str] = Field(default=None, description="Linked deployment execution ID")
    service_id: Optional[str] = Field(default=None, description="Canonical runtime service ID")
    pull_request_id: Optional[str] = Field(default=None, description="Linked PR/MR identifier (e.g. PR-582)")
    linked_work_item_ids: List[str] = Field(default_factory=list, description="Associated Jira/Linear keys (e.g. PROJ-912)")
    changed_components: List[str] = Field(default_factory=list, description="Subsystems or modules modified by this release")
    tenant_id: str = Field(default="default", description="Tenant identifier for multi-tenant isolation")
    created_at: str = Field(default_factory=lambda: "2026-10-25T10:00:00Z")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extended vendor/environment metadata")


# -----------------------------------------------------------------------------
# 2. SECURITY FINDINGS (SAST / SCA / DAST / SECRETS / CONTAINER)
# -----------------------------------------------------------------------------

class SecurityCategory(str, Enum):
    SAST      = "SAST"
    SCA       = "SCA"
    SECRETS   = "SECRETS"
    DAST      = "DAST"
    CONTAINER = "CONTAINER"
    IAC       = "IAC"


class SecuritySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class FindingStatus(str, Enum):
    ACTIVE             = "ACTIVE"
    RESOLVED           = "RESOLVED"
    EXCEPTION_ACCEPTED = "EXCEPTION_ACCEPTED"
    FALSE_POSITIVE     = "FALSE_POSITIVE"
    SUPERSEDED         = "SUPERSEDED"


class SecurityFinding(BaseModel):
    """
    Normalized, vendor-neutral security finding from any static, dynamic, or SCA scanner.
    Preserves original scanner provenance while providing standard fields for investigation.
    """
    finding_id: str = Field(description="Unique finding identifier (e.g. SEC-44 or Snyk-1234)")
    scanner: str = Field(description="Scanner origin (e.g. semgrep, snyk, trivy, osv)")
    category: SecurityCategory
    severity: SecuritySeverity
    status: FindingStatus = FindingStatus.ACTIVE
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    repository: str
    commit: str
    file: Optional[str] = None
    line_range: Optional[Tuple[int, int]] = None
    package: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    description: str
    remediation_guidance: str = ""
    is_exploitable_in_context: bool = True
    is_reachable: bool = True
    first_seen: str = ""
    last_seen: str = ""
    provenance: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 3. CI/CD & BUILD PIPELINE
# -----------------------------------------------------------------------------

class CIBuildStatus(str, Enum):
    PASSED    = "PASSED"
    FAILED    = "FAILED"
    RUNNING   = "RUNNING"
    CANCELLED = "CANCELLED"
    FLAKY     = "FLAKY"


class CIPipelineRun(BaseModel):
    """
    Normalized record of an automated CI/CD pipeline execution.
    Ties build and test results strictly to an exact commit hash.
    """
    pipeline_id: str
    repository: str
    commit: str
    branch: str = "main"
    status: CIBuildStatus
    failed_jobs: List[str] = Field(default_factory=list)
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    timestamp: str = ""
    provenance: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 4. WORK MANAGEMENT & INCIDENTS (JIRA / LINEAR)
# -----------------------------------------------------------------------------

class WorkItemStatus(str, Enum):
    DONE        = "DONE"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED     = "BLOCKED"
    REJECTED    = "REJECTED"
    OPEN        = "OPEN"


class WorkItem(BaseModel):
    """
    Normalized work item from Jira, Linear, or an incident management platform.
    """
    item_id: str = Field(description="Issue key (e.g. PROJ-912, INC-402)")
    title: str
    status: WorkItemStatus
    priority: str = "NORMAL"  # P1, BLOCKER, CRITICAL, HIGH, NORMAL
    is_blocking: bool = True
    is_incident: bool = False
    owner: str = ""
    approvals: List[str] = Field(default_factory=list)
    rejections: List[str] = Field(default_factory=list)
    linked_releases: List[str] = Field(default_factory=list)
    timestamp: str = ""
    provenance: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 5. SOURCE CONTROL & CODE REVIEW (GIT)
# -----------------------------------------------------------------------------

class CodeReviewStatus(str, Enum):
    APPROVED          = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    PENDING           = "PENDING"
    COMMENTED         = "COMMENTED"


class PullRequestReview(BaseModel):
    """
    Normalized representation of a pull request or merge request code review.
    """
    pr_id: str
    repository: str
    head_commit: str
    status: CodeReviewStatus
    reviewers: List[str] = Field(default_factory=list)
    approvers: List[str] = Field(default_factory=list)
    is_merged: bool = False
    rollback_procedure_documented: bool = True
    timestamp: str = ""
    provenance: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# 6. DECISION & RECOMMENDATION MODELS
# -----------------------------------------------------------------------------

class ReleaseDecisionOutcome(str, Enum):
    READY                 = "READY"                 # Fully verified, uncontested, all criteria satisfied
    BLOCKED               = "BLOCKED"               # Active critical blocker, failed CI, active incident
    CONDITIONAL           = "CONDITIONAL"           # Minor issues with accepted exception or non-blocking fix
    REQUIRES_REVIEW       = "REQUIRES_REVIEW"       # Missing required human governance/CAB approval
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # Stale/missing CI, provider outage, unverified state
    UNKNOWN               = "UNKNOWN"               # Inconclusive evaluation


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class ReleaseRecommendation(BaseModel):
    """
    Actionable, evidence-grounded recommendation produced by ORACLE when a release is blocked or at risk.
    """
    recommendation_id: str = Field(default_factory=lambda: f"rec-{uuid.uuid4().hex[:8]}")
    target_issue: str
    action_summary: str
    rationale: str
    current_state: str = ""
    recommended_state: str = ""
    risk_assessment: str = ""
    evidence_references: List[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# 7. GOVERNED ACTIONS
# -----------------------------------------------------------------------------

class GovernedActionType(str, Enum):
    CREATE_JIRA_REMEDIATION = "CREATE_JIRA_REMEDIATION"
    COMMENT_ON_PR           = "COMMENT_ON_PR"
    REQUEST_CODE_REVIEW     = "REQUEST_CODE_REVIEW"
    TRIGGER_SECURITY_SCAN   = "TRIGGER_SECURITY_SCAN"
    SCHEDULE_CAB_MEETING    = "SCHEDULE_CAB_MEETING"
    BLOCK_DEPLOYMENT        = "BLOCK_DEPLOYMENT"
    APPROVE_DEPLOYMENT      = "APPROVE_DEPLOYMENT"


class GovernedActionStatus(str, Enum):
    PROPOSED                = "PROPOSED"
    VALIDATED               = "VALIDATED"
    AUTHORIZED              = "AUTHORIZED"
    EXECUTED                = "EXECUTED"
    REJECTED                = "REJECTED"
    VERIFIED                = "VERIFIED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class GovernedActionProposal(BaseModel):
    """
    Strictly governed action proposal.
    Enforces authorization, human approval gates, idempotency keys, and audit logging.
    """
    action_id: str = Field(default_factory=lambda: f"act-{uuid.uuid4().hex[:8]}")
    action_type: GovernedActionType
    target_system: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    status: GovernedActionStatus = GovernedActionStatus.PROPOSED
    idempotency_key: str = ""
    requires_human_approval: bool = True
    authorized_by: Optional[str] = None
    execution_timestamp: Optional[str] = None
    tenant_id: str = "default"
    audit_trail: List[str] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# 8. FINAL RELEASE DECISION & ASSESSMENT
# -----------------------------------------------------------------------------

class ReleaseDecision(BaseModel):
    """
    Authoritative release readiness decision derived by the Controller from verified evidence.
    """
    release_id: str
    tenant_id: str = "default"
    outcome: ReleaseDecisionOutcome
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    blocking_factors: List[str] = Field(default_factory=list)
    verified_factors: List[str] = Field(default_factory=list)
    recommendations: List[ReleaseRecommendation] = Field(default_factory=list)
    governed_actions: List[GovernedActionProposal] = Field(default_factory=list)
    evidence_item_ids: List[str] = Field(default_factory=list)
    contradiction_ids: List[str] = Field(default_factory=list)
    unresolved_gap_ids: List[str] = Field(default_factory=list)
    investigation_id: str = ""
    investigation_status: str = "VERIFIED"
    provenance: Dict[str, Any] = Field(default_factory=dict)

    @property
    def blockers(self) -> List[str]:
        return self.blocking_factors


class ReleaseAssessment(BaseModel):
    """
    Top-level observable container presented to users and downstream APIs.
    """
    assessment_id: str = Field(default_factory=lambda: f"assess-{uuid.uuid4().hex[:8]}")
    tenant_id: str = "default"
    candidate: ReleaseCandidate
    decision: ReleaseDecision
    discovered_evidence: List[Evidence] = Field(default_factory=list)
    gaps: List[InformationGap] = Field(default_factory=list)
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    telemetry: Dict[str, Any] = Field(default_factory=dict)

    def to_summary_str(self) -> str:
        """Format human-readable summary view matching flagship UX."""
        lines = [
            "RELEASE READINESS",
            "=================",
            f"Release: {self.candidate.service_name} {self.candidate.version} ({self.candidate.release_id})",
            f"Commit: {self.candidate.commit[:10]} (Branch: {self.candidate.branch})",
            "",
            f"Decision: {self.decision.outcome.value}",
            f"Risk: {self.decision.risk_level.value}",
            f"Confidence: {int(self.decision.confidence * 100)}%",
            "",
            "Blocking factors:",
        ]
        if self.decision.blocking_factors:
            for bf in self.decision.blocking_factors:
                lines.append(f"  ✗ {bf}")
        else:
            lines.append("  (None - no active blockers)")

        lines.append("")
        lines.append("Verified:")
        if self.decision.verified_factors:
            for vf in self.decision.verified_factors:
                lines.append(f"  ✓ {vf}")
        else:
            lines.append("  (None)")

        if self.decision.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for idx, rec in enumerate(self.decision.recommendations, 1):
                lines.append(f"  {idx}. {rec.action_summary} ({rec.rationale})")

        lines.append("")
        lines.append("Evidence:")
        for eid in self.decision.evidence_item_ids[:8]:
            lines.append(f"  • {eid}")
        if len(self.decision.evidence_item_ids) > 8:
            lines.append(f"  • ... and {len(self.decision.evidence_item_ids) - 8} more items")

        lines.append("")
        lines.append(f"Investigation status: {self.decision.investigation_status}")
        return "\n".join(lines)
