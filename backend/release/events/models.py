"""
Canonical Enterprise Event Models & Taxonomy (Brick 4.3)

Defines vendor-neutral models for:
1. EnterpriseEventType taxonomy (Source Control, Work Management, CI/CD, Security, Incidents).
2. EnterpriseEvent (canonical event container with correlation keys, entity bindings, and provenance).
3. DecisionChangeEvent (structured notification when controller decision outcome flips).
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.release.models import ReleaseDecisionOutcome


class EnterpriseEventType(str, Enum):
    """Vendor-neutral taxonomy of enterprise lifecycle events."""
    # Source Control & Code Review
    CODE_PUSHED              = "CODE_PUSHED"
    BRANCH_UPDATED           = "BRANCH_UPDATED"
    PR_CREATED               = "PR_CREATED"
    PR_UPDATED               = "PR_UPDATED"
    PR_APPROVED              = "PR_APPROVED"
    PR_REJECTED              = "PR_REJECTED"
    PR_MERGED                = "PR_MERGED"

    # Work Management (Jira / Linear)
    JIRA_ISSUE_CREATED       = "JIRA_ISSUE_CREATED"
    JIRA_ISSUE_UPDATED       = "JIRA_ISSUE_UPDATED"
    JIRA_STATUS_CHANGED      = "JIRA_STATUS_CHANGED"
    JIRA_BLOCKER_CHANGED     = "JIRA_BLOCKER_CHANGED"

    # CI/CD Pipelines
    CI_STARTED               = "CI_STARTED"
    CI_COMPLETED             = "CI_COMPLETED"
    CI_FAILED                = "CI_FAILED"
    CI_SUCCEEDED             = "CI_SUCCEEDED"

    # Security & Vulnerability Scanners
    SECURITY_FINDING_CREATED  = "SECURITY_FINDING_CREATED"
    SECURITY_FINDING_UPDATED  = "SECURITY_FINDING_UPDATED"
    SECURITY_FINDING_RESOLVED = "SECURITY_FINDING_RESOLVED"
    SECURITY_SCAN_COMPLETED   = "SECURITY_SCAN_COMPLETED"

    # Dependency & Supply Chain
    DEPENDENCY_CHANGED       = "DEPENDENCY_CHANGED"

    # Artifacts & Deployments
    ARTIFACT_BUILT           = "ARTIFACT_BUILT"
    DEPLOYMENT_CHANGED       = "DEPLOYMENT_CHANGED"

    # Runtime & Security Posture
    RUNTIME_EXPOSURE_CHANGED = "RUNTIME_EXPOSURE_CHANGED"
    SECURITY_CONTROL_CHANGED = "SECURITY_CONTROL_CHANGED"

    # Incidents & Operations
    INCIDENT_CREATED         = "INCIDENT_CREATED"
    INCIDENT_OPENED          = "INCIDENT_OPENED"
    INCIDENT_UPDATED         = "INCIDENT_UPDATED"
    INCIDENT_RESOLVED        = "INCIDENT_RESOLVED"


class EnterpriseEvent(BaseModel):
    """
    Canonical vendor-neutral enterprise event.
    Represents an untrusted signal from an external system that may trigger targeted re-investigation.
    Does NOT store unnecessary raw provider payloads directly inside the domain model.
    """
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:10]}")
    event_type: EnterpriseEventType
    source: str = Field(description="Originating system e.g. 'github', 'jira', 'semgrep', 'trivy'")
    source_event_id: str = Field(default_factory=lambda: f"src-{uuid.uuid4().hex[:8]}", description="Unique event/delivery ID assigned by the origin provider")
    timestamp: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z", description="ISO-8601 event generation timestamp from provider")
    entity_type: str = Field(default="generic", description="Primary entity classification: 'commit', 'pull_request', 'work_item', 'pipeline', 'finding', 'incident'")
    entity_id: str = Field(default="", description="Primary entity canonical identifier")

    received_at: str = Field(default_factory=lambda: "2026-09-09T12:00:00Z")
    tenant_id: str = Field(default="default", description="Tenant identifier for multi-tenant isolation")

    # Domain binding keys
    repository: Optional[str] = None
    commit: Optional[str] = None
    release_id: Optional[str] = None
    work_item_id: Optional[str] = None
    service_id: Optional[str] = None
    environment: Optional[str] = None
    artifact_digest: Optional[str] = None
    deployment_id: Optional[str] = None

    # Correlation keys & payload reference
    correlation_keys: Dict[str, Any] = Field(default_factory=dict)
    payload_reference: Optional[str] = Field(default=None, description="SHA-256 or URI pointer to raw payload in blob store")
    payload: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)

    def compute_idempotency_key(self) -> str:
        """Derive deterministic idempotency key for duplicate suppression."""
        import hashlib
        raw = f"{self.tenant_id}:{self.source.lower()}:{self.source_event_id}:{self.event_type.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DecisionChangeEvent(BaseModel):
    """
    Structured notification emitted whenever an event alters the sovereign decision outcome of a release.
    """
    change_id: str = Field(default_factory=lambda: f"dchg-{uuid.uuid4().hex[:8]}")
    tenant_id: str = "default"
    release_id: str
    previous_outcome: ReleaseDecisionOutcome
    new_outcome: ReleaseDecisionOutcome
    trigger_event_id: str
    changed_evidence_ids: List[str] = Field(default_factory=list)
    explanation: str
    timestamp: str

