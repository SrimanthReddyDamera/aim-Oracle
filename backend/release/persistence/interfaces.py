"""
Provider-Neutral Persistence Interfaces for ORACLE (Brick 4.4)

Defines authoritative abstract repositories for enterprise state:
- EventRepository (Durable Event Journal)
- IdempotencyRepository (Atomic DB-enforced deduplication)
- InvestigationRepository (Investigation lifecycle & state re-hydration)
- GapRepository (Information gap state machine & DAG cascade persistence)
- EvidenceRepository (Evidence store & lifecycle history)
- DecisionRepository (Authoritative decision persistence)
- DecisionLineageRepository (Decision timeline & explainability)
- ActionRepository (Governed action proposals, executions & reconciliation)
- WorkerLeaseRepository (Distributed task leases, heartbeats & crash recovery)
- EvidenceGraphRepository (Temporal projection of the EvidenceGraph)
- AuditRepository (Append-only audit journal)
- EntityRepository (Deterministic entity mappings)
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Tuple

from backend.evidence.models import Evidence
from backend.investigation.models import ContradictionRecord, GapStatus, InformationGap
from backend.release.events.graph import EvidenceGraph
from backend.release.events.lifecycle import EvidenceState
from backend.release.events.models import DecisionChangeEvent, EnterpriseEvent
from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    ReleaseAssessment,
    ReleaseCandidate,
    ReleaseDecision,
)
from backend.release.investigation import ReleaseInvestigationResult


# -----------------------------------------------------------------------------
# 1. EVENT REPOSITORY (DURABLE EVENT JOURNAL)
# -----------------------------------------------------------------------------

class EventRepository(abc.ABC):
    """Authoritative durable repository for the enterprise event journal."""

    @abc.abstractmethod
    def append_event(self, event: EnterpriseEvent) -> bool:
        """Append an accepted canonical event to the durable journal."""
        pass

    @abc.abstractmethod
    def get_event(self, event_id: str) -> Optional[EnterpriseEvent]:
        """Fetch an event by its unique identifier."""
        pass

    @abc.abstractmethod
    def list_events(
        self,
        release_id: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EnterpriseEvent]:
        """List events in chronological order with optional filtering."""
        pass

    @abc.abstractmethod
    def get_events_since(
        self,
        since_iso: str,
        release_id: Optional[str] = None,
    ) -> List[EnterpriseEvent]:
        """Fetch events received or created after a specified timestamp."""
        pass

    @abc.abstractmethod
    def count_events(self, release_id: Optional[str] = None) -> int:
        """Return total count of journaled events."""
        pass


# -----------------------------------------------------------------------------
# 2. IDEMPOTENCY REPOSITORY (DATABASE-ENFORCED DEDUPLICATION)
# -----------------------------------------------------------------------------

class IdempotencyRepository(abc.ABC):
    """Durable idempotency registration enforced by DB uniqueness constraints."""

    @abc.abstractmethod
    def register_if_absent(
        self,
        idempotency_key: str,
        event_id: str,
        source: str,
        source_event_id: str,
        event_type: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """
        Atomically register an event identity key if absent.
        Returns True if newly registered, False if already registered (duplicate suppressed).
        """
        pass

    @abc.abstractmethod
    def get_registration(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve idempotency registration details."""
        pass

    @abc.abstractmethod
    def purge_expired(self, current_timestamp_iso: str) -> int:
        """Purge idempotency keys past their TTL."""
        pass


# -----------------------------------------------------------------------------
# 3. INVESTIGATION & ASSESSMENT REPOSITORY
# -----------------------------------------------------------------------------

class InvestigationRepository(abc.ABC):
    """Persists complete investigation and assessment state across process restarts."""

    @abc.abstractmethod
    def save_investigation(self, result: ReleaseInvestigationResult) -> None:
        """Save investigation state, candidate binding, and telemetry."""
        pass

    @abc.abstractmethod
    def get_investigation(self, investigation_id: str) -> Optional[ReleaseInvestigationResult]:
        """Reconstruct full investigation result from durable storage."""
        pass

    @abc.abstractmethod
    def get_latest_investigation_for_release(
        self, release_id: str
    ) -> Optional[ReleaseInvestigationResult]:
        """Retrieve the latest investigation for a given release."""
        pass

    @abc.abstractmethod
    def list_investigations(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List investigation summaries."""
        pass

    @abc.abstractmethod
    def save_assessment(self, assessment: ReleaseAssessment) -> None:
        """Save a top-level release assessment container."""
        pass

    @abc.abstractmethod
    def get_assessment(self, release_id: str) -> Optional[ReleaseAssessment]:
        """Reconstruct latest release assessment for a release."""
        pass

    @abc.abstractmethod
    def get_all_assessments(self) -> Dict[str, ReleaseAssessment]:
        """Retrieve all current release assessments."""
        pass


# -----------------------------------------------------------------------------
# 4. GAP REPOSITORY
# -----------------------------------------------------------------------------

class GapRepository(abc.ABC):
    """Persists individual gap state machines and resolution evidence."""

    @abc.abstractmethod
    def save_gaps(self, investigation_id: str, gaps: List[InformationGap]) -> None:
        """Persist or update gaps for an investigation."""
        pass

    @abc.abstractmethod
    def get_gaps(self, investigation_id: str) -> List[InformationGap]:
        """Load all gaps for an investigation."""
        pass

    @abc.abstractmethod
    def update_gap_status(
        self,
        investigation_id: str,
        gap_id: str,
        status: GapStatus,
        resolution: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> None:
        """Update single gap state and resolution."""
        pass


# -----------------------------------------------------------------------------
# 5. EVIDENCE REPOSITORY & LIFECYCLE
# -----------------------------------------------------------------------------

class EvidenceRepository(abc.ABC):
    """Persists evidence items and their full transition history."""

    @abc.abstractmethod
    def save_evidence(
        self,
        evidence: Evidence,
        investigation_id: Optional[str] = None,
        state: EvidenceState = EvidenceState.VALID,
    ) -> None:
        """Persist or update an evidence item."""
        pass

    @abc.abstractmethod
    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Fetch evidence by its ID."""
        pass

    @abc.abstractmethod
    def list_evidence_for_investigation(self, investigation_id: str) -> List[Evidence]:
        """List all admitted evidence items associated with an investigation."""
        pass

    @abc.abstractmethod
    def update_evidence_state(
        self,
        evidence_id: str,
        state: EvidenceState,
        reason: str,
        superseded_by: Optional[str] = None,
        causal_event_id: Optional[str] = None,
    ) -> None:
        """Transition evidence lifecycle state and append to immutable transition log."""
        pass

    @abc.abstractmethod
    def get_evidence_lifecycle_history(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Retrieve chronological lifecycle transitions for an evidence item."""
        pass

    @abc.abstractmethod
    def find_expired_evidence(self, now_iso: str) -> List[Evidence]:
        """Find active evidence items whose validity window has expired."""
        pass


# -----------------------------------------------------------------------------
# 6. DECISION & DECISION LINEAGE REPOSITORIES
# -----------------------------------------------------------------------------

class DecisionRepository(abc.ABC):
    """Persists authoritative release readiness decisions."""

    @abc.abstractmethod
    def save_decision(self, decision: ReleaseDecision) -> None:
        """Persist an authoritative decision."""
        pass

    @abc.abstractmethod
    def get_latest_decision(self, release_id: str) -> Optional[ReleaseDecision]:
        """Retrieve the latest authoritative decision for a release."""
        pass

    @abc.abstractmethod
    def get_decision_history(self, release_id: str) -> List[ReleaseDecision]:
        """Retrieve chronological decision history for a release."""
        pass


class DecisionLineageRepository(abc.ABC):
    """Persists decision transition events and causal explanations."""

    @abc.abstractmethod
    def record_transition(self, release_id: str, change_event: DecisionChangeEvent) -> None:
        """Record an outcome transition event."""
        pass

    @abc.abstractmethod
    def get_lineage(self, release_id: str) -> List[DecisionChangeEvent]:
        """Retrieve complete transition lineage for a release."""
        pass

    @abc.abstractmethod
    def get_latest_transition(self, release_id: str) -> Optional[DecisionChangeEvent]:
        """Retrieve most recent transition event."""
        pass


# -----------------------------------------------------------------------------
# 7. GOVERNED ACTION REPOSITORY
# -----------------------------------------------------------------------------

class ActionRepository(abc.ABC):
    """Persists governed action proposals, authorizations, executions, and reconciliation."""

    @abc.abstractmethod
    def save_action(self, action: GovernedActionProposal) -> None:
        """Save or update a governed action proposal."""
        pass

    @abc.abstractmethod
    def get_action(self, action_id: str) -> Optional[GovernedActionProposal]:
        """Retrieve action proposal by ID."""
        pass

    @abc.abstractmethod
    def update_action_status(
        self,
        action_id: str,
        status: GovernedActionStatus,
        audit_entry: str,
        authorized_by: Optional[str] = None,
        execution_timestamp: Optional[str] = None,
    ) -> None:
        """Update action state and append to its audit trail."""
        pass

    @abc.abstractmethod
    def record_action_execution(
        self,
        idempotency_key: str,
        action_id: str,
        result_payload: Dict[str, Any],
    ) -> bool:
        """Record successful execution result atomically by idempotency key."""
        pass

    @abc.abstractmethod
    def get_action_execution(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Check if action idempotency key was previously executed."""
        pass

    @abc.abstractmethod
    def list_actions(
        self,
        release_id: Optional[str] = None,
        status: Optional[GovernedActionStatus] = None,
    ) -> List[GovernedActionProposal]:
        """List governed actions with optional filters."""
        pass


# -----------------------------------------------------------------------------
# 8. WORKER LEASE REPOSITORY
# -----------------------------------------------------------------------------

class WorkerLeaseRepository(abc.ABC):
    """Distributed task claim, lease heartbeat, and dead-worker recovery."""

    @abc.abstractmethod
    def create_task(
        self,
        task_id: str,
        task_type: str,
        payload: Dict[str, Any],
    ) -> str:
        """Enqueue a new task in PENDING status."""
        pass

    @abc.abstractmethod
    def claim_next_task(
        self,
        worker_id: str,
        task_types: Optional[List[str]] = None,
        lease_duration_seconds: int = 30,
    ) -> Optional[Dict[str, Any]]:
        """
        Atomically claim next available pending or retryable task.
        Also reclaims expired leases.
        """
        pass

    @abc.abstractmethod
    def heartbeat_lease(
        self,
        task_id: str,
        worker_id: str,
        extension_seconds: int = 30,
    ) -> bool:
        """Extend lease duration for an active worker."""
        pass

    @abc.abstractmethod
    def complete_task(
        self,
        task_id: str,
        worker_id: str,
        result_payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Mark task as SUCCEEDED."""
        pass

    @abc.abstractmethod
    def fail_task(
        self,
        task_id: str,
        worker_id: str,
        error_message: str,
        retryable: bool = True,
        max_retries: int = 3,
    ) -> bool:
        """Mark task as RETRYABLE (or FAILED if retries exhausted)."""
        pass

    @abc.abstractmethod
    def reclaim_expired_leases(self, now_iso: str) -> int:
        """Reset expired claims back to RETRYABLE."""
        pass

    @abc.abstractmethod
    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task details and status."""
        pass


# -----------------------------------------------------------------------------
# 9. EVIDENCE GRAPH REPOSITORY (TEMPORAL PROJECTION)
# -----------------------------------------------------------------------------

class EvidenceGraphRepository(abc.ABC):
    """Persists EvidenceGraph topology with temporal validity intervals."""

    @abc.abstractmethod
    def save_node(
        self,
        node_id: str,
        node_type: str,
        properties: Dict[str, Any],
        valid_from: str,
        valid_until: Optional[str] = None,
        is_active: bool = True,
    ) -> None:
        """Persist or update graph node with temporal validity."""
        pass

    @abc.abstractmethod
    def save_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        properties: Dict[str, Any],
        valid_from: str,
        valid_until: Optional[str] = None,
        is_active: bool = True,
    ) -> None:
        """Persist or update graph edge with temporal validity."""
        pass

    @abc.abstractmethod
    def get_graph_snapshot(self, as_of_iso: Optional[str] = None) -> EvidenceGraph:
        """
        Reconstruct EvidenceGraph as it existed at time T.
        If as_of_iso is None, returns current active graph.
        """
        pass

    @abc.abstractmethod
    def get_node_history(self, node_id: str) -> List[Dict[str, Any]]:
        """Retrieve temporal version history for a graph node."""
        pass


# -----------------------------------------------------------------------------
# 10. AUDIT REPOSITORY
# -----------------------------------------------------------------------------

class AuditRepository(abc.ABC):
    """Append-only audit journal."""

    @abc.abstractmethod
    def record_audit(
        self,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Dict[str, Any],
        correlation_id: Optional[str] = None,
    ) -> str:
        """Record an immutable audit entry."""
        pass

    @abc.abstractmethod
    def query_audit(
        self,
        entity_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query audit log entries."""
        pass


# -----------------------------------------------------------------------------
# 11. ENTITY REPOSITORY
# -----------------------------------------------------------------------------

class EntityRepository(abc.ABC):
    """Stores deterministic entity candidate definitions and mappings."""

    @abc.abstractmethod
    def save_candidate(self, candidate: ReleaseCandidate) -> None:
        """Persist or update a registered release candidate."""
        pass

    @abc.abstractmethod
    def get_candidate(self, release_id: str) -> Optional[ReleaseCandidate]:
        """Fetch candidate by release_id."""
        pass

    @abc.abstractmethod
    def list_candidates(self) -> List[ReleaseCandidate]:
        """List all registered release candidates."""
        pass


# -----------------------------------------------------------------------------
# 12. WEBHOOK REGISTRATION REPOSITORY (Brick 4.5)
# -----------------------------------------------------------------------------

class WebhookRegistrationRepository(abc.ABC):
    """Stores and retrieves external webhook registrations."""

    @abc.abstractmethod
    def save_registration(self, registration: Any) -> None:
        """Persist or update a webhook registration."""
        pass

    @abc.abstractmethod
    def get_registration(self, registration_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch registration by ID."""
        pass

    @abc.abstractmethod
    def list_registrations(
        self,
        tenant_id: str = "default",
        provider: Optional[str] = None,
        target_entity: Optional[str] = None,
    ) -> List[Any]:
        """List active or all webhook registrations."""
        pass

    @abc.abstractmethod
    def delete_registration(self, registration_id: str, tenant_id: str = "default") -> bool:
        """Remove a webhook registration."""
        pass


# -----------------------------------------------------------------------------
# 13. DISTRIBUTED LOCK REPOSITORY (Brick 4.5)
# -----------------------------------------------------------------------------

class DistributedLockRepository(abc.ABC):
    """Database-backed distributed locking with monotonic fencing tokens."""

    @abc.abstractmethod
    def acquire_lock(
        self,
        lock_key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[Tuple[int, float]]:
        """
        Attempt to acquire distributed lock.
        Returns (fencing_token, expires_at) if acquired, None if locked by active owner.
        """
        pass

    @abc.abstractmethod
    def renew_lock(
        self,
        lock_key: str,
        owner: str,
        fencing_token: int,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> bool:
        """Renew active lock before expiration."""
        pass

    @abc.abstractmethod
    def release_lock(
        self,
        lock_key: str,
        owner: str,
        fencing_token: int,
        tenant_id: str = "default",
    ) -> bool:
        """Safely release lock if owner and fencing token match."""
        pass

    @abc.abstractmethod
    def get_lock(self, lock_key: str, tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        """Retrieve current lock status and metadata."""
        pass


# -----------------------------------------------------------------------------
# 14. SECURITY INTELLIGENCE REPOSITORY (Brick 4.8)
# -----------------------------------------------------------------------------

class SecurityRepository(abc.ABC):
    """Authoritative durable repository for security intelligence findings, impacts, and decisions."""

    @abc.abstractmethod
    def save_finding(self, finding: Any) -> bool:
        """Persist or update a normalized security finding."""
        pass

    @abc.abstractmethod
    def get_finding(self, finding_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch a security finding by its unique ID."""
        pass

    @abc.abstractmethod
    def list_findings(
        self,
        repository: Optional[str] = None,
        commit: Optional[str] = None,
        artifact_digest: Optional[str] = None,
        tenant_id: str = "default",
    ) -> List[Any]:
        """List findings matching repository, commit, or artifact filters."""
        pass

    @abc.abstractmethod
    def save_impact_assessment(self, assessment: Any) -> bool:
        """Persist a multi-dimensional security impact assessment."""
        pass

    @abc.abstractmethod
    def get_impact_assessment(self, assessment_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch impact assessment by ID."""
        pass

    @abc.abstractmethod
    def save_investigation(self, investigation: Any) -> bool:
        """Persist full security investigation aggregate."""
        pass

    @abc.abstractmethod
    def get_investigation(self, investigation_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch security investigation by ID."""
        pass

    @abc.abstractmethod
    def save_decision(self, decision: Any) -> bool:
        """Persist security clearance decision."""
        pass

    @abc.abstractmethod
    def get_decision(self, decision_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch security decision by ID."""
        pass

    @abc.abstractmethod
    def save_verification(self, verification: Any) -> bool:
        """Persist closed-loop verification record."""
        pass

    @abc.abstractmethod
    def get_verification(self, verification_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch verification by ID."""
        pass


# -----------------------------------------------------------------------------
# 15. ARTIFACT & DEPLOYMENT REPOSITORY (Brick 4.8)
# -----------------------------------------------------------------------------

class ArtifactDeploymentRepository(abc.ABC):
    """Authoritative durable repository for exact artifacts, deployments, and runtime services."""

    @abc.abstractmethod
    def save_artifact(self, artifact: Any) -> bool:
        """Persist or update build artifact."""
        pass

    @abc.abstractmethod
    def get_artifact(self, artifact_digest: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch build artifact by cryptographic digest."""
        pass

    @abc.abstractmethod
    def save_deployment(self, deployment: Any) -> bool:
        """Persist or update deployment record."""
        pass

    @abc.abstractmethod
    def get_deployment(self, deployment_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch deployment by ID."""
        pass

    @abc.abstractmethod
    def list_deployments(
        self,
        service_id: Optional[str] = None,
        environment: Optional[str] = None,
        tenant_id: str = "default",
    ) -> List[Any]:
        """List deployments matching service and environment filters."""
        pass

    @abc.abstractmethod
    def save_runtime_service(self, service: Any) -> bool:
        """Persist or update runtime service definition."""
        pass

    @abc.abstractmethod
    def get_runtime_service(self, service_id: str, tenant_id: str = "default") -> Optional[Any]:
        """Fetch runtime service by ID."""
        pass

