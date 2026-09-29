"""
PostgreSQL Enterprise Persistence Store Implementation for ORACLE (Brick 4.4)

Provides production-grade multi-worker persistence using psycopg:
- Row-level locking (FOR UPDATE SKIP LOCKED)
- Parameterized SQL statements
- Database-enforced uniqueness constraints
- Full repository implementations matching SQLite interfaces
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.evidence.models import Evidence
from backend.release.connectivity.credentials import GLOBAL_REDACTOR
from backend.investigation.dag import DependencyGraph
from backend.investigation.models import ContradictionRecord, GapStatus, GapType, InformationGap
from backend.release.correlation import CorrelationCluster, EvidenceValidationFailure
from backend.release.events.graph import EvidenceGraph, GraphEdgeType, GraphNodeType
from backend.release.events.lifecycle import EvidenceState
from backend.release.events.models import DecisionChangeEvent, EnterpriseEvent, EnterpriseEventType
from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    GovernedActionType,
    ReleaseAssessment,
    ReleaseCandidate,
    ReleaseDecision,
    ReleaseDecisionOutcome,
    ReleaseRecommendation,
    RiskLevel,
)
from backend.release.investigation import ReleaseInvestigationResult
from backend.release.connectivity.webhooks import WebhookRegistration, WebhookRegistrationStatus
from backend.release.persistence.interfaces import (
    ActionRepository,
    ArtifactDeploymentRepository,
    AuditRepository,
    DecisionLineageRepository,
    DecisionRepository,
    DistributedLockRepository,
    EntityRepository,
    EventRepository,
    EvidenceGraphRepository,
    EvidenceRepository,
    GapRepository,
    IdempotencyRepository,
    InvestigationRepository,
    SecurityRepository,
    WebhookRegistrationRepository,
    WorkerLeaseRepository,
)
from backend.release.security.models import (
    BuildArtifact,
    Deployment,
    RuntimeService,
    SecurityDecision,
    SecurityFinding,
    SecurityImpactAssessment,
    SecurityInvestigation,
    SecurityVerification,
)
from backend.release.persistence.migrator import DatabaseMigrator

logger = logging.getLogger("oracle.persistence.postgres")


class PostgresConnectionPool:
    """Manages PostgreSQL connections via psycopg."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        try:
            import psycopg
            self._psycopg = psycopg
        except ImportError:
            raise ImportError(
                "psycopg is required for Postgres persistence. Install via: pip install 'psycopg[binary]'"
            )

        # Apply migrations on bootstrap connection
        with self.get_connection() as conn:
            DatabaseMigrator(is_postgres=True).apply_postgres_migrations(conn)

    def get_connection(self):
        return self._psycopg.connect(self.dsn, autocommit=True)


class PostgresEventRepository(EventRepository):
    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def append_event(self, event: EnterpriseEvent) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO event_journal (
                        event_id, source, source_event_id, event_type, timestamp, received_at,
                        entity_type, entity_id, repository, commit_hash, release_id,
                        work_item_id, service_id, environment, correlation_keys_json,
                        payload_json, provenance_json, processing_status, attempt_count, correlation_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (event_id) DO UPDATE SET
                        processing_status = EXCLUDED.processing_status,
                        attempt_count = EXCLUDED.attempt_count;
                    """,
                    (
                        event.event_id,
                        event.source,
                        event.source_event_id,
                        event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                        event.timestamp,
                        event.received_at,
                        event.entity_type,
                        event.entity_id,
                        event.repository,
                        event.commit,
                        event.release_id,
                        event.work_item_id,
                        event.service_id,
                        event.environment,
                        json.dumps(event.correlation_keys),
                        json.dumps(GLOBAL_REDACTOR.redact_dict(getattr(event, "payload", {}) or {}) if isinstance(getattr(event, "payload", {}), dict) else getattr(event, "payload", {})),
                        json.dumps(event.provenance),
                        "PENDING",
                        0,
                        event.provenance.get("correlation_id", ""),
                    ),
                )
        return True

    def get_event(self, event_id: str) -> Optional[EnterpriseEvent]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_id, source, source_event_id, event_type, timestamp, received_at,
                           entity_type, entity_id, repository, commit_hash, release_id,
                           work_item_id, service_id, environment, correlation_keys_json,
                           payload_json, provenance_json
                    FROM event_journal WHERE event_id = %s;
                    """,
                    (event_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return self._row_to_event(row)

    def list_events(
        self,
        release_id: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EnterpriseEvent]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                query = (
                    "SELECT event_id, source, source_event_id, event_type, timestamp, received_at, "
                    "entity_type, entity_id, repository, commit_hash, release_id, "
                    "work_item_id, service_id, environment, correlation_keys_json, "
                    "payload_json, provenance_json FROM event_journal WHERE 1=1"
                )
                params: List[Any] = []
                if release_id:
                    query += " AND release_id = %s"
                    params.append(release_id)
                if source:
                    query += " AND source = %s"
                    params.append(source)
                query += " ORDER BY timestamp ASC LIMIT %s OFFSET %s;"
                params.extend([limit, offset])

                cursor.execute(query, tuple(params))
                return [self._row_to_event(r) for r in cursor.fetchall()]

    def get_events_since(
        self,
        since_iso: str,
        release_id: Optional[str] = None,
    ) -> List[EnterpriseEvent]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                query = (
                    "SELECT event_id, source, source_event_id, event_type, timestamp, received_at, "
                    "entity_type, entity_id, repository, commit_hash, release_id, "
                    "work_item_id, service_id, environment, correlation_keys_json, "
                    "payload_json, provenance_json FROM event_journal WHERE timestamp >= %s"
                )
                params: List[Any] = [since_iso]
                if release_id:
                    query += " AND release_id = %s"
                    params.append(release_id)
                query += " ORDER BY timestamp ASC;"
                cursor.execute(query, tuple(params))
                return [self._row_to_event(r) for r in cursor.fetchall()]

    def count_events(self, release_id: Optional[str] = None) -> int:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                if release_id:
                    cursor.execute("SELECT COUNT(*) FROM event_journal WHERE release_id = %s;", (release_id,))
                else:
                    cursor.execute("SELECT COUNT(*) FROM event_journal;")
                row = cursor.fetchone()
                return row[0] if row else 0

    def _row_to_event(self, row: Tuple) -> EnterpriseEvent:
        return EnterpriseEvent(
            event_id=row[0],
            source=row[1],
            source_event_id=row[2],
            event_type=EnterpriseEventType(row[3]) if row[3] in EnterpriseEventType._value2member_map_ else EnterpriseEventType.CODE_PUSHED,
            timestamp=row[4],
            received_at=row[5],
            entity_type=row[6],
            entity_id=row[7],
            repository=row[8],
            commit=row[9],
            release_id=row[10],
            work_item_id=row[11],
            service_id=row[12],
            environment=row[13],
            correlation_keys=json.loads(row[14]) if row[14] else {},
            payload=json.loads(row[15]) if row[15] else {},
            provenance=json.loads(row[16]) if row[16] else {},
        )


class PostgresIdempotencyRepository(IdempotencyRepository):
    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def register_if_absent(
        self,
        idempotency_key: str,
        event_id: str,
        source: str,
        source_event_id: str,
        event_type: str,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                cursor.execute(
                    """
                    INSERT INTO event_idempotency (
                        idempotency_key, event_id, source, source_event_id, event_type, registered_at, ttl_seconds
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING;
                    """,
                    (idempotency_key, event_id, source, source_event_id, event_type, now_iso, ttl_seconds),
                )
                return cursor.rowcount > 0

    def get_registration(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT idempotency_key, event_id, source, source_event_id, event_type, registered_at, ttl_seconds
                    FROM event_idempotency WHERE idempotency_key = %s;
                    """,
                    (idempotency_key,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "idempotency_key": row[0],
                    "event_id": row[1],
                    "source": row[2],
                    "source_event_id": row[3],
                    "event_type": row[4],
                    "registered_at": row[5],
                    "ttl_seconds": row[6],
                }

    def purge_expired(self, current_timestamp_iso: str) -> int:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM event_idempotency WHERE ttl_seconds IS NOT NULL;")
                return cursor.rowcount


class PostgresWorkerLeaseRepository(WorkerLeaseRepository):
    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def create_task(
        self,
        task_id: Optional[str] = None,
        task_type: str = "DEFAULT",
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        tid = task_id or f"task-{uuid.uuid4().hex[:12]}"
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO worker_leases (task_id, task_type, payload_json, status, attempt_count)
                    VALUES (%s, %s, %s, 'PENDING', 0)
                    ON CONFLICT (task_id) DO UPDATE SET
                        task_type = EXCLUDED.task_type,
                        payload_json = EXCLUDED.payload_json,
                        status = 'PENDING';
                    """,
                    (tid, task_type, json.dumps(payload or {})),
                )
        return tid

    def claim_next_task(
        self,
        worker_id: str,
        task_types: Optional[List[str]] = None,
        lease_duration_seconds: int = 30,
    ) -> Optional[Dict[str, Any]]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now = time.time()
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
                lease_until_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + lease_duration_seconds))

                # Reclaim expired leases
                self.reclaim_expired_leases(now_iso)

                query = (
                    "SELECT task_id, task_type, payload_json, attempt_count "
                    "FROM worker_leases "
                    "WHERE status IN ('PENDING', 'RETRYABLE') "
                )
                params: List[Any] = []
                if task_types:
                    placeholders = ",".join("%s" for _ in task_types)
                    query += f"AND task_type IN ({placeholders}) "
                    params.extend(task_types)
                query += "ORDER BY CASE WHEN status = 'PENDING' THEN 1 ELSE 2 END, task_id ASC FOR UPDATE SKIP LOCKED LIMIT 1;"

                cursor.execute(query, tuple(params))
                row = cursor.fetchone()
                if not row:
                    return None

                task_id, task_type, payload_json, attempts = row[0], row[1], row[2], row[3]

                cursor.execute(
                    """
                    UPDATE worker_leases
                    SET worker_id = %s, status = 'CLAIMED', claimed_at = %s, lease_until = %s,
                        heartbeat_at = %s, attempt_count = attempt_count + 1
                    WHERE task_id = %s;
                    """,
                    (worker_id, now_iso, lease_until_iso, now_iso, task_id),
                )
                return {
                    "task_id": task_id,
                    "task_type": task_type,
                    "payload": json.loads(payload_json) if payload_json else {},
                    "attempt_count": attempts + 1,
                    "worker_id": worker_id,
                    "lease_until": lease_until_iso,
                }

    def heartbeat_lease(self, task_id: str, worker_id: str, extension_seconds: int = 30) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now = time.time()
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
                lease_until_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + extension_seconds))
                cursor.execute(
                    """
                    UPDATE worker_leases
                    SET heartbeat_at = %s, lease_until = %s
                    WHERE task_id = %s AND worker_id = %s AND status IN ('CLAIMED', 'RUNNING');
                    """,
                    (now_iso, lease_until_iso, task_id, worker_id),
                )
                return cursor.rowcount > 0

    def complete_task(self, task_id: str, worker_id: str, result_payload: Optional[Dict[str, Any]] = None) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                cursor.execute(
                    """
                    UPDATE worker_leases
                    SET status = 'SUCCEEDED', completed_at = %s, result_json = %s
                    WHERE task_id = %s AND worker_id = %s;
                    """,
                    (now_iso, json.dumps(result_payload or {}), task_id, worker_id),
                )
                return cursor.rowcount > 0

    def fail_task(self, task_id: str, worker_id: str, error_message: str, retryable: bool = True, max_retries: int = 3) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT attempt_count FROM worker_leases WHERE task_id = %s;", (task_id,))
                row = cursor.fetchone()
                attempts = row[0] if row else 1
                next_status = "RETRYABLE" if (retryable and attempts < max_retries) else "FAILED"
                cursor.execute(
                    """
                    UPDATE worker_leases
                    SET status = %s, result_json = %s
                    WHERE task_id = %s AND worker_id = %s;
                    """,
                    (next_status, json.dumps({"error": error_message}), task_id, worker_id),
                )
                return cursor.rowcount > 0

    def reclaim_expired_leases(self, now_iso: str) -> int:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE worker_leases
                    SET status = 'RETRYABLE', worker_id = NULL
                    WHERE status IN ('CLAIMED', 'RUNNING') AND lease_until < %s;
                    """,
                    (now_iso,),
                )
                return cursor.rowcount

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT task_id, task_type, payload_json, worker_id, status, attempt_count,
                           claimed_at, lease_until, heartbeat_at, completed_at, result_json
                    FROM worker_leases WHERE task_id = %s;
                    """,
                    (task_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "task_id": row[0],
                    "task_type": row[1],
                    "payload": json.loads(row[2]) if row[2] else {},
                    "worker_id": row[3],
                    "status": row[4],
                    "attempt_count": row[5],
                    "claimed_at": row[6],
                    "lease_until": row[7],
                    "heartbeat_at": row[8],
                    "completed_at": row[9],
                    "result": json.loads(row[10]) if row[10] else None,
                }


class PostgresWebhookRegistrationRepository(WebhookRegistrationRepository):
    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def save_registration(self, registration: WebhookRegistration) -> None:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                status_val = registration.status.value if hasattr(registration.status, "value") else str(registration.status)
                cursor.execute(
                    """
                    INSERT INTO webhook_registrations (
                        registration_id, tenant_id, provider, external_registration_id,
                        target_entity, callback_url, secret_token, event_types_json,
                        status, created_at, updated_at, last_verified_at, provenance_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (registration_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        updated_at = EXCLUDED.updated_at,
                        last_verified_at = EXCLUDED.last_verified_at,
                        provenance_json = EXCLUDED.provenance_json;
                    """,
                    (
                        registration.registration_id,
                        getattr(registration, "tenant_id", "default") or "default",
                        registration.provider,
                        registration.external_registration_id,
                        registration.target_entity,
                        registration.callback_url,
                        registration.secret_token,
                        json.dumps(registration.event_types),
                        status_val,
                        registration.created_at or now_iso,
                        registration.updated_at or now_iso,
                        registration.last_verified_at,
                        json.dumps(registration.provenance or {}),
                    ),
                )

    def get_registration(self, registration_id: str, tenant_id: str = "default") -> Optional[WebhookRegistration]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT registration_id, tenant_id, provider, external_registration_id,
                           target_entity, callback_url, secret_token, event_types_json,
                           status, created_at, updated_at, last_verified_at, provenance_json
                    FROM webhook_registrations
                    WHERE registration_id = %s AND tenant_id = %s;
                    """,
                    (registration_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return self._row_to_registration(row)

    def list_registrations(
        self,
        tenant_id: str = "default",
        provider: Optional[str] = None,
        target_entity: Optional[str] = None,
    ) -> List[WebhookRegistration]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                query = (
                    "SELECT registration_id, tenant_id, provider, external_registration_id, "
                    "target_entity, callback_url, secret_token, event_types_json, "
                    "status, created_at, updated_at, last_verified_at, provenance_json "
                    "FROM webhook_registrations WHERE tenant_id = %s"
                )
                params: List[Any] = [tenant_id]
                if provider:
                    query += " AND provider = %s"
                    params.append(provider)
                if target_entity:
                    query += " AND target_entity = %s"
                    params.append(target_entity)
                query += " ORDER BY created_at DESC;"
                cursor.execute(query, tuple(params))
                return [self._row_to_registration(r) for r in cursor.fetchall()]

    def delete_registration(self, registration_id: str, tenant_id: str = "default") -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM webhook_registrations WHERE registration_id = %s AND tenant_id = %s;",
                    (registration_id, tenant_id),
                )
                return cursor.rowcount > 0

    def _row_to_registration(self, row: Tuple) -> WebhookRegistration:
        return WebhookRegistration(
            registration_id=row[0],
            tenant_id=row[1],
            provider=row[2],
            external_registration_id=row[3],
            target_entity=row[4],
            callback_url=row[5],
            secret_token=row[6],
            event_types=json.loads(row[7]) if row[7] else [],
            status=WebhookRegistrationStatus(row[8]) if row[8] in WebhookRegistrationStatus._value2member_map_ else WebhookRegistrationStatus.REGISTERED,
            created_at=row[9],
            updated_at=row[10],
            last_verified_at=row[11],
            provenance=json.loads(row[12]) if row[12] else {},
        )


class PostgresDistributedLockRepository(DistributedLockRepository):
    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def acquire_lock(
        self,
        lock_key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[Tuple[int, float]]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now = time.time()
                expires_at = now + ttl_seconds
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                cursor.execute(
                    "SELECT owner, fencing_token, expires_at FROM distributed_locks WHERE lock_key = %s AND tenant_id = %s FOR UPDATE;",
                    (lock_key, tenant_id),
                )
                row = cursor.fetchone()
                if row:
                    current_owner, current_token, current_expires = row[0], int(row[1]), float(row[2])
                    if current_expires > now and current_owner:
                        if current_owner == owner:
                            cursor.execute(
                                "UPDATE distributed_locks SET expires_at = %s, acquired_at = %s WHERE lock_key = %s AND tenant_id = %s;",
                                (expires_at, now_iso, lock_key, tenant_id),
                            )
                            return (current_token, expires_at)
                        return None
                    new_token = current_token + 1
                else:
                    new_token = 1

                cursor.execute(
                    """
                    INSERT INTO distributed_locks (
                        lock_key, tenant_id, owner, fencing_token, acquired_at, expires_at, metadata_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (lock_key) DO UPDATE SET
                        owner = EXCLUDED.owner,
                        fencing_token = EXCLUDED.fencing_token,
                        acquired_at = EXCLUDED.acquired_at,
                        expires_at = EXCLUDED.expires_at;
                    """,
                    (lock_key, tenant_id, owner, new_token, now_iso, expires_at, "{}"),
                )
                return (new_token, expires_at)

    def renew_lock(
        self,
        lock_key: str,
        owner: str,
        fencing_token: int,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                now = time.time()
                new_expires = now + ttl_seconds
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                cursor.execute(
                    """
                    UPDATE distributed_locks
                    SET expires_at = %s, acquired_at = %s
                    WHERE lock_key = %s AND tenant_id = %s AND owner = %s AND fencing_token = %s AND expires_at > %s;
                    """,
                    (new_expires, now_iso, lock_key, tenant_id, owner, fencing_token, now),
                )
                return cursor.rowcount > 0

    def release_lock(
        self,
        lock_key: str,
        owner: str,
        fencing_token: int,
        tenant_id: str = "default",
    ) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE distributed_locks SET owner = '', expires_at = 0 WHERE lock_key = %s AND tenant_id = %s AND owner = %s AND fencing_token = %s;",
                    (lock_key, tenant_id, owner, fencing_token),
                )
                return cursor.rowcount > 0

    def get_lock(self, lock_key: str, tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT lock_key, tenant_id, owner, fencing_token, acquired_at, expires_at, metadata_json
                    FROM distributed_locks
                    WHERE lock_key = %s AND tenant_id = %s;
                    """,
                    (lock_key, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "lock_key": row[0],
                    "tenant_id": row[1],
                    "owner": row[2],
                    "fencing_token": row[3],
                    "acquired_at": row[4],
                    "expires_at": row[5],
                    "metadata": json.loads(row[6]) if row[6] else {},
                }


# -----------------------------------------------------------------------------
# 14. POSTGRES SECURITY REPOSITORY (Brick 4.8)
# -----------------------------------------------------------------------------

class PostgresSecurityRepository(SecurityRepository):
    """PostgreSQL implementation of authoritative security intelligence repository."""

    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def save_finding(self, finding: SecurityFinding) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = finding.model_dump_json() if hasattr(finding, "model_dump_json") else json.dumps(finding)
                cursor.execute(
                    """
                    INSERT INTO security_findings (
                        finding_id, tenant_id, repository, commit_hash, artifact_digest, severity, category, status, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        severity = EXCLUDED.severity,
                        artifact_digest = EXCLUDED.artifact_digest,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        finding.finding_id,
                        getattr(finding, "tenant_id", "default"),
                        finding.repository,
                        finding.commit,
                        getattr(finding, "artifact_digest", None),
                        getattr(finding.severity, "value", str(finding.severity)),
                        getattr(finding.category, "value", str(finding.category)),
                        getattr(finding.status, "value", str(finding.status)),
                        payload,
                    ),
                )
                return True

    def get_finding(self, finding_id: str, tenant_id: str = "default") -> Optional[SecurityFinding]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM security_findings WHERE finding_id = %s AND tenant_id = %s;",
                    (finding_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return SecurityFinding.model_validate_json(row[0])

    def list_findings(
        self,
        repository: Optional[str] = None,
        commit: Optional[str] = None,
        artifact_digest: Optional[str] = None,
        tenant_id: str = "default",
    ) -> List[SecurityFinding]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                clauses = ["tenant_id = %s"]
                params: List[Any] = [tenant_id]
                if repository:
                    clauses.append("repository = %s")
                    params.append(repository)
                if commit:
                    clauses.append("commit_hash = %s")
                    params.append(commit)
                if artifact_digest:
                    clauses.append("artifact_digest = %s")
                    params.append(artifact_digest)
                where_stmt = " AND ".join(clauses)
                cursor.execute(f"SELECT payload_json FROM security_findings WHERE {where_stmt};", tuple(params))
                return [SecurityFinding.model_validate_json(row[0]) for row in cursor.fetchall()]

    def save_impact_assessment(self, assessment: SecurityImpactAssessment) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = assessment.model_dump_json() if hasattr(assessment, "model_dump_json") else json.dumps(assessment)
                cursor.execute(
                    """
                    INSERT INTO security_impact_assessments (
                        assessment_id, finding_id, tenant_id, repository, commit_hash, artifact_digest, impact_level, business_impact, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(assessment_id) DO UPDATE SET
                        impact_level = EXCLUDED.impact_level,
                        business_impact = EXCLUDED.business_impact,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        assessment.assessment_id,
                        assessment.finding_id,
                        getattr(assessment, "tenant_id", "default"),
                        assessment.repository,
                        assessment.commit,
                        getattr(assessment, "artifact_digest", None),
                        getattr(assessment.impact_level, "value", str(assessment.impact_level)),
                        getattr(assessment.business_impact, "value", str(assessment.business_impact)),
                        payload,
                    ),
                )
                return True

    def get_impact_assessment(self, assessment_id: str, tenant_id: str = "default") -> Optional[SecurityImpactAssessment]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM security_impact_assessments WHERE assessment_id = %s AND tenant_id = %s;",
                    (assessment_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return SecurityImpactAssessment.model_validate_json(row[0])

    def save_investigation(self, investigation: SecurityInvestigation) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = investigation.model_dump_json() if hasattr(investigation, "model_dump_json") else json.dumps(investigation)
                dec_outcome = investigation.decision.outcome.value if investigation.decision else "SECURITY_UNKNOWN"
                cursor.execute(
                    """
                    INSERT INTO security_investigations (
                        investigation_id, tenant_id, repository, commit_hash, artifact_digest, decision_outcome, created_at, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(investigation_id) DO UPDATE SET
                        decision_outcome = EXCLUDED.decision_outcome,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        investigation.investigation_id,
                        investigation.tenant_id,
                        investigation.repository,
                        investigation.commit,
                        investigation.artifact_digest,
                        dec_outcome,
                        investigation.created_at,
                        payload,
                    ),
                )
                return True

    def get_investigation(self, investigation_id: str, tenant_id: str = "default") -> Optional[SecurityInvestigation]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM security_investigations WHERE investigation_id = %s AND tenant_id = %s;",
                    (investigation_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return SecurityInvestigation.model_validate_json(row[0])

    def save_decision(self, decision: SecurityDecision) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = decision.model_dump_json() if hasattr(decision, "model_dump_json") else json.dumps(decision)
                cursor.execute(
                    """
                    INSERT INTO security_decisions (
                        decision_id, tenant_id, repository, commit_hash, artifact_digest, outcome, risk_level, created_at, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(decision_id) DO UPDATE SET
                        outcome = EXCLUDED.outcome,
                        risk_level = EXCLUDED.risk_level,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        decision.decision_id,
                        decision.tenant_id,
                        decision.repository,
                        decision.commit,
                        decision.artifact_digest,
                        decision.outcome.value,
                        decision.risk_level.value,
                        decision.timestamp,
                        payload,
                    ),
                )
                return True

    def get_decision(self, decision_id: str, tenant_id: str = "default") -> Optional[SecurityDecision]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM security_decisions WHERE decision_id = %s AND tenant_id = %s;",
                    (decision_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return SecurityDecision.model_validate_json(row[0])

    def save_verification(self, verification: SecurityVerification) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = verification.model_dump_json() if hasattr(verification, "model_dump_json") else json.dumps(verification)
                cursor.execute(
                    """
                    INSERT INTO security_verifications (
                        verification_id, finding_id, tenant_id, rescan_commit, rescan_artifact_digest, status, verified_at, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(verification_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        verification.verification_id,
                        verification.finding_id,
                        verification.tenant_id,
                        verification.rescan_commit,
                        verification.rescan_artifact_digest,
                        verification.status.value,
                        verification.verified_at,
                        payload,
                    ),
                )
                return True

    def get_verification(self, verification_id: str, tenant_id: str = "default") -> Optional[SecurityVerification]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM security_verifications WHERE verification_id = %s AND tenant_id = %s;",
                    (verification_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return SecurityVerification.model_validate_json(row[0])


# -----------------------------------------------------------------------------
# 15. POSTGRES ARTIFACT & DEPLOYMENT REPOSITORY (Brick 4.8)
# -----------------------------------------------------------------------------

class PostgresArtifactDeploymentRepository(ArtifactDeploymentRepository):
    """PostgreSQL implementation of exact artifact and deployment repository."""

    def __init__(self, pool: PostgresConnectionPool):
        self.pool = pool

    def save_artifact(self, artifact: BuildArtifact) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = artifact.model_dump_json() if hasattr(artifact, "model_dump_json") else json.dumps(artifact)
                cursor.execute(
                    """
                    INSERT INTO build_artifacts (
                        artifact_digest, tenant_id, artifact_id, artifact_name, repository, commit_hash, build_id, built_at, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(artifact_digest) DO UPDATE SET
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        artifact.artifact_digest,
                        artifact.tenant_id,
                        artifact.artifact_id,
                        artifact.artifact_name,
                        artifact.repository,
                        artifact.commit,
                        artifact.build_id,
                        artifact.built_at,
                        payload,
                    ),
                )
                return True

    def get_artifact(self, artifact_digest: str, tenant_id: str = "default") -> Optional[BuildArtifact]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM build_artifacts WHERE artifact_digest = %s AND tenant_id = %s;",
                    (artifact_digest, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return BuildArtifact.model_validate_json(row[0])

    def save_deployment(self, deployment: Deployment) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = deployment.model_dump_json() if hasattr(deployment, "model_dump_json") else json.dumps(deployment)
                cursor.execute(
                    """
                    INSERT INTO deployments (
                        deployment_id, tenant_id, service_id, environment, artifact_digest, commit_hash, deployed_at, status, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(deployment_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        deployment.deployment_id,
                        deployment.tenant_id,
                        deployment.service_id,
                        getattr(deployment.environment, "value", str(deployment.environment)),
                        deployment.artifact_digest,
                        deployment.commit,
                        deployment.deployed_at,
                        deployment.status,
                        payload,
                    ),
                )
                return True

    def get_deployment(self, deployment_id: str, tenant_id: str = "default") -> Optional[Deployment]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM deployments WHERE deployment_id = %s AND tenant_id = %s;",
                    (deployment_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return Deployment.model_validate_json(row[0])

    def list_deployments(
        self,
        service_id: Optional[str] = None,
        environment: Optional[str] = None,
        tenant_id: str = "default",
    ) -> List[Deployment]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                clauses = ["tenant_id = %s"]
                params: List[Any] = [tenant_id]
                if service_id:
                    clauses.append("service_id = %s")
                    params.append(service_id)
                if environment:
                    clauses.append("environment = %s")
                    params.append(environment)
                where_stmt = " AND ".join(clauses)
                cursor.execute(f"SELECT payload_json FROM deployments WHERE {where_stmt};", tuple(params))
                return [Deployment.model_validate_json(row[0]) for row in cursor.fetchall()]

    def save_runtime_service(self, service: RuntimeService) -> bool:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                payload = service.model_dump_json() if hasattr(service, "model_dump_json") else json.dumps(service)
                cursor.execute(
                    """
                    INSERT INTO runtime_services (
                        service_id, tenant_id, service_name, environment, exposure, auth_required, payload_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(service_id) DO UPDATE SET
                        exposure = EXCLUDED.exposure,
                        auth_required = EXCLUDED.auth_required,
                        payload_json = EXCLUDED.payload_json;
                    """,
                    (
                        service.service_id,
                        service.tenant_id,
                        service.service_name,
                        getattr(service.environment, "value", str(service.environment)),
                        getattr(service.exposure, "value", str(service.exposure)),
                        getattr(service.auth_required, "value", str(service.auth_required)),
                        payload,
                    ),
                )
                return True

    def get_runtime_service(self, service_id: str, tenant_id: str = "default") -> Optional[RuntimeService]:
        with self.pool.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT payload_json FROM runtime_services WHERE service_id = %s AND tenant_id = %s;",
                    (service_id, tenant_id),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return RuntimeService.model_validate_json(row[0])
