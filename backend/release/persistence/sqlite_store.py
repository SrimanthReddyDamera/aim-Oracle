"""
SQLite ACID Relational Store Implementation for ORACLE (Brick 4.4)

Provides thread-safe, WAL-enabled, foreign-key enforced persistence for:
- EventRepository
- IdempotencyRepository
- InvestigationRepository
- GapRepository
- EvidenceRepository
- DecisionRepository
- DecisionLineageRepository
- ActionRepository
- WorkerLeaseRepository
- EvidenceGraphRepository
- AuditRepository
- EntityRepository
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.release.connectivity.credentials import GLOBAL_REDACTOR
from backend.evidence.models import Evidence
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

logger = logging.getLogger("oracle.persistence.sqlite")


class SqliteConnectionPool:
    """Thread-safe connection provider for SQLite with WAL mode and foreign keys enabled."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._shared_conn: Optional[sqlite3.Connection] = None

        # If in-memory, hold a shared connection so the in-memory DB persists across threads
        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(
                ":memory:",
                check_same_thread=False,
                isolation_level=None,
            )
            self._configure_connection(self._shared_conn)
            DatabaseMigrator().apply_sqlite_migrations(self._shared_conn)
        else:
            # Apply migrations on a bootstrap connection
            bootstrap = sqlite3.connect(self.db_path)
            self._configure_connection(bootstrap)
            DatabaseMigrator().apply_sqlite_migrations(bootstrap)
            bootstrap.close()

    def _configure_connection(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 10000;")

    def get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn

        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._configure_connection(conn)
            self._local.conn = conn
        return self._local.conn

    def close(self) -> None:
        """Close connection handles."""
        if self._shared_conn is not None:
            try:
                self._shared_conn.close()
            except Exception:
                pass
            self._shared_conn = None
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None


# -----------------------------------------------------------------------------
# 1. SQLITE EVENT REPOSITORY
# -----------------------------------------------------------------------------

class SqliteEventRepository(EventRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def append_event(self, event: EnterpriseEvent) -> bool:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        tenant_id = getattr(event, "tenant_id", "default") or "default"
        cursor.execute(
            """
            INSERT OR REPLACE INTO event_journal (
                event_id, source, source_event_id, event_type, timestamp, received_at,
                entity_type, entity_id, repository, commit_hash, release_id,
                work_item_id, service_id, environment, correlation_keys_json,
                payload_json, provenance_json, processing_status, attempt_count, correlation_id, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                event.event_id,
                event.source,
                event.source_event_id,
                event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type),
                event.timestamp,
                getattr(event, "received_at", event.timestamp),
                event.entity_type,
                event.entity_id,
                event.repository or "",
                event.commit or "",
                event.release_id or "",
                event.work_item_id or "",
                event.service_id or "",
                event.environment or "",
                json.dumps(getattr(event, "correlation_keys", {})),
                json.dumps(GLOBAL_REDACTOR.redact_dict(getattr(event, "payload", {}) or {}) if isinstance(getattr(event, "payload", {}), dict) else getattr(event, "payload", {})),
                json.dumps(getattr(event, "provenance", {})),
                "PENDING",
                0,
                getattr(event, "provenance", {}).get("correlation_id", ""),
                tenant_id,
            ),
        )
        conn.commit()
        return True

    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[EnterpriseEvent]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT event_id, source, source_event_id, event_type, timestamp, received_at,
                       entity_type, entity_id, repository, commit_hash, release_id,
                       work_item_id, service_id, environment, correlation_keys_json,
                       payload_json, provenance_json, tenant_id
                FROM event_journal WHERE event_id = ? AND tenant_id = ?;
                """,
                (event_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT event_id, source, source_event_id, event_type, timestamp, received_at,
                       entity_type, entity_id, repository, commit_hash, release_id,
                       work_item_id, service_id, environment, correlation_keys_json,
                       payload_json, provenance_json, tenant_id
                FROM event_journal WHERE event_id = ?;
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
        tenant_id: Optional[str] = None,
    ) -> List[EnterpriseEvent]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        query = (
            "SELECT event_id, source, source_event_id, event_type, timestamp, received_at, "
            "entity_type, entity_id, repository, commit_hash, release_id, "
            "work_item_id, service_id, environment, correlation_keys_json, "
            "payload_json, provenance_json, tenant_id FROM event_journal WHERE 1=1"
        )
        params: List[Any] = []
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if release_id:
            query += " AND release_id = ?"
            params.append(release_id)
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY timestamp ASC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        cursor.execute(query, tuple(params))
        return [self._row_to_event(r) for r in cursor.fetchall()]

    def get_events_since(
        self,
        since_iso: str,
        release_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[EnterpriseEvent]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        query = (
            "SELECT event_id, source, source_event_id, event_type, timestamp, received_at, "
            "entity_type, entity_id, repository, commit_hash, release_id, "
            "work_item_id, service_id, environment, correlation_keys_json, "
            "payload_json, provenance_json, tenant_id FROM event_journal WHERE timestamp >= ?"
        )
        params: List[Any] = [since_iso]
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if release_id:
            query += " AND release_id = ?"
            params.append(release_id)
        query += " ORDER BY timestamp ASC;"
        cursor.execute(query, tuple(params))
        return [self._row_to_event(r) for r in cursor.fetchall()]

    def count_events(self, release_id: Optional[str] = None, tenant_id: Optional[str] = None) -> int:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM event_journal WHERE 1=1"
        params: List[Any] = []
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if release_id:
            query += " AND release_id = ?"
            params.append(release_id)
        cursor.execute(query + ";", tuple(params))
        row = cursor.fetchone()
        return row[0] if row else 0

    def _row_to_event(self, row: Tuple) -> EnterpriseEvent:
        tenant_id = row[17] if len(row) > 17 and row[17] else "default"
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
            tenant_id=tenant_id,
        )


# -----------------------------------------------------------------------------
# 2. SQLITE IDEMPOTENCY REPOSITORY
# -----------------------------------------------------------------------------

class SqliteIdempotencyRepository(IdempotencyRepository):
    def __init__(self, pool: SqliteConnectionPool):
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
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            cursor.execute(
                """
                INSERT OR IGNORE INTO event_idempotency (
                    idempotency_key, event_id, source, source_event_id, event_type, registered_at, ttl_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (idempotency_key, event_id, source, source_event_id, event_type, now_iso, ttl_seconds),
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            return False

    def get_registration(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT idempotency_key, event_id, source, source_event_id, event_type, registered_at, ttl_seconds
            FROM event_idempotency WHERE idempotency_key = ?;
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
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            DELETE FROM event_idempotency
            WHERE ttl_seconds IS NOT NULL;
            """
        )
        conn.commit()
        return cursor.rowcount


# -----------------------------------------------------------------------------
# 3. SQLITE GAP REPOSITORY
# -----------------------------------------------------------------------------

class SqliteGapRepository(GapRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_gaps(self, investigation_id: str, gaps: List[InformationGap]) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for gap in gaps:
            cursor.execute(
                """
                INSERT OR REPLACE INTO investigation_gaps (
                    investigation_id, gap_id, gap_type, target_entity, description,
                    why_needed, required_information, is_blocking, status, resolution,
                    resolution_evidence_ids_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    investigation_id,
                    gap.gap_id,
                    gap.gap_type.value if hasattr(gap.gap_type, "value") else str(gap.gap_type),
                    gap.target_entity,
                    gap.description,
                    gap.why_needed,
                    gap.required_information,
                    1 if gap.is_blocking else 0,
                    gap.status.value if hasattr(gap.status, "value") else str(gap.status),
                    gap.resolution,
                    json.dumps(gap.resolution_evidence_ids),
                    now_iso,
                ),
            )
        conn.commit()

    def get_gaps(self, investigation_id: str) -> List[InformationGap]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT gap_id, gap_type, target_entity, description, why_needed,
                   required_information, is_blocking, status, resolution, resolution_evidence_ids_json
            FROM investigation_gaps WHERE investigation_id = ?;
            """,
            (investigation_id,),
        )
        rows = cursor.fetchall()
        gaps = []
        for r in rows:
            gaps.append(
                InformationGap(
                    gap_id=r[0],
                    gap_type=GapType(r[1]) if r[1] in GapType._value2member_map_ else GapType.KNOWLEDGE,
                    target_entity=r[2],
                    description=r[3],
                    why_needed=r[4],
                    required_information=r[5],
                    is_blocking=bool(r[6]),
                    status=GapStatus(r[7]) if r[7] in GapStatus._value2member_map_ else GapStatus.OPEN,
                    resolution=r[8],
                    resolution_evidence_ids=json.loads(r[9]) if r[9] else [],
                )
            )
        return gaps

    def update_gap_status(
        self,
        investigation_id: str,
        gap_id: str,
        status: GapStatus,
        resolution: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        status_val = status.value if hasattr(status, "value") else str(status)
        if evidence_ids is not None:
            cursor.execute(
                """
                UPDATE investigation_gaps
                SET status = ?, resolution = ?, resolution_evidence_ids_json = ?, updated_at = ?
                WHERE investigation_id = ? AND gap_id = ?;
                """,
                (status_val, resolution, json.dumps(evidence_ids), now_iso, investigation_id, gap_id),
            )
        else:
            cursor.execute(
                """
                UPDATE investigation_gaps
                SET status = ?, resolution = ?, updated_at = ?
                WHERE investigation_id = ? AND gap_id = ?;
                """,
                (status_val, resolution, now_iso, investigation_id, gap_id),
            )
        conn.commit()


# -----------------------------------------------------------------------------
# 4. SQLITE EVIDENCE REPOSITORY
# -----------------------------------------------------------------------------

class SqliteEvidenceRepository(EvidenceRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_evidence(
        self,
        evidence: Evidence,
        investigation_id: Optional[str] = None,
        state: EvidenceState = EvidenceState.VALID,
    ) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        meta = evidence.metadata or {}
        src_id = getattr(evidence, "source_id", getattr(evidence, "source", "unknown"))
        src_type = getattr(evidence, "source_type", "document")
        content_hash = getattr(evidence, "content_hash", "")
        uri = getattr(evidence, "uri", None) or getattr(evidence, "canonical_uri", None) or ""
        ent_type = meta.get("entity_type", getattr(evidence, "entity_type", "release"))
        ent_id = meta.get("entity_id", getattr(evidence, "entity_id", ""))
        commit = meta.get("commit", getattr(evidence, "commit", ""))
        version = meta.get("version", getattr(evidence, "version", ""))
        created_at_val = getattr(evidence, "created_at", getattr(evidence, "timestamp", now_iso))
        valid_until_val = meta.get("valid_until", getattr(evidence, "valid_until", None))
        valid_until_str = str(valid_until_val) if valid_until_val else None

        cursor.execute(
            """
            INSERT OR REPLACE INTO evidence_store (
                evidence_id, investigation_id, source, source_type, content_hash,
                canonical_uri, entity_type, entity_id, commit_hash, version,
                valid_from, valid_until, state, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                evidence.evidence_id,
                investigation_id,
                src_id,
                src_type,
                content_hash,
                uri,
                ent_type,
                ent_id,
                commit,
                version or "",
                str(created_at_val),
                valid_until_str,
                state.value if hasattr(state, "value") else str(state),
                json.dumps(meta),
                now_iso,
            ),
        )
        conn.commit()

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT evidence_id, source, source_type, content_hash, canonical_uri,
                   entity_type, entity_id, commit_hash, version, valid_from, valid_until,
                   state, metadata_json
            FROM evidence_store WHERE evidence_id = ?;
            """,
            (evidence_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_evidence(row)

    def list_evidence_for_investigation(self, investigation_id: str) -> List[Evidence]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT evidence_id, source, source_type, content_hash, canonical_uri,
                   entity_type, entity_id, commit_hash, version, valid_from, valid_until,
                   state, metadata_json
            FROM evidence_store WHERE investigation_id = ?;
            """,
            (investigation_id,),
        )
        return [self._row_to_evidence(r) for r in cursor.fetchall()]

    def update_evidence_state(
        self,
        evidence_id: str,
        state: EvidenceState,
        reason: str,
        superseded_by: Optional[str] = None,
        causal_event_id: Optional[str] = None,
    ) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        state_val = state.value if hasattr(state, "value") else str(state)

        # 1. Update evidence state
        cursor.execute(
            "UPDATE evidence_store SET state = ? WHERE evidence_id = ?;",
            (state_val, evidence_id),
        )

        # 2. Append immutable transition record
        cursor.execute(
            """
            INSERT INTO evidence_lifecycle (
                evidence_id, state, transition_timestamp, reason, superseded_by, causal_event_id
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (evidence_id, state_val, now_iso, reason, superseded_by, causal_event_id),
        )
        conn.commit()

    def get_evidence_lifecycle_history(self, evidence_id: str) -> List[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT state, transition_timestamp, reason, superseded_by, causal_event_id
            FROM evidence_lifecycle WHERE evidence_id = ? ORDER BY id ASC;
            """,
            (evidence_id,),
        )
        return [
            {
                "state": r[0],
                "timestamp": r[1],
                "reason": r[2],
                "superseded_by": r[3],
                "causal_event_id": r[4],
            }
            for r in cursor.fetchall()
        ]

    def find_expired_evidence(self, now_iso: str) -> List[Evidence]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT evidence_id, source, source_type, content_hash, canonical_uri,
                   entity_type, entity_id, commit_hash, version, valid_from, valid_until,
                   state, metadata_json
            FROM evidence_store
            WHERE valid_until IS NOT NULL AND valid_until < ? AND state = 'VALID';
            """,
            (now_iso,),
        )
        return [self._row_to_evidence(r) for r in cursor.fetchall()]

    def _row_to_evidence(self, row: Tuple) -> Evidence:
        meta = json.loads(row[12]) if row[12] else {}
        if row[7]:
            meta.setdefault("commit", row[7])
        if row[8]:
            meta.setdefault("version", row[8])
        if row[10]:
            meta.setdefault("valid_until", row[10])
        return Evidence(
            evidence_id=row[0],
            source_id=row[1],
            source_type=row[2],
            uri=row[4] if row[4] else f"evidence://{row[1]}/{row[0]}",
            content=meta.get("content", f"Reconstructed evidence {row[0]}"),
            content_hash=row[3],
            source_path=meta.get("source_path", f"/evidence/{row[0]}.json"),
            chunk_index=int(meta.get("chunk_index", 0)),
            start_offset=int(meta.get("start_offset", 0)),
            end_offset=int(meta.get("end_offset", 100)),
            metadata=meta,
            created_at=str(row[9] if row[9] else "2026-09-09T12:00:00Z"),
        )


# -----------------------------------------------------------------------------
# 5. SQLITE INVESTIGATION & ASSESSMENT REPOSITORY
# -----------------------------------------------------------------------------

class SqliteInvestigationRepository(InvestigationRepository):
    def __init__(
        self,
        pool: SqliteConnectionPool,
        gap_repo: SqliteGapRepository,
        evidence_repo: SqliteEvidenceRepository,
    ):
        self.pool = pool
        self.gap_repo = gap_repo
        self.evidence_repo = evidence_repo

    def save_investigation(self, result: ReleaseInvestigationResult) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tenant_id = getattr(result.candidate, "tenant_id", "default") or "default"

        # 1. Save main investigation record
        cursor.execute(
            """
            INSERT OR REPLACE INTO investigations (
                investigation_id, release_id, service_name, version, commit_hash,
                status, created_at, updated_at, candidate_json, outages_json, telemetry_json, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                result.investigation_id,
                result.candidate.release_id,
                result.candidate.service_name,
                result.candidate.version,
                result.candidate.commit,
                "RESOLVED" if result.is_root_resolved else "BLOCKED",
                now_iso,
                now_iso,
                result.candidate.model_dump_json(),
                json.dumps(result.outages_detected),
                json.dumps(result.telemetry),
                tenant_id,
            ),
        )
        conn.commit()

        # 2. Save individual gaps
        self.gap_repo.save_gaps(result.investigation_id, result.gaps)

        # 3. Save admitted evidence linked to this investigation
        for ev in result.admitted_evidence:
            self.evidence_repo.save_evidence(ev, investigation_id=result.investigation_id)

    def get_investigation(self, investigation_id: str, tenant_id: Optional[str] = None) -> Optional[ReleaseInvestigationResult]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT investigation_id, release_id, service_name, version, commit_hash,
                       status, candidate_json, outages_json, telemetry_json
                FROM investigations WHERE investigation_id = ? AND tenant_id = ?;
                """,
                (investigation_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT investigation_id, release_id, service_name, version, commit_hash,
                       status, candidate_json, outages_json, telemetry_json
                FROM investigations WHERE investigation_id = ?;
                """,
                (investigation_id,),
            )
        row = cursor.fetchone()
        if not row:
            return None

        candidate = ReleaseCandidate.model_validate_json(row[6])
        outages = json.loads(row[7]) if row[7] else []
        telemetry = json.loads(row[8]) if row[8] else {}

        # Reconstruct gaps and admitted evidence
        gaps = self.gap_repo.get_gaps(investigation_id)
        evidence = self.evidence_repo.list_evidence_for_investigation(investigation_id)

        return ReleaseInvestigationResult(
            investigation_id=row[0],
            candidate=candidate,
            gaps=gaps,
            admitted_evidence=evidence,
            outages_detected=outages,
            telemetry=telemetry,
        )

    def get_latest_investigation_for_release(
        self, release_id: str, tenant_id: Optional[str] = None
    ) -> Optional[ReleaseInvestigationResult]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT investigation_id FROM investigations
                WHERE release_id = ? AND tenant_id = ? ORDER BY created_at DESC LIMIT 1;
                """,
                (release_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT investigation_id FROM investigations
                WHERE release_id = ? ORDER BY created_at DESC LIMIT 1;
                """,
                (release_id,),
            )
        row = cursor.fetchone()
        if not row:
            return None
        return self.get_investigation(row[0], tenant_id=tenant_id)

    def list_investigations(self, limit: int = 100, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT investigation_id, release_id, service_name, version, commit_hash,
                       status, created_at, updated_at
                FROM investigations WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?;
                """,
                (tenant_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT investigation_id, release_id, service_name, version, commit_hash,
                       status, created_at, updated_at
                FROM investigations ORDER BY created_at DESC LIMIT ?;
                """,
                (limit,),
            )
        return [
            {
                "investigation_id": r[0],
                "release_id": r[1],
                "service_name": r[2],
                "version": r[3],
                "commit": r[4],
                "status": r[5],
                "created_at": r[6],
                "updated_at": r[7],
            }
            for r in cursor.fetchall()
        ]

    def save_assessment(self, assessment: ReleaseAssessment) -> None:
        # Save investigation
        inv_res = ReleaseInvestigationResult(
            investigation_id=assessment.decision.investigation_id or f"inv-{assessment.candidate.release_id}",
            candidate=assessment.candidate,
            gaps=assessment.gaps,
            admitted_evidence=assessment.discovered_evidence,
            contradictions=assessment.contradictions,
            telemetry=assessment.telemetry,
        )
        self.save_investigation(inv_res)

    def get_assessment(self, release_id: str) -> Optional[ReleaseAssessment]:
        inv = self.get_latest_investigation_for_release(release_id)
        if not inv:
            return None

        # Fetch latest decision from decisions table
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT decision_id, outcome, risk_level, confidence, rationale,
                   blocking_factors_json, verified_factors_json, recommendations_json,
                   governed_actions_json, evidence_ids_json, contradiction_ids_json,
                   unresolved_gap_ids_json, decision_timestamp, provenance_json
            FROM decisions WHERE release_id = ? ORDER BY decision_timestamp DESC LIMIT 1;
            """,
            (release_id,),
        )
        row = cursor.fetchone()
        if not row:
            # Generate default decision from investigation state
            decision = ReleaseDecision(
                release_id=release_id,
                outcome=ReleaseDecisionOutcome.READY if inv.is_root_resolved else ReleaseDecisionOutcome.BLOCKED,
                risk_level=RiskLevel.LOW if inv.is_root_resolved else RiskLevel.HIGH,
                confidence=1.0 if inv.is_root_resolved else 0.85,
                rationale="Reconstructed decision from persistent investigation state.",
                investigation_id=inv.investigation_id,
                evidence_item_ids=[e.evidence_id for e in inv.admitted_evidence],
            )
        else:
            decision = ReleaseDecision(
                release_id=release_id,
                outcome=ReleaseDecisionOutcome(row[1]),
                risk_level=RiskLevel(row[2]),
                confidence=float(row[3]),
                rationale=row[4],
                blocking_factors=json.loads(row[5]) if row[5] else [],
                verified_factors=json.loads(row[6]) if row[6] else [],
                recommendations=[ReleaseRecommendation(**rec) for rec in json.loads(row[7])] if row[7] else [],
                governed_actions=[GovernedActionProposal(**act) for act in json.loads(row[8])] if row[8] else [],
                evidence_item_ids=json.loads(row[9]) if row[9] else [],
                contradiction_ids=json.loads(row[10]) if row[10] else [],
                unresolved_gap_ids=json.loads(row[11]) if row[11] else [],
                investigation_id=inv.investigation_id,
                provenance=json.loads(row[13]) if row[13] else {},
            )

        return ReleaseAssessment(
            assessment_id=f"assess-{release_id}",
            candidate=inv.candidate,
            decision=decision,
            discovered_evidence=inv.admitted_evidence,
            gaps=inv.gaps,
            contradictions=inv.contradictions,
            telemetry=inv.telemetry,
        )

    def get_all_assessments(self) -> Dict[str, ReleaseAssessment]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT release_id FROM investigations;")
        release_ids = [r[0] for r in cursor.fetchall()]
        assessments = {}
        for rid in release_ids:
            ass = self.get_assessment(rid)
            if ass:
                assessments[rid] = ass
        return assessments


# -----------------------------------------------------------------------------
# 6. SQLITE DECISION & LINEAGE REPOSITORIES
# -----------------------------------------------------------------------------

class SqliteDecisionRepository(DecisionRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_decision(self, decision: ReleaseDecision) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tenant_id = getattr(decision, "tenant_id", "default") or "default"
        cursor.execute(
            """
            INSERT OR REPLACE INTO decisions (
                decision_id, investigation_id, release_id, outcome, risk_level,
                confidence, rationale, blocking_factors_json, verified_factors_json,
                recommendations_json, governed_actions_json, evidence_ids_json,
                contradiction_ids_json, unresolved_gap_ids_json, decision_timestamp, provenance_json, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                f"dec-{decision.release_id}-{uuid.uuid4().hex[:6]}",
                decision.investigation_id,
                decision.release_id,
                decision.outcome.value if hasattr(decision.outcome, "value") else str(decision.outcome),
                decision.risk_level.value if hasattr(decision.risk_level, "value") else str(decision.risk_level),
                decision.confidence,
                decision.rationale,
                json.dumps(decision.blocking_factors),
                json.dumps(decision.verified_factors),
                json.dumps([r.model_dump() for r in decision.recommendations]),
                json.dumps([a.model_dump() for a in decision.governed_actions]),
                json.dumps(decision.evidence_item_ids),
                json.dumps(decision.contradiction_ids),
                json.dumps(decision.unresolved_gap_ids),
                now_iso,
                json.dumps(decision.provenance),
                tenant_id,
            ),
        )
        conn.commit()

    def get_latest_decision(self, release_id: str, tenant_id: Optional[str] = None) -> Optional[ReleaseDecision]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT decision_id, investigation_id, release_id, outcome, risk_level,
                       confidence, rationale, blocking_factors_json, verified_factors_json,
                       recommendations_json, governed_actions_json, evidence_ids_json,
                       contradiction_ids_json, unresolved_gap_ids_json, decision_timestamp, provenance_json, tenant_id
                FROM decisions WHERE release_id = ? AND tenant_id = ? ORDER BY decision_timestamp DESC LIMIT 1;
                """,
                (release_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT decision_id, investigation_id, release_id, outcome, risk_level,
                       confidence, rationale, blocking_factors_json, verified_factors_json,
                       recommendations_json, governed_actions_json, evidence_ids_json,
                       contradiction_ids_json, unresolved_gap_ids_json, decision_timestamp, provenance_json, tenant_id
                FROM decisions WHERE release_id = ? ORDER BY decision_timestamp DESC LIMIT 1;
                """,
                (release_id,),
            )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_decision(row)

    def get_decision_history(self, release_id: str, tenant_id: Optional[str] = None) -> List[ReleaseDecision]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT decision_id, investigation_id, release_id, outcome, risk_level,
                       confidence, rationale, blocking_factors_json, verified_factors_json,
                       recommendations_json, governed_actions_json, evidence_ids_json,
                       contradiction_ids_json, unresolved_gap_ids_json, decision_timestamp, provenance_json, tenant_id
                FROM decisions WHERE release_id = ? AND tenant_id = ? ORDER BY decision_timestamp ASC;
                """,
                (release_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT decision_id, investigation_id, release_id, outcome, risk_level,
                       confidence, rationale, blocking_factors_json, verified_factors_json,
                       recommendations_json, governed_actions_json, evidence_ids_json,
                       contradiction_ids_json, unresolved_gap_ids_json, decision_timestamp, provenance_json, tenant_id
                FROM decisions WHERE release_id = ? ORDER BY decision_timestamp ASC;
                """,
                (release_id,),
            )
        return [self._row_to_decision(r) for r in cursor.fetchall()]

    def _row_to_decision(self, row: Tuple) -> ReleaseDecision:
        tenant_id = row[16] if len(row) > 16 and row[16] else "default"
        return ReleaseDecision(
            release_id=row[2],
            outcome=ReleaseDecisionOutcome(row[3]),
            risk_level=RiskLevel(row[4]),
            confidence=float(row[5]),
            rationale=row[6],
            blocking_factors=json.loads(row[7]) if row[7] else [],
            verified_factors=json.loads(row[8]) if row[8] else [],
            recommendations=[ReleaseRecommendation(**rec) for rec in json.loads(row[9])] if row[9] else [],
            governed_actions=[GovernedActionProposal(**act) for act in json.loads(row[10])] if row[10] else [],
            evidence_item_ids=json.loads(row[11]) if row[11] else [],
            contradiction_ids=json.loads(row[12]) if row[12] else [],
            unresolved_gap_ids=json.loads(row[13]) if row[13] else [],
            investigation_id=row[1],
            provenance=json.loads(row[15]) if row[15] else {},
            tenant_id=tenant_id,
        )


class SqliteDecisionLineageRepository(DecisionLineageRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def record_transition(self, release_id: str, change_event: DecisionChangeEvent) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO decision_lineage (
                change_id, release_id, previous_outcome, new_outcome, trigger_event_id,
                changed_evidence_ids_json, explanation, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                change_event.change_id,
                release_id,
                change_event.previous_outcome.value if hasattr(change_event.previous_outcome, "value") else str(change_event.previous_outcome),
                change_event.new_outcome.value if hasattr(change_event.new_outcome, "value") else str(change_event.new_outcome),
                change_event.trigger_event_id,
                json.dumps(change_event.changed_evidence_ids),
                change_event.explanation,
                change_event.timestamp,
            ),
        )
        conn.commit()

    def get_lineage(self, release_id: str) -> List[DecisionChangeEvent]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT change_id, release_id, previous_outcome, new_outcome, trigger_event_id,
                   changed_evidence_ids_json, explanation, timestamp
            FROM decision_lineage WHERE release_id = ? ORDER BY timestamp ASC;
            """,
            (release_id,),
        )
        return [
            DecisionChangeEvent(
                change_id=r[0],
                release_id=r[1],
                previous_outcome=ReleaseDecisionOutcome(r[2]),
                new_outcome=ReleaseDecisionOutcome(r[3]),
                trigger_event_id=r[4],
                changed_evidence_ids=json.loads(r[5]) if r[5] else [],
                explanation=r[6],
                timestamp=r[7],
            )
            for r in cursor.fetchall()
        ]

    def get_latest_transition(self, release_id: str) -> Optional[DecisionChangeEvent]:
        lineage = self.get_lineage(release_id)
        return lineage[-1] if lineage else None


# -----------------------------------------------------------------------------
# 7. SQLITE ACTION REPOSITORY
# -----------------------------------------------------------------------------

class SqliteActionRepository(ActionRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_action(self, action: GovernedActionProposal) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tenant_id = getattr(action, "tenant_id", "default") or "default"
        cursor.execute(
            """
            INSERT OR REPLACE INTO governed_actions (
                action_id, action_type, target_system, payload_json, status,
                idempotency_key, requires_human_approval, authorized_by,
                execution_timestamp, audit_trail_json, created_at, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                action.action_id,
                action.action_type.value if hasattr(action.action_type, "value") else str(action.action_type),
                action.target_system,
                json.dumps(action.payload),
                action.status.value if hasattr(action.status, "value") else str(action.status),
                action.idempotency_key,
                1 if action.requires_human_approval else 0,
                action.authorized_by,
                action.execution_timestamp,
                json.dumps(action.audit_trail),
                now_iso,
                tenant_id,
            ),
        )
        conn.commit()

    def get_action(self, action_id: str, tenant_id: Optional[str] = None) -> Optional[GovernedActionProposal]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT action_id, action_type, target_system, payload_json, status,
                       idempotency_key, requires_human_approval, authorized_by,
                       execution_timestamp, audit_trail_json, tenant_id
                FROM governed_actions WHERE action_id = ? AND tenant_id = ?;
                """,
                (action_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT action_id, action_type, target_system, payload_json, status,
                       idempotency_key, requires_human_approval, authorized_by,
                       execution_timestamp, audit_trail_json, tenant_id
                FROM governed_actions WHERE action_id = ?;
                """,
                (action_id,),
            )
        row = cursor.fetchone()
        if not row:
            return None
        return GovernedActionProposal(
            action_id=row[0],
            action_type=GovernedActionType(row[1]),
            target_system=row[2],
            payload=json.loads(row[3]) if row[3] else {},
            status=GovernedActionStatus(row[4]),
            idempotency_key=row[5],
            requires_human_approval=bool(row[6]),
            authorized_by=row[7],
            execution_timestamp=row[8],
            audit_trail=json.loads(row[9]) if row[9] else [],
            tenant_id=row[10] if len(row) > 10 and row[10] else "default",
        )

    def update_action_status(
        self,
        action_id: str,
        status: GovernedActionStatus,
        audit_entry: str,
        authorized_by: Optional[str] = None,
        execution_timestamp: Optional[str] = None,
    ) -> None:
        action = self.get_action(action_id)
        if not action:
            return
        action.status = status
        action.audit_trail.append(audit_entry)
        if authorized_by:
            action.authorized_by = authorized_by
        if execution_timestamp:
            action.execution_timestamp = execution_timestamp
        self.save_action(action)

    def record_action_execution(
        self,
        idempotency_key: str,
        action_id: str,
        result_payload: Dict[str, Any],
    ) -> bool:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            cursor.execute(
                """
                INSERT OR IGNORE INTO governed_action_executions (
                    idempotency_key, action_id, result_payload_json, executed_at
                ) VALUES (?, ?, ?, ?);
                """,
                (idempotency_key, action_id, json.dumps(result_payload), now_iso),
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            return False

    def get_action_execution(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT result_payload_json FROM governed_action_executions WHERE idempotency_key = ?;
            """,
            (idempotency_key,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return json.loads(row[0]) if row[0] else {}

    def list_actions(
        self,
        release_id: Optional[str] = None,
        status: Optional[GovernedActionStatus] = None,
        tenant_id: Optional[str] = None,
    ) -> List[GovernedActionProposal]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        query = (
            "SELECT action_id, action_type, target_system, payload_json, status, "
            "idempotency_key, requires_human_approval, authorized_by, "
            "execution_timestamp, audit_trail_json, tenant_id FROM governed_actions WHERE 1=1"
        )
        params: List[Any] = []
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY created_at DESC;"
        cursor.execute(query, tuple(params))
        actions = []
        for row in cursor.fetchall():
            act = GovernedActionProposal(
                action_id=row[0],
                action_type=GovernedActionType(row[1]),
                target_system=row[2],
                payload=json.loads(row[3]) if row[3] else {},
                status=GovernedActionStatus(row[4]),
                idempotency_key=row[5],
                requires_human_approval=bool(row[6]),
                authorized_by=row[7],
                execution_timestamp=row[8],
                audit_trail=json.loads(row[9]) if row[9] else [],
                tenant_id=row[10] if len(row) > 10 and row[10] else "default",
            )
            if release_id and act.payload.get("release_id") != release_id:
                continue
            actions.append(act)
        return actions


# -----------------------------------------------------------------------------
# 8. SQLITE WORKER LEASE REPOSITORY
# -----------------------------------------------------------------------------

class SqliteWorkerLeaseRepository(WorkerLeaseRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def create_task(
        self,
        task_id: Optional[str] = None,
        task_type: str = "DEFAULT",
        payload: Optional[Dict[str, Any]] = None,
        tenant_id: str = "default",
    ) -> str:
        tid = task_id or f"task-{uuid.uuid4().hex[:12]}"
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO worker_leases (
                task_id, task_type, payload_json, status, attempt_count, tenant_id
            ) VALUES (?, ?, ?, 'PENDING', 0, ?);
            """,
            (tid, task_type, json.dumps(payload or {}), tenant_id),
        )
        conn.commit()
        return tid

    def claim_next_task(
        self,
        worker_id: str,
        task_types: Optional[List[str]] = None,
        lease_duration_seconds: int = 30,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now = time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        lease_until_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + lease_duration_seconds))

        # First reclaim expired leases
        self.reclaim_expired_leases(now_iso)

        # Select candidate task
        query = (
            "SELECT task_id, task_type, payload_json, attempt_count, tenant_id FROM worker_leases "
            "WHERE status IN ('PENDING', 'RETRYABLE') "
        )
        params: List[Any] = []
        if tenant_id:
            query += "AND tenant_id = ? "
            params.append(tenant_id)
        if task_types:
            placeholders = ",".join("?" for _ in task_types)
            query += f"AND task_type IN ({placeholders}) "
            params.extend(task_types)
        query += "ORDER BY CASE WHEN status = 'PENDING' THEN 1 ELSE 2 END, task_id ASC LIMIT 1;"

        cursor.execute(query, tuple(params))
        row = cursor.fetchone()
        if not row:
            return None

        task_id, task_type, payload_json, attempts, row_tenant = row[0], row[1], row[2], row[3], row[4]

        # Atomic claim check
        cursor.execute(
            """
            UPDATE worker_leases
            SET worker_id = ?, status = 'CLAIMED', claimed_at = ?, lease_until = ?,
                heartbeat_at = ?, attempt_count = attempt_count + 1
            WHERE task_id = ? AND status IN ('PENDING', 'RETRYABLE');
            """,
            (worker_id, now_iso, lease_until_iso, now_iso, task_id),
        )
        conn.commit()
        if cursor.rowcount > 0:
            return {
                "task_id": task_id,
                "task_type": task_type,
                "payload": json.loads(payload_json) if payload_json else {},
                "attempt_count": attempts + 1,
                "worker_id": worker_id,
                "lease_until": lease_until_iso,
                "tenant_id": row_tenant or "default",
            }
        return None

    def heartbeat_lease(
        self,
        task_id: str,
        worker_id: str,
        extension_seconds: int = 30,
    ) -> bool:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now = time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        lease_until_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + extension_seconds))

        cursor.execute(
            """
            UPDATE worker_leases
            SET heartbeat_at = ?, lease_until = ?
            WHERE task_id = ? AND worker_id = ? AND status IN ('CLAIMED', 'RUNNING');
            """,
            (now_iso, lease_until_iso, task_id, worker_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def complete_task(
        self,
        task_id: str,
        worker_id: str,
        result_payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cursor.execute(
            """
            UPDATE worker_leases
            SET status = 'SUCCEEDED', completed_at = ?, result_json = ?
            WHERE task_id = ? AND worker_id = ?;
            """,
            (now_iso, json.dumps(result_payload or {}), task_id, worker_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def fail_task(
        self,
        task_id: str,
        worker_id: str,
        error_message: str,
        retryable: bool = True,
        max_retries: int = 3,
    ) -> bool:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT attempt_count FROM worker_leases WHERE task_id = ?;", (task_id,))
        row = cursor.fetchone()
        attempts = row[0] if row else 1

        next_status = "RETRYABLE" if (retryable and attempts < max_retries) else "FAILED"
        cursor.execute(
            """
            UPDATE worker_leases
            SET status = ?, result_json = ?
            WHERE task_id = ? AND worker_id = ?;
            """,
            (next_status, json.dumps({"error": error_message}), task_id, worker_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def reclaim_expired_leases(self, now_iso: str) -> int:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE worker_leases
            SET status = 'RETRYABLE', worker_id = NULL
            WHERE status IN ('CLAIMED', 'RUNNING') AND lease_until <= ?;
            """,
            (now_iso,),
        )
        conn.commit()
        return cursor.rowcount

    def get_task(self, task_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                """
                SELECT task_id, task_type, payload_json, worker_id, status, attempt_count,
                       claimed_at, lease_until, heartbeat_at, completed_at, result_json, tenant_id
                FROM worker_leases WHERE task_id = ? AND tenant_id = ?;
                """,
                (task_id, tenant_id),
            )
        else:
            cursor.execute(
                """
                SELECT task_id, task_type, payload_json, worker_id, status, attempt_count,
                       claimed_at, lease_until, heartbeat_at, completed_at, result_json, tenant_id
                FROM worker_leases WHERE task_id = ?;
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
            "tenant_id": row[11] if len(row) > 11 and row[11] else "default",
        }


# -----------------------------------------------------------------------------
# 9. SQLITE EVIDENCE GRAPH REPOSITORY
# -----------------------------------------------------------------------------

class SqliteEvidenceGraphRepository(EvidenceGraphRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_node(
        self,
        node_id: str,
        node_type: str,
        properties: Dict[str, Any],
        valid_from: str,
        valid_until: Optional[str] = None,
        is_active: bool = True,
        tenant_id: str = "default",
    ) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cursor.execute(
            """
            INSERT OR REPLACE INTO graph_nodes (
                node_id, node_type, properties_json, valid_from, valid_until, is_active, updated_at, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (node_id, node_type, json.dumps(properties), valid_from, valid_until, 1 if is_active else 0, now_iso, tenant_id),
        )
        conn.commit()

    def save_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        properties: Dict[str, Any],
        valid_from: str,
        valid_until: Optional[str] = None,
        is_active: bool = True,
        tenant_id: str = "default",
    ) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cursor.execute(
            """
            INSERT OR REPLACE INTO graph_edges (
                source_id, target_id, edge_type, properties_json, valid_from, valid_until, is_active, updated_at, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (source_id, target_id, edge_type, json.dumps(properties), valid_from, valid_until, 1 if is_active else 0, now_iso, tenant_id),
        )
        conn.commit()

    def get_graph_snapshot(self, as_of_iso: Optional[str] = None, tenant_id: str = "default") -> EvidenceGraph:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        graph = EvidenceGraph()

        if as_of_iso:
            # Temporal query: What did ORACLE know at time T?
            cursor.execute(
                """
                SELECT node_id, node_type, properties_json FROM graph_nodes
                WHERE tenant_id = ? AND valid_from <= ? AND (valid_until IS NULL OR valid_until > ?);
                """,
                (tenant_id, as_of_iso, as_of_iso),
            )
            for row in cursor.fetchall():
                nt = GraphNodeType(row[1]) if row[1] in GraphNodeType._value2member_map_ else GraphNodeType.RELEASE
                props = json.loads(row[2]) if row[2] else {}
                graph.add_node(row[0], nt, props)

            cursor.execute(
                """
                SELECT source_id, target_id, edge_type, properties_json FROM graph_edges
                WHERE tenant_id = ? AND valid_from <= ? AND (valid_until IS NULL OR valid_until > ?);
                """,
                (tenant_id, as_of_iso, as_of_iso),
            )
            for row in cursor.fetchall():
                et = GraphEdgeType(row[2]) if row[2] in GraphEdgeType._value2member_map_ else GraphEdgeType.DEPENDS_ON
                props = json.loads(row[3]) if row[3] else {}
                graph.add_edge(row[0], row[1], et, props)
        else:
            # Active graph query
            cursor.execute(
                "SELECT node_id, node_type, properties_json FROM graph_nodes WHERE tenant_id = ? AND is_active = 1;",
                (tenant_id,),
            )
            for row in cursor.fetchall():
                nt = GraphNodeType(row[1]) if row[1] in GraphNodeType._value2member_map_ else GraphNodeType.RELEASE
                props = json.loads(row[2]) if row[2] else {}
                graph.add_node(row[0], nt, props)

            cursor.execute(
                "SELECT source_id, target_id, edge_type, properties_json FROM graph_edges WHERE tenant_id = ? AND is_active = 1;",
                (tenant_id,),
            )
            for row in cursor.fetchall():
                et = GraphEdgeType(row[2]) if row[2] in GraphEdgeType._value2member_map_ else GraphEdgeType.DEPENDS_ON
                props = json.loads(row[3]) if row[3] else {}
                graph.add_edge(row[0], row[1], et, props)

        return graph

    def get_node_history(self, node_id: str, tenant_id: str = "default") -> List[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT node_id, node_type, properties_json, valid_from, valid_until, is_active
            FROM graph_nodes WHERE node_id = ? AND tenant_id = ? ORDER BY valid_from ASC;
            """,
            (node_id, tenant_id),
        )
        return [
            {
                "node_id": r[0],
                "node_type": r[1],
                "properties": json.loads(r[2]) if r[2] else {},
                "valid_from": r[3],
                "valid_until": r[4],
                "is_active": bool(r[5]),
            }
            for r in cursor.fetchall()
        ]


# -----------------------------------------------------------------------------
# 10. SQLITE AUDIT REPOSITORY
# -----------------------------------------------------------------------------

class SqliteAuditRepository(AuditRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def record_audit(
        self,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Dict[str, Any],
        correlation_id: Optional[str] = None,
    ) -> str:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        audit_id = f"aud-{uuid.uuid4().hex[:8]}"
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cursor.execute(
            """
            INSERT INTO audit_journal (
                audit_id, timestamp, actor, action, entity_type, entity_id, details_json, correlation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (audit_id, now_iso, actor, action, entity_type, entity_id, json.dumps(details), correlation_id or ""),
        )
        conn.commit()
        return audit_id

    def query_audit(
        self,
        entity_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        query = "SELECT audit_id, timestamp, actor, action, entity_type, entity_id, details_json, correlation_id FROM audit_journal WHERE 1=1"
        params: List[Any] = []
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY timestamp DESC LIMIT ?;"
        params.append(limit)

        cursor.execute(query, tuple(params))
        return [
            {
                "audit_id": r[0],
                "timestamp": r[1],
                "actor": r[2],
                "action": r[3],
                "entity_type": r[4],
                "entity_id": r[5],
                "details": json.loads(r[6]) if r[6] else {},
                "correlation_id": r[7],
            }
            for r in cursor.fetchall()
        ]


# -----------------------------------------------------------------------------
# 11. SQLITE ENTITY REPOSITORY
# -----------------------------------------------------------------------------

class SqliteEntityRepository(EntityRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_candidate(self, candidate: ReleaseCandidate) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tenant_id = getattr(candidate, "tenant_id", "default") or "default"
        cursor.execute(
            """
            INSERT OR REPLACE INTO entity_candidates (
                release_id, service_name, version, repository, branch, commit_hash,
                target_environment, pull_request_id, linked_work_items_json,
                changed_components_json, candidate_json, created_at, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                candidate.release_id,
                candidate.service_name,
                candidate.version,
                candidate.repository,
                candidate.branch,
                candidate.commit,
                candidate.target_environment,
                candidate.pull_request_id,
                json.dumps(candidate.linked_work_item_ids),
                json.dumps(candidate.changed_components),
                candidate.model_dump_json(),
                now_iso,
                tenant_id,
            ),
        )
        conn.commit()

    def get_candidate(self, release_id: str, tenant_id: Optional[str] = None) -> Optional[ReleaseCandidate]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                "SELECT candidate_json FROM entity_candidates WHERE release_id = ? AND tenant_id = ?;",
                (release_id, tenant_id),
            )
        else:
            cursor.execute(
                "SELECT candidate_json FROM entity_candidates WHERE release_id = ?;",
                (release_id,),
            )
        row = cursor.fetchone()
        if not row:
            return None
        return ReleaseCandidate.model_validate_json(row[0])

    def list_candidates(self, tenant_id: Optional[str] = None) -> List[ReleaseCandidate]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute("SELECT candidate_json FROM entity_candidates WHERE tenant_id = ? ORDER BY created_at DESC;", (tenant_id,))
        else:
            cursor.execute("SELECT candidate_json FROM entity_candidates ORDER BY created_at DESC;")
        return [ReleaseCandidate.model_validate_json(r[0]) for r in cursor.fetchall()]


# -----------------------------------------------------------------------------
# 12. SQLITE WEBHOOK REGISTRATION REPOSITORY (Brick 4.5)
# -----------------------------------------------------------------------------

class SqliteWebhookRegistrationRepository(WebhookRegistrationRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool

    def save_registration(self, registration: WebhookRegistration) -> None:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        status_val = registration.status.value if hasattr(registration.status, "value") else str(registration.status)
        cursor.execute(
            """
            INSERT OR REPLACE INTO webhook_registrations (
                registration_id, tenant_id, provider, external_registration_id,
                target_entity, callback_url, secret_token, event_types_json,
                status, created_at, updated_at, last_verified_at, provenance_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
        conn.commit()

    def get_registration(self, registration_id: str, tenant_id: str = "default") -> Optional[WebhookRegistration]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT registration_id, tenant_id, provider, external_registration_id,
                   target_entity, callback_url, secret_token, event_types_json,
                   status, created_at, updated_at, last_verified_at, provenance_json
            FROM webhook_registrations
            WHERE registration_id = ? AND tenant_id = ?;
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
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        query = (
            "SELECT registration_id, tenant_id, provider, external_registration_id, "
            "target_entity, callback_url, secret_token, event_types_json, "
            "status, created_at, updated_at, last_verified_at, provenance_json "
            "FROM webhook_registrations WHERE tenant_id = ?"
        )
        params: List[Any] = [tenant_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        if target_entity:
            query += " AND target_entity = ?"
            params.append(target_entity)
        query += " ORDER BY created_at DESC;"
        cursor.execute(query, tuple(params))
        return [self._row_to_registration(r) for r in cursor.fetchall()]

    def delete_registration(self, registration_id: str, tenant_id: str = "default") -> bool:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM webhook_registrations WHERE registration_id = ? AND tenant_id = ?;",
            (registration_id, tenant_id),
        )
        conn.commit()
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


# -----------------------------------------------------------------------------
# 13. SQLITE DISTRIBUTED LOCK REPOSITORY (Brick 4.5)
# -----------------------------------------------------------------------------

class SqliteDistributedLockRepository(DistributedLockRepository):
    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool
        self._lock = threading.Lock()

    def acquire_lock(
        self,
        lock_key: str,
        owner: str,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> Optional[Tuple[int, float]]:
        conn = self.pool.get_connection()
        now = time.time()
        expires_at = now + ttl_seconds
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT owner, fencing_token, expires_at FROM distributed_locks WHERE lock_key = ? AND tenant_id = ?;",
                (lock_key, tenant_id),
            )
            row = cursor.fetchone()
            if row:
                current_owner, current_token, current_expires = row[0], int(row[1]), float(row[2])
                if current_expires > now and current_owner:
                    if current_owner == owner:
                        # Re-acquire/renew by current owner
                        cursor.execute(
                            "UPDATE distributed_locks SET expires_at = ?, acquired_at = ? WHERE lock_key = ? AND tenant_id = ?;",
                            (expires_at, now_iso, lock_key, tenant_id),
                        )
                        conn.commit()
                        return (current_token, expires_at)
                    return None
                new_token = current_token + 1
            else:
                new_token = 1

            cursor.execute(
                """
                INSERT OR REPLACE INTO distributed_locks (
                    lock_key, tenant_id, owner, fencing_token, acquired_at, expires_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (lock_key, tenant_id, owner, new_token, now_iso, expires_at, "{}"),
            )
            conn.commit()
            return (new_token, expires_at)

    def renew_lock(
        self,
        lock_key: str,
        owner: str,
        fencing_token: int,
        ttl_seconds: float = 30.0,
        tenant_id: str = "default",
    ) -> bool:
        conn = self.pool.get_connection()
        now = time.time()
        new_expires = now + ttl_seconds
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE distributed_locks
                SET expires_at = ?, acquired_at = ?
                WHERE lock_key = ? AND tenant_id = ? AND owner = ? AND fencing_token = ? AND expires_at > ?;
                """,
                (new_expires, now_iso, lock_key, tenant_id, owner, fencing_token, now),
            )
            conn.commit()
            return cursor.rowcount > 0

    def release_lock(
        self,
        lock_key: str,
        owner: str,
        fencing_token: int,
        tenant_id: str = "default",
    ) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE distributed_locks
                SET owner = '', expires_at = 0
                WHERE lock_key = ? AND tenant_id = ? AND owner = ? AND fencing_token = ?;
                """,
                (lock_key, tenant_id, owner, fencing_token),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_lock(self, lock_key: str, tenant_id: str = "default") -> Optional[Dict[str, Any]]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT lock_key, tenant_id, owner, fencing_token, acquired_at, expires_at, metadata_json
            FROM distributed_locks
            WHERE lock_key = ? AND tenant_id = ?;
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
# 14. SQLITE SECURITY REPOSITORY (Brick 4.8)
# -----------------------------------------------------------------------------

class SqliteSecurityRepository(SecurityRepository):
    """SQLite implementation of authoritative security intelligence repository."""

    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool
        self._lock = threading.RLock()

    def save_finding(self, finding: SecurityFinding) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = finding.model_dump_json() if hasattr(finding, "model_dump_json") else json.dumps(finding)
            cursor.execute(
                """
                INSERT INTO security_findings (
                    finding_id, tenant_id, repository, commit_hash, artifact_digest, severity, category, status, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    status = excluded.status,
                    severity = excluded.severity,
                    artifact_digest = excluded.artifact_digest,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_finding(self, finding_id: str, tenant_id: str = "default") -> Optional[SecurityFinding]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM security_findings WHERE finding_id = ? AND tenant_id = ?;",
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
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        clauses = ["tenant_id = ?"]
        params: List[Any] = [tenant_id]
        if repository:
            clauses.append("repository = ?")
            params.append(repository)
        if commit:
            clauses.append("commit_hash = ?")
            params.append(commit)
        if artifact_digest:
            clauses.append("artifact_digest = ?")
            params.append(artifact_digest)
        where_stmt = " AND ".join(clauses)
        cursor.execute(f"SELECT payload_json FROM security_findings WHERE {where_stmt};", tuple(params))
        return [SecurityFinding.model_validate_json(row[0]) for row in cursor.fetchall()]

    def save_impact_assessment(self, assessment: SecurityImpactAssessment) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = assessment.model_dump_json() if hasattr(assessment, "model_dump_json") else json.dumps(assessment)
            cursor.execute(
                """
                INSERT INTO security_impact_assessments (
                    assessment_id, finding_id, tenant_id, repository, commit_hash, artifact_digest, impact_level, business_impact, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(assessment_id) DO UPDATE SET
                    impact_level = excluded.impact_level,
                    business_impact = excluded.business_impact,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_impact_assessment(self, assessment_id: str, tenant_id: str = "default") -> Optional[SecurityImpactAssessment]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM security_impact_assessments WHERE assessment_id = ? AND tenant_id = ?;",
            (assessment_id, tenant_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return SecurityImpactAssessment.model_validate_json(row[0])

    def save_investigation(self, investigation: SecurityInvestigation) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = investigation.model_dump_json() if hasattr(investigation, "model_dump_json") else json.dumps(investigation)
            dec_outcome = investigation.decision.outcome.value if investigation.decision else "SECURITY_UNKNOWN"
            cursor.execute(
                """
                INSERT INTO security_investigations (
                    investigation_id, tenant_id, repository, commit_hash, artifact_digest, decision_outcome, created_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(investigation_id) DO UPDATE SET
                    decision_outcome = excluded.decision_outcome,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_investigation(self, investigation_id: str, tenant_id: str = "default") -> Optional[SecurityInvestigation]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM security_investigations WHERE investigation_id = ? AND tenant_id = ?;",
            (investigation_id, tenant_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return SecurityInvestigation.model_validate_json(row[0])

    def save_decision(self, decision: SecurityDecision) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = decision.model_dump_json() if hasattr(decision, "model_dump_json") else json.dumps(decision)
            cursor.execute(
                """
                INSERT INTO security_decisions (
                    decision_id, tenant_id, repository, commit_hash, artifact_digest, outcome, risk_level, created_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(decision_id) DO UPDATE SET
                    outcome = excluded.outcome,
                    risk_level = excluded.risk_level,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_decision(self, decision_id: str, tenant_id: str = "default") -> Optional[SecurityDecision]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM security_decisions WHERE decision_id = ? AND tenant_id = ?;",
            (decision_id, tenant_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return SecurityDecision.model_validate_json(row[0])

    def save_verification(self, verification: SecurityVerification) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = verification.model_dump_json() if hasattr(verification, "model_dump_json") else json.dumps(verification)
            cursor.execute(
                """
                INSERT INTO security_verifications (
                    verification_id, finding_id, tenant_id, rescan_commit, rescan_artifact_digest, status, verified_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(verification_id) DO UPDATE SET
                    status = excluded.status,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_verification(self, verification_id: str, tenant_id: str = "default") -> Optional[SecurityVerification]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM security_verifications WHERE verification_id = ? AND tenant_id = ?;",
            (verification_id, tenant_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return SecurityVerification.model_validate_json(row[0])


# -----------------------------------------------------------------------------
# 15. SQLITE ARTIFACT & DEPLOYMENT REPOSITORY (Brick 4.8)
# -----------------------------------------------------------------------------

class SqliteArtifactDeploymentRepository(ArtifactDeploymentRepository):
    """SQLite implementation of exact artifact and deployment repository."""

    def __init__(self, pool: SqliteConnectionPool):
        self.pool = pool
        self._lock = threading.RLock()

    def save_artifact(self, artifact: BuildArtifact) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = artifact.model_dump_json() if hasattr(artifact, "model_dump_json") else json.dumps(artifact)
            cursor.execute(
                """
                INSERT INTO build_artifacts (
                    artifact_digest, tenant_id, artifact_id, artifact_name, repository, commit_hash, build_id, built_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(artifact_digest) DO UPDATE SET
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_artifact(self, artifact_digest: str, tenant_id: str = "default") -> Optional[BuildArtifact]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM build_artifacts WHERE artifact_digest = ? AND tenant_id = ?;",
            (artifact_digest, tenant_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return BuildArtifact.model_validate_json(row[0])

    def save_deployment(self, deployment: Deployment) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = deployment.model_dump_json() if hasattr(deployment, "model_dump_json") else json.dumps(deployment)
            cursor.execute(
                """
                INSERT INTO deployments (
                    deployment_id, tenant_id, service_id, environment, artifact_digest, commit_hash, deployed_at, status, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(deployment_id) DO UPDATE SET
                    status = excluded.status,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_deployment(self, deployment_id: str, tenant_id: str = "default") -> Optional[Deployment]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM deployments WHERE deployment_id = ? AND tenant_id = ?;",
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
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        clauses = ["tenant_id = ?"]
        params: List[Any] = [tenant_id]
        if service_id:
            clauses.append("service_id = ?")
            params.append(service_id)
        if environment:
            clauses.append("environment = ?")
            params.append(environment)
        where_stmt = " AND ".join(clauses)
        cursor.execute(f"SELECT payload_json FROM deployments WHERE {where_stmt};", tuple(params))
        return [Deployment.model_validate_json(row[0]) for row in cursor.fetchall()]

    def save_runtime_service(self, service: RuntimeService) -> bool:
        conn = self.pool.get_connection()
        with self._lock:
            cursor = conn.cursor()
            payload = service.model_dump_json() if hasattr(service, "model_dump_json") else json.dumps(service)
            cursor.execute(
                """
                INSERT INTO runtime_services (
                    service_id, tenant_id, service_name, environment, exposure, auth_required, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_id) DO UPDATE SET
                    exposure = excluded.exposure,
                    auth_required = excluded.auth_required,
                    payload_json = excluded.payload_json;
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
            conn.commit()
            return True

    def get_runtime_service(self, service_id: str, tenant_id: str = "default") -> Optional[RuntimeService]:
        conn = self.pool.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM runtime_services WHERE service_id = ? AND tenant_id = ?;",
            (service_id, tenant_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return RuntimeService.model_validate_json(row[0])

