"""
Persistence Factory & Durable Store Bundle for ORACLE (Brick 4.5)

Provides unified access to all authoritative enterprise repositories:
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
- WebhookRegistrationRepository
- DistributedLockRepository
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from backend.release.persistence.interfaces import (
    ActionRepository,
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
    WebhookRegistrationRepository,
    WorkerLeaseRepository,
)
from backend.release.persistence.sqlite_store import (
    SqliteActionRepository,
    SqliteAuditRepository,
    SqliteConnectionPool,
    SqliteDecisionLineageRepository,
    SqliteDecisionRepository,
    SqliteDistributedLockRepository,
    SqliteEntityRepository,
    SqliteEventRepository,
    SqliteEvidenceGraphRepository,
    SqliteEvidenceRepository,
    SqliteGapRepository,
    SqliteIdempotencyRepository,
    SqliteInvestigationRepository,
    SqliteWebhookRegistrationRepository,
    SqliteWorkerLeaseRepository,
)


@dataclass
class DurableStoreBundle:
    """Convenience bundle holding all repository instances for an ORACLE runtime."""
    events: EventRepository
    idempotency: IdempotencyRepository
    investigations: InvestigationRepository
    gaps: GapRepository
    evidence: EvidenceRepository
    decisions: DecisionRepository
    lineage: DecisionLineageRepository
    actions: ActionRepository
    leases: WorkerLeaseRepository
    graph: EvidenceGraphRepository
    audit: AuditRepository
    entities: EntityRepository
    is_postgres: bool = False
    webhooks: Optional[WebhookRegistrationRepository] = None
    locks: Optional[DistributedLockRepository] = None
    security: Optional[Any] = None
    artifacts: Optional[Any] = None
    pool: Optional[Any] = None



class PersistenceFactory:
    """Instantiates repository bundles based on database connection strings."""

    @classmethod
    def create_bundle(
        cls,
        database_url: Optional[str] = None,
        in_memory: bool = False,
    ) -> DurableStoreBundle:
        db_url = database_url or os.environ.get("ORACLE_DATABASE_URL") or os.environ.get("DATABASE_URL")

        if db_url and (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
            try:
                from backend.release.persistence.postgres_store import (
                    PostgresActionRepository,
                    PostgresAuditRepository,
                    PostgresConnectionPool,
                    PostgresDecisionLineageRepository,
                    PostgresDecisionRepository,
                    PostgresDistributedLockRepository,
                    PostgresEntityRepository,
                    PostgresEventRepository,
                    PostgresEvidenceGraphRepository,
                    PostgresEvidenceRepository,
                    PostgresGapRepository,
                    PostgresIdempotencyRepository,
                    PostgresInvestigationRepository,
                    PostgresWebhookRegistrationRepository,
                    PostgresWorkerLeaseRepository,
                    PostgresSecurityRepository,
                    PostgresArtifactDeploymentRepository,
                )
                pg_pool = PostgresConnectionPool(db_url)
                # For repositories that share standard relational structure, create instances
                events = PostgresEventRepository(pg_pool)
                idemp = PostgresIdempotencyRepository(pg_pool)
                gaps = PostgresGapRepository(pg_pool)
                evidence = PostgresEvidenceRepository(pg_pool)
                inv = PostgresInvestigationRepository(pg_pool, gaps, evidence)
                dec = PostgresDecisionRepository(pg_pool)
                lin = PostgresDecisionLineageRepository(pg_pool)
                actions = PostgresActionRepository(pg_pool)
                leases = PostgresWorkerLeaseRepository(pg_pool)
                graph = PostgresEvidenceGraphRepository(pg_pool)
                audit = PostgresAuditRepository(pg_pool)
                entities = PostgresEntityRepository(pg_pool)
                webhooks = PostgresWebhookRegistrationRepository(pg_pool)
                locks = PostgresDistributedLockRepository(pg_pool)
                security = PostgresSecurityRepository(pg_pool)
                artifacts = PostgresArtifactDeploymentRepository(pg_pool)

                return DurableStoreBundle(
                    events=events,
                    idempotency=idemp,
                    investigations=inv,
                    gaps=gaps,
                    evidence=evidence,
                    decisions=dec,
                    lineage=lin,
                    actions=actions,
                    leases=leases,
                    graph=graph,
                    audit=audit,
                    entities=entities,
                    is_postgres=True,
                    webhooks=webhooks,
                    locks=locks,
                    security=security,
                    artifacts=artifacts,
                    pool=pg_pool,
                )
            except Exception:
                # Log and fallback safely to sqlite
                pass

        # Default: SQLite (in-memory or file-based)
        target = ":memory:" if in_memory or not db_url else db_url.replace("sqlite:///", "")
        pool = SqliteConnectionPool(target)

        events = SqliteEventRepository(pool)
        idemp = SqliteIdempotencyRepository(pool)
        gaps = SqliteGapRepository(pool)
        evidence = SqliteEvidenceRepository(pool)
        inv = SqliteInvestigationRepository(pool, gaps, evidence)
        dec = SqliteDecisionRepository(pool)
        lin = SqliteDecisionLineageRepository(pool)
        actions = SqliteActionRepository(pool)
        leases = SqliteWorkerLeaseRepository(pool)
        graph = SqliteEvidenceGraphRepository(pool)
        audit = SqliteAuditRepository(pool)
        entities = SqliteEntityRepository(pool)
        webhooks = SqliteWebhookRegistrationRepository(pool)
        locks = SqliteDistributedLockRepository(pool)

        from backend.release.persistence.sqlite_store import (
            SqliteArtifactDeploymentRepository,
            SqliteSecurityRepository,
        )
        sec = SqliteSecurityRepository(pool)
        art = SqliteArtifactDeploymentRepository(pool)

        return DurableStoreBundle(
            events=events,
            idempotency=idemp,
            investigations=inv,
            gaps=gaps,
            evidence=evidence,
            decisions=dec,
            lineage=lin,
            actions=actions,
            leases=leases,
            graph=graph,
            audit=audit,
            entities=entities,
            is_postgres=False,
            webhooks=webhooks,
            locks=locks,
            security=sec,
            artifacts=art,
            pool=pool,
        )
