"""
Persistence Subsystem for ORACLE (Brick 4.4)
"""

from backend.release.persistence.factory import DurableStoreBundle, PersistenceFactory
from backend.release.persistence.interfaces import (
    ActionRepository,
    AuditRepository,
    DecisionLineageRepository,
    DecisionRepository,
    EntityRepository,
    EventRepository,
    EvidenceGraphRepository,
    EvidenceRepository,
    GapRepository,
    IdempotencyRepository,
    InvestigationRepository,
    WorkerLeaseRepository,
)
from backend.release.persistence.migrator import DatabaseMigrator
from backend.release.persistence.sqlite_store import (
    SqliteActionRepository,
    SqliteAuditRepository,
    SqliteConnectionPool,
    SqliteDecisionLineageRepository,
    SqliteDecisionRepository,
    SqliteEntityRepository,
    SqliteEventRepository,
    SqliteEvidenceGraphRepository,
    SqliteEvidenceRepository,
    SqliteGapRepository,
    SqliteIdempotencyRepository,
    SqliteInvestigationRepository,
    SqliteWorkerLeaseRepository,
)

__all__ = [
    "DurableStoreBundle",
    "PersistenceFactory",
    "DatabaseMigrator",
    "EventRepository",
    "IdempotencyRepository",
    "InvestigationRepository",
    "GapRepository",
    "EvidenceRepository",
    "DecisionRepository",
    "DecisionLineageRepository",
    "ActionRepository",
    "WorkerLeaseRepository",
    "EvidenceGraphRepository",
    "AuditRepository",
    "EntityRepository",
    "SqliteConnectionPool",
    "SqliteEventRepository",
    "SqliteIdempotencyRepository",
    "SqliteInvestigationRepository",
    "SqliteGapRepository",
    "SqliteEvidenceRepository",
    "SqliteDecisionRepository",
    "SqliteDecisionLineageRepository",
    "SqliteActionRepository",
    "SqliteWorkerLeaseRepository",
    "SqliteEvidenceGraphRepository",
    "SqliteAuditRepository",
    "SqliteEntityRepository",
]
