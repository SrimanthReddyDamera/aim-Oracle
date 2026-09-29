"""
ORACLE Event-Driven Intelligence & Evidence Graph (Brick 4.3)

Provides continuously event-aware enterprise intelligence:
- Canonical EnterpriseEvent & EnterpriseEventType taxonomy
- Normalizers for GitHub, Jira, and Security webhooks
- WebhookSecurityValidator (HMAC-SHA256, constant-time comparison, replay protection)
- EventIdempotencyManager (atomic check-and-set duplicate suppression)
- DeterministicEntityResolver (domain-grounded release/entity mapping)
- InvestigationImpactAnalyzer (targeted DAG invalidation)
- EvidenceLifecycleManager (VALID, STALE, SUPERSEDED state transitions)
- EvidenceGraph (17 node types, 17 edge types, temporal validity)
- DecisionLineageTracker (explainable decision shifts e.g. READY -> BLOCKED)
- EventRouter (end-to-end webhook ingestion & targeted re-investigation)
"""

from backend.release.events.models import (
    DecisionChangeEvent,
    EnterpriseEvent,
    EnterpriseEventType,
)
from backend.release.events.normalizers import (
    EventNormalizer,
    GitHubEventNormalizer,
    JiraEventNormalizer,
    SecurityEventNormalizer,
)
from backend.release.events.security import (
    WebhookReplayError,
    WebhookSecurityError,
    WebhookSecurityValidator,
    WebhookSignatureError,
)
from backend.release.events.idempotency import EventIdempotencyManager
from backend.release.events.resolver import DeterministicEntityResolver
from backend.release.events.impact import (
    ImpactAnalysisResult,
    InvestigationImpactAnalyzer,
)
from backend.release.events.lifecycle import (
    EvidenceLifecycleManager,
    EvidenceLifecycleRecord,
    EvidenceState,
)
from backend.release.events.graph import (
    EvidenceGraph,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)
from backend.release.events.lineage import (
    DecisionLineageRecord,
    DecisionLineageTracker,
)
from backend.release.events.router import EventRouter, IngestionReceipt

__all__ = [
    "EnterpriseEventType",
    "EnterpriseEvent",
    "DecisionChangeEvent",
    "EventNormalizer",
    "GitHubEventNormalizer",
    "JiraEventNormalizer",
    "SecurityEventNormalizer",
    "WebhookSecurityError",
    "WebhookSignatureError",
    "WebhookReplayError",
    "WebhookSecurityValidator",
    "EventIdempotencyManager",
    "DeterministicEntityResolver",
    "ImpactAnalysisResult",
    "InvestigationImpactAnalyzer",
    "EvidenceState",
    "EvidenceLifecycleRecord",
    "EvidenceLifecycleManager",
    "GraphNodeType",
    "GraphEdgeType",
    "GraphNode",
    "GraphEdge",
    "EvidenceGraph",
    "DecisionLineageRecord",
    "DecisionLineageTracker",
    "EventRouter",
    "IngestionReceipt",
]
