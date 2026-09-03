"""
ORACLE Investigation Models & Epistemic Contracts (Brick 3.4 Revision v2 + Brick 3.7 Adaptive Retrieval)
Defines domain-agnostic data structures for evidence graphs, first-class InformationGaps,
in-memory InvestigationSession, and the final EvidencePackage.

EPISTEMIC INVARIANTS:
  - The Controller owns all mutable state and gap transitions.
  - The LLM has NO authority over sufficiency, truth, priority, or termination.
  - LLM_INFERENCE edges are investigation hypotheses, NOT factual proof.
  - Evidence sufficiency is separated from truth: conflicting claims transition
    to RECONCILIATION_REQUIRED, never marked uncontested RESOLVED.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence


# -----------------------------------------------------------------------------
# GRAPH & EDGE ENUMS
# -----------------------------------------------------------------------------
class EdgeDerivationType(str, Enum):
    DETERMINISTIC_REFERENCE = "DETERMINISTIC_REFERENCE"  # Exact regex/token code citation
    DOCUMENT_METADATA       = "DOCUMENT_METADATA"        # Header, author, date, or manifest metadata
    LLM_INFERENCE           = "LLM_INFERENCE"            # Semantic dependency inferred by model (HYPOTHESIS ONLY)


class RelationshipType(str, Enum):
    DEPENDS_ON   = "DEPENDS_ON"   # Functional or operational dependency
    SUPERSEDES   = "SUPERSEDES"   # Temporal rollback or replacement of older document
    CONTRADICTS  = "CONTRADICTS"  # Opposing/disputed claims across documents
    REFERENCES   = "REFERENCES"   # Citation of entity, ticket, or code


class EvidenceEdge(BaseModel):
    """Directed relationship between two pieces of evidence with provenance."""
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    basis: str
    derived_by: EdgeDerivationType
    confidence: float = Field(ge=0.0, le=1.0)

    @property
    def is_factual_proof(self) -> bool:
        return self.derived_by != EdgeDerivationType.LLM_INFERENCE


# -----------------------------------------------------------------------------
# GAP DOMAIN MODELS (GENERIC & DOMAIN-AGNOSTIC)
# -----------------------------------------------------------------------------
class GapType(str, Enum):
    OBJECTIVE_ROOT               = "OBJECTIVE_ROOT"               # Direct requirement from root objective
    PREREQUISITE                 = "PREREQUISITE"                 # Stated operational requirement/dependency
    AUTHORITY_RESOLUTION         = "AUTHORITY_RESOLUTION"         # Decision, approval, or disposition needed
    STATE_VERIFICATION           = "STATE_VERIFICATION"           # Active version, status, or parameter
    CONTRADICTION_RECONCILIATION = "CONTRADICTION_RECONCILIATION" # Opposing claims requiring arbitration


class GapStatus(str, Enum):
    OPEN                    = "OPEN"                    # Identified and awaiting retrieval
    INVESTIGATING           = "INVESTIGATING"           # Retrieval action in flight
    RESOLVED                = "RESOLVED"                # Sufficient uncontested evidence collected
    UNRESOLVED              = "UNRESOLVED"              # Attempted; chunks failed requirement
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED" # Evidence found, but opposing claims detected
    BLOCKED                 = "BLOCKED"                 # Exhausted strategies; unanswerable in corpus


class InformationGap(BaseModel):
    """
    First-class domain-agnostic representation of a discrete factual requirement.
    Managed strictly by the Controller state machine.
    """
    gap_id: str
    gap_type: GapType = GapType.OBJECTIVE_ROOT
    priority_score: float = 0.0                      # Deterministically computed by Controller
    is_blocking: bool = True                         # If True, must be resolved/reconciled for sufficiency
    description: str
    target_entity: str = ""                          # Generic entity token or component
    required_information: str = ""                   # Specific factual question to be proven
    originating_evidence_ids: List[str] = Field(default_factory=list)

    status: GapStatus = GapStatus.OPEN
    attempt_count: int = 0
    max_attempts: int = 2
    attempted_queries: List[str] = Field(default_factory=list)
    resolution_evidence_ids: List[str] = Field(default_factory=list)
    conflicting_evidence_ids: List[str] = Field(default_factory=list)

    # Backwards compatibility attributes for earlier bricks
    candidate_queries: List[str] = Field(default_factory=list)
    priority: int = Field(default=1, ge=1, le=3)
    targeted_query: str = ""
    rationale: str = ""

    @property
    def resolved(self) -> bool:
        return self.status in [GapStatus.RESOLVED, GapStatus.RECONCILIATION_REQUIRED]

    @property
    def resolution_status(self) -> bool:
        return self.resolved

    @resolution_status.setter
    def resolution_status(self, val: bool):
        if val:
            if self.conflicting_evidence_ids:
                self.status = GapStatus.RECONCILIATION_REQUIRED
            else:
                self.status = GapStatus.RESOLVED
        else:
            if self.attempt_count >= self.max_attempts:
                self.status = GapStatus.BLOCKED
            else:
                self.status = GapStatus.UNRESOLVED


InvestigationGap = InformationGap  # Full backward alias


# -----------------------------------------------------------------------------
# CONTRADICTION & SESSION MODELS (IN-MEMORY ONLY)
# -----------------------------------------------------------------------------
class ContradictionRecord(BaseModel):
    """Tracks opposing claims discovered across evidence chunks."""
    contradiction_id: str
    claim_a_evidence_id: str
    claim_b_evidence_id: str
    conflicting_subject: str
    basis: str
    reconciled: bool = False
    authoritative_evidence_id: Optional[str] = None


class InvestigationSession(BaseModel):
    """
    Lightweight in-memory session container for an active investigation.
    Zero database persistence required; strictly in RAM (< 350 KB per session).
    """
    session_id: str
    objective: str

    # Evidence Ledger
    discovered_evidence: Dict[str, Evidence] = Field(default_factory=dict)
    unresolved_references: Set[str] = Field(default_factory=set)

    # Gap Ledger
    gaps: Dict[str, InformationGap] = Field(default_factory=dict)
    detected_contradictions: List[ContradictionRecord] = Field(default_factory=list)

    # Action & Retrieval History
    query_history: Set[str] = Field(default_factory=set)
    zero_yield_queries: Set[str] = Field(default_factory=set)

    # Resource & Lifecycle Counters
    hop_count: int = 0
    llm_call_count: int = 0
    max_hops: int = 3
    max_llm_calls: int = 3
    max_queries: int = 6
    max_wall_time_seconds: float = 30.0

    is_sufficient: bool = False
    termination_reason: Optional[str] = None

    # Audit Trail
    investigation_trace: List[Any] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# CONTROLLER TRACE & PACKAGE MODELS
# -----------------------------------------------------------------------------
class InvestigationBudget(BaseModel):
    max_hops: int = 3
    max_llm_calls: int = 3
    max_queries: int = 6
    max_total_chunks: int = 15
    max_wall_time_seconds: float = 30.0


class InvestigationEvent(BaseModel):
    hop: int
    event_type: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class InvestigationState(BaseModel):
    """Legacy state container kept for full interface compatibility."""
    objective: str
    accumulated_evidence: Dict[str, Evidence] = Field(default_factory=dict)
    evidence_graph: List[EvidenceEdge] = Field(default_factory=list)
    pending_gaps: List[InformationGap] = Field(default_factory=list)
    resolved_gaps: List[InformationGap] = Field(default_factory=list)
    executed_queries: Set[str] = Field(default_factory=set)
    zero_yield_queries: Set[str] = Field(default_factory=set)
    unresolved_references: Set[str] = Field(default_factory=set)
    investigation_trace: List[InvestigationEvent] = Field(default_factory=list)
    hop_count: int = 0
    llm_call_count: int = 0
    is_sufficient: bool = False
    termination_reason: Optional[str] = None


# -----------------------------------------------------------------------------
# ADAPTIVE RETRIEVAL CONFIG & TELEMETRY (BRICK 3.7)
# -----------------------------------------------------------------------------
class AdaptiveRetrievalConfig(BaseModel):
    """
    Deterministic configuration for controller-owned adaptive candidate window expansion.
    Fully domain-agnostic and runtime-configurable.
    """
    initial_k: int = 8
    expansion_k: int = 10
    decay_threshold: float = 0.50
    min_score: float = 2.40
    source_concentration_threshold: float = 0.625
    max_expansions: int = 1
    enabled: bool = True


class RetrievalDecisionTelemetry(BaseModel):
    """
    Deterministic audit trail for every retrieval admission decision.
    """
    initial_k: int
    final_k: int
    rank_4_score: float
    rank_8_score: float
    decay_ratio: float
    min_score: float
    source_concentration: float
    reference_affinity: bool
    expansion_triggers: List[str] = Field(default_factory=list)
    expanded: bool
    retrieved_evidence_ids: List[str] = Field(default_factory=list)


class EvidencePackage(BaseModel):
    """The final deliverable delivered to downstream reasoning layers."""
    objective: str
    termination_reason: str
    controller_verified: bool
    budget_summary: Dict[str, Any]
    evidence_items: List[Evidence]
    graph_edges: List[EvidenceEdge]
    gap_history: List[Dict[str, Any]]
    investigation_trace: List[InvestigationEvent] = Field(default_factory=list)
    gaps: List[InformationGap] = Field(default_factory=list)
    retrieval_telemetry: Optional[RetrievalDecisionTelemetry] = None
    federated_telemetry: Optional[Dict[str, Any]] = None
