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
from typing import Any, Dict, List, Optional, Set, Union
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
    OPEN                    = "OPEN"                    # Identified and awaiting planning/dispatch
    PLANNED                 = "PLANNED"                 # Formulated with candidate query/action
    SEARCHING               = "SEARCHING"               # Retrieval action in flight
    INVESTIGATING           = "INVESTIGATING"           # Retrieval action in flight (backwards compatibility)
    UNDER_REVIEW            = "UNDER_REVIEW"            # Evidence collected, evaluating criteria
    RESOLVED                = "RESOLVED"                # Sufficient uncontested evidence collected
    UNRESOLVED              = "UNRESOLVED"              # Attempted; chunks failed requirement
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED" # Evidence found, but opposing claims detected
    BLOCKED                 = "BLOCKED"                 # Exhausted strategies; unanswerable in corpus
    REOPENED                = "REOPENED"                # Later evidence invalidated earlier resolution
    DEPENDENCY_UNSATISFIED  = "DEPENDENCY_UNSATISFIED"  # Upstream prerequisite gap is unresolved, blocked, or invalidated


VALID_GAP_TRANSITIONS: Dict[GapStatus, Set[GapStatus]] = {
    GapStatus.OPEN: {
        GapStatus.PLANNED,
        GapStatus.SEARCHING,
        GapStatus.INVESTIGATING,
        GapStatus.UNDER_REVIEW,
        GapStatus.RESOLVED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.UNRESOLVED,
        GapStatus.BLOCKED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.PLANNED: {
        GapStatus.SEARCHING,
        GapStatus.INVESTIGATING,
        GapStatus.UNDER_REVIEW,
        GapStatus.OPEN,
        GapStatus.BLOCKED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.SEARCHING: {
        GapStatus.UNDER_REVIEW,
        GapStatus.UNRESOLVED,
        GapStatus.BLOCKED,
        GapStatus.RESOLVED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.INVESTIGATING: {
        GapStatus.UNDER_REVIEW,
        GapStatus.UNRESOLVED,
        GapStatus.BLOCKED,
        GapStatus.RESOLVED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.UNDER_REVIEW: {
        GapStatus.RESOLVED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.UNRESOLVED,
        GapStatus.BLOCKED,
        GapStatus.OPEN,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.RESOLVED: {
        GapStatus.REOPENED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.OPEN,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.UNRESOLVED: {
        GapStatus.PLANNED,
        GapStatus.SEARCHING,
        GapStatus.INVESTIGATING,
        GapStatus.UNDER_REVIEW,
        GapStatus.RESOLVED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.BLOCKED,
        GapStatus.OPEN,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.RECONCILIATION_REQUIRED: {
        GapStatus.RESOLVED,
        GapStatus.REOPENED,
        GapStatus.BLOCKED,
        GapStatus.UNDER_REVIEW,
        GapStatus.SEARCHING,
        GapStatus.INVESTIGATING,
        GapStatus.OPEN,
        GapStatus.PLANNED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.BLOCKED: {
        GapStatus.OPEN,
        GapStatus.PLANNED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.REOPENED: {
        GapStatus.PLANNED,
        GapStatus.SEARCHING,
        GapStatus.INVESTIGATING,
        GapStatus.UNDER_REVIEW,
        GapStatus.RESOLVED,
        GapStatus.RECONCILIATION_REQUIRED,
        GapStatus.DEPENDENCY_UNSATISFIED,
    },
    GapStatus.DEPENDENCY_UNSATISFIED: {
        GapStatus.PLANNED,
        GapStatus.OPEN,
        GapStatus.SEARCHING,
        GapStatus.BLOCKED,
        GapStatus.REOPENED,
        GapStatus.RESOLVED,
    },
}


class InvalidGapTransitionError(ValueError):
    """Raised when an illegal gap state transition is attempted."""
    pass


# -----------------------------------------------------------------------------
# HYPOTHESIS & ACTION MODELS
# -----------------------------------------------------------------------------
class InvestigationHypothesis(BaseModel):
    """Working hypothesis formed during investigation planning."""
    hypothesis_id: str
    statement: str
    status: str = "PROPOSED"  # PROPOSED, SUPPORTED, REFUTED, INCONCLUSIVE
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    conflicting_evidence_ids: List[str] = Field(default_factory=list)
    rationale: str = ""


class ActionType(str, Enum):
    SEARCH = "SEARCH"
    EVALUATE = "EVALUATE"
    RECONCILE = "RECONCILE"


class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


class InvestigationAction(BaseModel):
    """Controller-governed targeted action tied to an originating InformationGap."""
    action_id: str
    gap_id: str
    action_type: ActionType = ActionType.SEARCH
    query: str
    reason: str
    status: ActionStatus = ActionStatus.PROPOSED
    rejection_reason: Optional[str] = None
    created_at_hop: int = 0
    executed_at_hop: Optional[int] = None
    yield_chunk_count: int = 0


class InformationGap(BaseModel):
    """
    First-class domain-agnostic representation of a discrete factual requirement.
    Managed strictly by the Controller state machine.
    """
    gap_id: str
    gap_type: Union[GapType, str] = GapType.PREREQUISITE
    priority_score: float = 0.0                      # Deterministically computed by Controller
    is_blocking: bool = True                         # If True, must be resolved/reconciled for sufficiency
    description: str
    why_needed: str = ""                             # Epistemic reason why this information is needed
    evidence_requirement: str = ""                   # Specific evidence/facts required to resolve
    target_entity: str = ""                          # Generic entity token or component
    required_information: str = ""                   # Specific factual question to be proven
    required_facts: List[str] = Field(default_factory=list) # Discrete factual requirements that must all be satisfied
    originating_evidence_ids: List[str] = Field(default_factory=list)

    status: GapStatus = GapStatus.OPEN
    depends_on_gap_ids: List[str] = Field(default_factory=list) # Upstream prerequisite gap IDs required before this gap can be satisfied
    dependent_gap_ids: List[str] = Field(default_factory=list)  # Downstream gap IDs that depend on this gap
    unsatisfied_prerequisites: List[str] = Field(default_factory=list) # Currently unresolved or blocked upstream prerequisite gap IDs
    related_hypothesis: Optional[str] = None
    related_claim: Optional[str] = None
    attempt_count: int = 0
    max_attempts: int = 2
    attempted_queries: List[str] = Field(default_factory=list)
    attempted_actions: List[InvestigationAction] = Field(default_factory=list)
    resolution_evidence_ids: List[str] = Field(default_factory=list)
    conflicting_evidence_ids: List[str] = Field(default_factory=list)
    resolution: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    gap_version: int = 0

    # Backwards compatibility attributes for earlier bricks
    candidate_queries: List[str] = Field(default_factory=list)
    priority: int = Field(default=1, ge=1, le=3)
    targeted_query: str = ""
    rationale: str = ""

    def __init__(self, **data: Any):
        if "why_needed" in data and not data.get("rationale"):
            data["rationale"] = data["why_needed"]
        elif "rationale" in data and not data.get("why_needed"):
            data["why_needed"] = data["rationale"]
        if "evidence_requirement" in data and not data.get("required_information"):
            data["required_information"] = data["evidence_requirement"]
        elif "required_information" in data and not data.get("evidence_requirement"):
            data["evidence_requirement"] = data["required_information"]
        if "evidence_references" in data and not data.get("resolution_evidence_ids"):
            data["resolution_evidence_ids"] = data["evidence_references"]
        if "conflicting_evidence_references" in data and not data.get("conflicting_evidence_ids"):
            data["conflicting_evidence_ids"] = data["conflicting_evidence_references"]
        super().__init__(**data)

    @property
    def evidence_references(self) -> List[str]:
        return self.resolution_evidence_ids

    @evidence_references.setter
    def evidence_references(self, val: List[str]):
        self.resolution_evidence_ids = val

    @property
    def conflicting_evidence_references(self) -> List[str]:
        return self.conflicting_evidence_ids

    @conflicting_evidence_references.setter
    def conflicting_evidence_references(self, val: List[str]):
        self.conflicting_evidence_ids = val

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


class InvestigationPlan(BaseModel):
    """Investigation plan generated at investigation onset."""
    objective: str
    hypotheses: List[InvestigationHypothesis] = Field(default_factory=list)
    gaps: List[InformationGap] = Field(default_factory=list)
    planned_actions: List[InvestigationAction] = Field(default_factory=list)


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

    # Hypotheses
    hypotheses: List[InvestigationHypothesis] = Field(default_factory=list)

    # Evidence Ledger
    discovered_evidence: Dict[str, Evidence] = Field(default_factory=dict)
    unresolved_references: Set[str] = Field(default_factory=set)

    # Gap Ledger
    gaps: Dict[str, InformationGap] = Field(default_factory=dict)
    detected_contradictions: List[ContradictionRecord] = Field(default_factory=list)

    # Action & Retrieval History
    actions: List[InvestigationAction] = Field(default_factory=list)
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
    session_version: int = 0

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
    hypotheses: List[InvestigationHypothesis] = Field(default_factory=list)
    actions: List[InvestigationAction] = Field(default_factory=list)
    evidence_items: List[Evidence]
    graph_edges: List[EvidenceEdge]
    gap_history: List[Dict[str, Any]]
    investigation_trace: List[InvestigationEvent] = Field(default_factory=list)
    gaps: List[InformationGap] = Field(default_factory=list)
    retrieval_telemetry: Optional[RetrievalDecisionTelemetry] = None
    federated_telemetry: Optional[Dict[str, Any]] = None

    def to_observable_dict(self) -> Dict[str, Any]:
        """Expose structured investigation state for UI visualization and API consumers."""
        return {
            "objective": self.objective,
            "controller_verified": self.controller_verified,
            "termination_reason": self.termination_reason,
            "budget_summary": self.budget_summary,
            "hypotheses": [h.model_dump() for h in self.hypotheses],
            "gaps": [
                {
                    "gap_id": g.gap_id,
                    "gap_type": g.gap_type.value if hasattr(g.gap_type, "value") else str(g.gap_type),
                    "status": g.status.value if hasattr(g.status, "value") else str(g.status),
                    "priority_score": g.priority_score,
                    "is_blocking": g.is_blocking,
                    "description": g.description,
                    "why_needed": g.why_needed,
                    "evidence_requirement": g.evidence_requirement,
                    "target_entity": g.target_entity,
                    "resolution": g.resolution,
                    "resolution_evidence_ids": g.resolution_evidence_ids,
                    "conflicting_evidence_ids": g.conflicting_evidence_ids,
                    "attempted_queries": g.attempted_queries,
                    "provenance": g.provenance,
                    "gap_version": g.gap_version,
                }
                for g in self.gaps
            ],
            "actions": [a.model_dump() for a in self.actions],
            "evidence_items": [
                {
                    "evidence_id": e.evidence_id,
                    "source_id": e.source_id,
                    "source_path": e.source_path,
                    "content_preview": e.content[:150],
                    "content_hash": e.content_hash,
                }
                for e in self.evidence_items
            ],
            "graph_edges": [edge.model_dump() for edge in self.graph_edges],
            "investigation_trace": [t.model_dump() for t in self.investigation_trace],
            "retrieval_telemetry": self.retrieval_telemetry.model_dump() if self.retrieval_telemetry else None,
            "federated_telemetry": self.federated_telemetry,
        }
