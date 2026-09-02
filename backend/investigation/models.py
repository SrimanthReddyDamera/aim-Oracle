"""
ORACLE Investigation Models & Epistemic Contracts (Brick 3 & 3.2)
Defines the core data structures for evidence graph modeling, first-class InvestigationGaps,
investigation budgets, deterministic trace events, and the complete EvidencePackage.

EPISTEMIC INVARIANT:
  LLM_INFERENCE edges are investigation hypotheses, NOT factual proof.
  An edge with derived_by == LLM_INFERENCE may guide retrieval queries, but cannot
  independently satisfy factual sufficiency verification.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence


class EdgeDerivationType(str, Enum):
    DETERMINISTIC_REFERENCE = "DETERMINISTIC_REFERENCE"  # Exact regex/token code link (e.g. text cites "INC-402")
    DOCUMENT_METADATA       = "DOCUMENT_METADATA"        # Header, author, date, or manifest metadata
    LLM_INFERENCE           = "LLM_INFERENCE"            # Semantic dependency inferred by the model (HYPOTHESIS ONLY)


class RelationshipType(str, Enum):
    DEPENDS_ON   = "DEPENDS_ON"   # Functional or operational dependency
    SUPERSEDES   = "SUPERSEDES"   # Temporal rollback or replacement of older document
    CONTRADICTS  = "CONTRADICTS"  # Opposing/disputed claims across documents
    REFERENCES   = "REFERENCES"   # Explicit citation of entity, ticket, or code


class EvidenceEdge(BaseModel):
    """
    Directed relationship between two pieces of evidence.
    Carries rigorous provenance on how the link was derived.
    """
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    basis: str                                  # Exact snippet or rationale establishing the link
    derived_by: EdgeDerivationType              # Provenance source
    confidence: float = Field(ge=0.0, le=1.0)   # 1.0 for deterministic; float for inference

    @property
    def is_factual_proof(self) -> bool:
        """
        True if backed by explicit document evidence or deterministic references.
        False if derived solely by LLM inference (hypotheses cannot establish factual proof).
        """
        return self.derived_by != EdgeDerivationType.LLM_INFERENCE


class InvestigationGap(BaseModel):
    """
    First-class deterministic representation of a missing factual requirement (Brick 3.2).
    Tracks the full lifecycle of what evidence prompted the gap, what queries were attempted,
    and what evidence objects ultimately resolved it.
    """
    gap_id: str
    description: str
    originating_evidence_ids: List[str] = Field(default_factory=list)
    required_information: str = ""
    candidate_queries: List[str] = Field(default_factory=list)
    attempted_queries: List[str] = Field(default_factory=list)
    resolution_status: bool = False
    resolution_evidence_ids: List[str] = Field(default_factory=list)

    # Backwards compatibility properties for Brick 3.0 / 3.1 code
    priority: int = Field(default=1, ge=1, le=3)
    targeted_query: str = ""
    rationale: str = ""

    @property
    def resolved(self) -> bool:
        return self.resolution_status

    @resolved.setter
    def resolved(self, value: bool):
        self.resolution_status = value


# Type alias for complete backward compatibility
InformationGap = InvestigationGap


class InvestigationBudget(BaseModel):
    """
    Configurable resource ceilings for an investigation run.
    """
    max_hops: int = 3
    max_llm_calls: int = 3
    max_queries: int = 6
    max_total_chunks: int = 15
    max_wall_time_seconds: float = 30.0


class InvestigationEvent(BaseModel):
    """
    Deterministic audit event recording every action and decision taken by the controller.
    Ensures complete transparency into:
      - what was searched
      - which evidence was found
      - which contradictions existed
      - why investigation continued
      - why it terminated
    """
    hop: int
    event_type: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class InvestigationState(BaseModel):
    """
    Accumulated state across investigation iterations.
    """
    objective: str
    accumulated_evidence: Dict[str, Evidence] = Field(default_factory=dict)
    evidence_graph: List[EvidenceEdge] = Field(default_factory=list)
    pending_gaps: List[InvestigationGap] = Field(default_factory=list)
    resolved_gaps: List[InvestigationGap] = Field(default_factory=list)
    executed_queries: Set[str] = Field(default_factory=set)
    zero_yield_queries: Set[str] = Field(default_factory=set)
    unresolved_references: Set[str] = Field(default_factory=set)
    investigation_trace: List[InvestigationEvent] = Field(default_factory=list)
    hop_count: int = 0
    llm_call_count: int = 0
    is_sufficient: bool = False
    termination_reason: Optional[str] = None


class EvidencePackage(BaseModel):
    """
    The final immutable deliverable of the Investigation Engine.
    Delivered to downstream reasoning layers.
    """
    objective: str
    termination_reason: str
    controller_verified: bool
    budget_summary: Dict[str, Any]
    evidence_items: List[Evidence]
    graph_edges: List[EvidenceEdge]
    gap_history: List[Dict[str, Any]]
    investigation_trace: List[InvestigationEvent] = Field(default_factory=list)
    gaps: List[InvestigationGap] = Field(default_factory=list)
