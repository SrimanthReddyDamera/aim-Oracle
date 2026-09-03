"""
ORACLE Epistemic Synthesis Models (Brick 4.0)
Defines domain-agnostic data structures for claims, causal relationships,
exact provenance citations, and structured synthesis results.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SynthesisStatus(str, Enum):
    SUCCESS                 = "SUCCESS"
    INSUFFICIENT_EVIDENCE   = "INSUFFICIENT_EVIDENCE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class ClaimType(str, Enum):
    FACTUAL_ASSERTION = "FACTUAL_ASSERTION"   # Direct verified statement of fact
    DEPENDENCY        = "DEPENDENCY"          # Operational or functional prerequisite
    DECISION          = "DECISION"            # Authoritative sign-off, approval, or rejection
    STATE_OBSERVATION = "STATE_OBSERVATION"   # Observed configuration, version, or status
    CAUSAL_LINK       = "CAUSAL_LINK"         # Statement of cause-and-effect relationship


class VerificationState(str, Enum):
    VERIFIED   = "VERIFIED"     # 100% supported by admitted Evidence items
    UNVERIFIED = "UNVERIFIED"   # Claim lacks direct evidence backing
    CONTESTED  = "CONTESTED"    # Subject to opposing/contradictory evidence


class Claim(BaseModel):
    """
    Atomic unit of synthesized knowledge supported by verified evidence.
    Candidate claims may enter with empty evidence_ids, but only claims with
    >= 1 admitted Evidence object pass the Grounding Gate.
    """
    claim_id: str
    statement: str
    evidence_ids: List[str] = Field(default_factory=list, description="Admitted evidence IDs backing this claim")
    verbatim_anchor: Optional[str] = Field(default=None, description="Exact verbatim substring from cited evidence proving the claim")
    claim_type: ClaimType = ClaimType.FACTUAL_ASSERTION
    verification_state: VerificationState = VerificationState.VERIFIED
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    causal_predecessors: List[str] = Field(default_factory=list, description="IDs of claims that caused or preceded this claim")


class Citation(BaseModel):
    """
    Deterministic citation preserving exact provenance back to the origin resource.
    Never fabricated or approximated by LLM.
    """
    citation_id: str                         # Sequential marker, e.g. "cit_1" or "[1]"
    evidence_id: str                         # Foreign key to admitted Evidence
    source_type: str                         # Provider or source type identifier (generic string)
    source_uri: Optional[str] = None         # Remote HTTPS permalink or file path
    display_reference: str                   # Human-readable reference
    start_offset: int                        # Start byte offset in original source
    end_offset: int                          # End byte offset in original source
    content_hash: str                        # Cryptographic SHA-256 hash of evidence content
    content_preview: str                     # Short verbatim excerpt for auditability


class InsufficientEvidenceReport(BaseModel):
    """Structured report returned whenever evidence is insufficient for definitive claims."""
    objective: str
    what_is_known: List[str] = Field(default_factory=list)
    missing_requirements: List[str] = Field(default_factory=list)
    open_gaps: List[Dict[str, Any]] = Field(default_factory=list)
    suggested_investigation_queries: List[str] = Field(default_factory=list)


class ReconciliationReport(BaseModel):
    """Structured report returned whenever contradictory evidence cannot be silently resolved."""
    objective: str
    contradictions: List[Dict[str, Any]] = Field(default_factory=list)
    opposing_claims: List[Dict[str, Any]] = Field(default_factory=list)
    arbitration_basis: Optional[str] = None


class SynthesisResult(BaseModel):
    """The final authoritative deliverable of the ORACLE synthesis layer."""
    status: SynthesisStatus
    objective: str
    final_answer: str                        # Formatted answer with inline [1], [2] citations or explanation
    claims: List[Claim] = Field(default_factory=list)
    citations: List[Citation] = Field(default_factory=list)
    insufficient_report: Optional[InsufficientEvidenceReport] = None
    reconciliation_report: Optional[ReconciliationReport] = None
    evidence_count: int = 0
    synthesis_wall_time_ms: float = 0.0
