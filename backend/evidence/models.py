"""
ORACLE Evidence Models (Brick 2A)
Defines the atomic Evidence object representing normalized chunks with byte-level provenance.
"""

from typing import Any, Dict, Optional, Tuple
from pydantic import BaseModel, Field, model_validator


class Evidence(BaseModel):
    """
    Atomic unit of factual knowledge in ORACLE.
    Maintains exact byte-level provenance back to the raw source file.
    
    Identity Guarantee:
      The canonical identity of an Evidence object is strictly determined by:
      (evidence_id, source_id, content_hash, start_offset, end_offset).
      Runtime fields such as 'created_at' represent ingestion metadata only
      and do NOT participate in evidence equality or cryptographic identity.
    """
    evidence_id: str = Field(description="Unique deterministic ID (e.g. DOC-ARCH#c001)")
    source_id: str = Field(description="Identifier of the origin document")
    source_type: str = Field(default="document", description="Source classification ('document', 'jira', 'linear', 'github', 'slack')")
    uri: Optional[str] = Field(default=None, description="Canonical URI or deeplink to origin resource")
    content: str = Field(description="Normalized textual content of the chunk")
    content_hash: str = Field(description="SHA-256 hash of the content")
    source_path: str = Field(description="Relative path to the source file on disk")
    chunk_index: int = Field(ge=0, description="Zero-indexed position of chunk in source document")
    start_offset: int = Field(ge=0, description="Start byte offset in original UTF-8 file")
    end_offset: int = Field(ge=0, description="End byte offset in original UTF-8 file")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Structural metadata (headers, tags)")
    created_at: str = Field(description="Ingestion timestamp (metadata only)")

    @model_validator(mode="after")
    def validate_offsets(self) -> "Evidence":
        if self.start_offset > self.end_offset:
            raise ValueError(
                f"start_offset ({self.start_offset}) cannot be greater than end_offset ({self.end_offset})"
            )
        return self

    def canonical_identity(self) -> Tuple[str, str, str, int, int]:
        """
        Returns the content-derived, platform-invariant identity tuple.
        Guaranteed to be identical across runs, machines, and execution environments.
        """
        return (
            self.evidence_id,
            self.source_id,
            self.content_hash,
            self.start_offset,
            self.end_offset,
        )
