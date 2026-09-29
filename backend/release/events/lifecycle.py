"""
Evidence Lifecycle & Versioning Management (Brick 4.3)

Enforces explicit evidence lifecycle states:
- VALID: Current, admissible evidence satisfying release requirements.
- STALE: Obsolete due to commit push, code change, or temporal drift.
- SUPERSEDED: Replaced by newer evidence versions.
- REJECTED: Discarded due to foreign repository or schema invalidity.
- CONTRADICTED: Irreconcilably opposed by verified cross-system claims.
- EXPIRED: Past TTL validity window.

Invariants:
1. Evidence is NEVER deleted when it becomes stale; full historical provenance is preserved.
2. Stale or superseded evidence CANNOT satisfy active DAG gaps.
3. Decision audit trails maintain complete before-and-after evidence lineage.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceState(str, Enum):
    """Authoritative lifecycle state of an evidence record."""
    VALID        = "VALID"
    STALE        = "STALE"
    SUPERSEDED   = "SUPERSEDED"
    REJECTED     = "REJECTED"
    CONTRADICTED = "CONTRADICTED"
    EXPIRED      = "EXPIRED"


class EvidenceLifecycleRecord(BaseModel):
    """Historical lifecycle audit container for an Evidence entity."""
    evidence_id: str
    state: EvidenceState = EvidenceState.VALID
    version: int = 1
    superseded_by: Optional[str] = None
    invalidated_by_event_id: Optional[str] = None
    invalidation_reason: Optional[str] = None
    created_at: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    transition_history: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def current_state(self) -> EvidenceState:
        return self.state

    @property
    def transitions(self) -> List[Dict[str, Any]]:
        return self.transition_history

    @property
    def superseded_by_evidence_id(self) -> Optional[str]:
        return self.superseded_by


class EvidenceLifecycleManager:
    """
    Thread-safe manager governing evidence state transitions and version lineage.
    """

    def __init__(self):
        self._records: Dict[str, EvidenceLifecycleRecord] = {}
        self._lock = threading.RLock()

    def register_evidence(
        self,
        evidence_id: str,
        initial_state: EvidenceState = EvidenceState.VALID,
    ) -> EvidenceLifecycleRecord:
        """Register or retrieve an evidence lifecycle record."""
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            if evidence_id not in self._records:
                rec = EvidenceLifecycleRecord(
                    evidence_id=evidence_id,
                    state=initial_state,
                    version=1,
                    transition_history=[
                        {"from_state": None, "to_state": initial_state.value, "timestamp": now_ts, "reason": "Initial ingestion"}
                    ],
                )
                self._records[evidence_id] = rec
            return self._records[evidence_id]

    def mark_stale(
        self,
        evidence_id: str,
        event_id: str = "",
        reason: str = "Invalidated by event",
    ) -> EvidenceLifecycleRecord:
        """Transition evidence from VALID to STALE."""
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            rec = self.register_evidence(evidence_id)
            prev_state = rec.state
            rec.state = EvidenceState.STALE
            rec.invalidated_by_event_id = event_id
            rec.invalidation_reason = reason
            rec.transition_history.append({
                "from_state": prev_state.value,
                "to_state": EvidenceState.STALE.value,
                "event_id": event_id,
                "timestamp": now_ts,
                "reason": reason,
            })
            return rec

    def mark_superseded(
        self,
        evidence_id: str,
        new_evidence_id: Optional[str] = None,
        event_id: str = "",
        reason: str = "Superseded by newer evidence",
        superseding_evidence_id: Optional[str] = None,
    ) -> EvidenceLifecycleRecord:
        """Transition evidence to SUPERSEDED, linking its replacement."""
        replacement_id = new_evidence_id or superseding_evidence_id or ""
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            rec = self.register_evidence(evidence_id)
            prev_state = rec.state
            rec.state = EvidenceState.SUPERSEDED
            rec.superseded_by = replacement_id
            rec.invalidated_by_event_id = event_id
            rec.invalidation_reason = reason
            rec.transition_history.append({
                "from_state": prev_state.value,
                "to_state": EvidenceState.SUPERSEDED.value,
                "superseded_by": replacement_id,
                "event_id": event_id,
                "timestamp": now_ts,
                "reason": reason,
            })
            return rec

    def get_state(self, evidence_id: str) -> EvidenceState:
        with self._lock:
            rec = self._records.get(evidence_id)
            return rec.state if rec else EvidenceState.VALID

    def is_admissible(self, evidence_id: str) -> bool:
        """Only VALID evidence may satisfy active release gaps."""
        return self.get_state(evidence_id) == EvidenceState.VALID

    def get_record(self, evidence_id: str) -> Optional[EvidenceLifecycleRecord]:
        with self._lock:
            return self._records.get(evidence_id)

    def get_all_records(self) -> Dict[str, EvidenceLifecycleRecord]:
        with self._lock:
            return dict(self._records)
