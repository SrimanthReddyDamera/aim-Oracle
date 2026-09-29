"""
Decision Lineage & Change Explainability (Brick 4.3)

Maintains immutable decision lineages per release candidate.
Answers:
- "What evidence supported the previous decision?"
- "What changed?"
- "Which evidence became stale?"
- "Why did the decision change?"
Emits DecisionChangeEvent whenever sovereign decision outcomes transition.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.release.events.models import DecisionChangeEvent, EnterpriseEvent
from backend.release.models import ReleaseDecision, ReleaseDecisionOutcome


class DecisionLineageRecord(BaseModel):
    """Chronological record of a decision state, its backing evidence, and its cause."""
    record_id: str
    release_id: str
    decision: ReleaseDecision
    trigger_event: Optional[EnterpriseEvent] = None
    invalidated_evidence_ids: List[str] = Field(default_factory=list)
    new_evidence_ids: List[str] = Field(default_factory=list)
    change_reason: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


class DecisionLineageTracker:
    """
    Thread-safe engine tracking decision transitions and constructing natural-language explanations.
    """

    def __init__(self):
        self._history: Dict[str, List[DecisionLineageRecord]] = {}  # release_id -> list of records
        self._lock = threading.RLock()

    def record_decision(
        self,
        release_id: str,
        decision: ReleaseDecision,
        trigger_event: Optional[EnterpriseEvent] = None,
        invalidated_evidence_ids: Optional[List[str]] = None,
        new_evidence_ids: Optional[List[str]] = None,
    ) -> Optional[DecisionChangeEvent]:
        """
        Record a new decision snapshot.
        If outcome changed from the prior record, constructs an explanation and returns DecisionChangeEvent.
        """
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        inv_ev_ids = invalidated_evidence_ids or []
        new_ev_ids = new_evidence_ids or []

        with self._lock:
            history = self._history.setdefault(release_id, [])
            prev_record = history[-1] if history else None

            explanation = None
            notification = None

            if prev_record and prev_record.decision.outcome != decision.outcome:
                # Generate explanation for the decision change
                explanation = self._construct_explanation(
                    prev_decision=prev_record.decision,
                    new_decision=decision,
                    trigger_event=trigger_event,
                    invalidated_evidence_ids=inv_ev_ids,
                    new_evidence_ids=new_ev_ids,
                )

                notification = DecisionChangeEvent(
                    release_id=release_id,
                    previous_outcome=prev_record.decision.outcome,
                    new_outcome=decision.outcome,
                    trigger_event_id=trigger_event.event_id if trigger_event else "manual",
                    changed_evidence_ids=inv_ev_ids + new_ev_ids,
                    explanation=explanation,
                    timestamp=now_ts,
                )
            elif not prev_record:
                explanation = f"Initial baseline assessment for {release_id}: {decision.outcome.value}."

            rec = DecisionLineageRecord(
                record_id=f"lin-{len(history)+1:03d}-{release_id}",
                release_id=release_id,
                decision=decision,
                trigger_event=trigger_event,
                invalidated_evidence_ids=inv_ev_ids,
                new_evidence_ids=new_ev_ids,
                change_reason=explanation,
                timestamp=now_ts,
            )
            history.append(rec)
            return notification

    def _construct_explanation(
        self,
        prev_decision: ReleaseDecision,
        new_decision: ReleaseDecision,
        trigger_event: Optional[EnterpriseEvent],
        invalidated_evidence_ids: List[str],
        new_evidence_ids: List[str],
    ) -> str:
        """Deterministically derive a provenance-grounded explanation for outcome shift."""
        parts: List[str] = [
            f"Decision transitioned from {prev_decision.outcome.value} to {new_decision.outcome.value}."
        ]

        if trigger_event:
            parts.append(
                f"Triggered by {trigger_event.source.upper()} event '{trigger_event.event_type.value}' on {trigger_event.entity_id}."
            )

        if invalidated_evidence_ids:
            parts.append(
                f"Invalidated {len(invalidated_evidence_ids)} prior evidence artifact(s): {', '.join(invalidated_evidence_ids[:3])}."
            )

        if new_decision.blocking_factors:
            parts.append(
                f"New blocking conditions: {'; '.join(new_decision.blocking_factors[:2])}."
            )
        elif new_decision.outcome == ReleaseDecisionOutcome.READY:
            parts.append("All previously blocking conditions resolved and verified.")

        return " ".join(parts)

    def get_history(self, release_id: str) -> List[DecisionLineageRecord]:
        with self._lock:
            return list(self._history.get(release_id, []))

    def get_lineage(self, release_id: str) -> List[DecisionLineageRecord]:
        """Alias for get_history."""
        return self.get_history(release_id)

    def get_latest_change_reason(self, release_id: str) -> Optional[str]:
        with self._lock:
            history = self._history.get(release_id, [])
            if not history:
                return None
            return history[-1].change_reason

    def explain_latest_change(self, release_id: str) -> Optional[str]:
        """Alias for get_latest_change_reason."""
        return self.get_latest_change_reason(release_id)
