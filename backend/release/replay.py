"""
Controlled Event Replay Engine (Brick 4.4)

Provides administrative state reconstruction, audit, and debugging workflows.
Preserves original event identity while preventing duplicate external side-effects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.release.events.models import EnterpriseEvent
from backend.release.models import ReleaseDecisionOutcome
from backend.release.persistence.factory import DurableStoreBundle

logger = logging.getLogger("oracle.replay")


@dataclass
class ReplayReport:
    """Deliverable of a controlled administrative event replay."""
    total_events_replayed: int
    release_id: Optional[str]
    dry_run: bool
    reconstructed_decisions: Dict[str, str] = field(default_factory=dict)
    suppressed_side_effects: int = 0
    errors: List[str] = field(default_factory=list)


class EventReplayEngine:
    """Executes controlled historical replay against the durable event journal."""

    def __init__(self, store: DurableStoreBundle, event_router: Optional[Any] = None):
        self.store = store
        self.event_router = event_router

    def replay_events(
        self,
        since_iso: Optional[str] = None,
        release_id: Optional[str] = None,
        dry_run: bool = True,
    ) -> ReplayReport:
        """
        Replay historical events in strict chronological order.
        Never executes duplicate live external actions.
        """
        if since_iso:
            events = self.store.events.get_events_since(since_iso=since_iso, release_id=release_id)
        else:
            events = self.store.events.list_events(release_id=release_id, limit=10000)

        report = ReplayReport(
            total_events_replayed=len(events),
            release_id=release_id,
            dry_run=dry_run,
        )

        for event in events:
            try:
                # In replay, external governed actions must NOT be dispatched
                report.suppressed_side_effects += 1

                if self.event_router:
                    # Execute impact analysis and investigation in replay mode
                    receipt = self.event_router.process_canonical_event(event, is_replay=True)
                    if receipt and receipt.notifications:
                        for notif in receipt.notifications:
                            report.reconstructed_decisions[notif.release_id] = notif.new_outcome.value
            except Exception as e:
                logger.error(f"Error replaying event {event.event_id}: {e}", exc_info=True)
                report.errors.append(f"Event {event.event_id}: {str(e)}")

        return report
