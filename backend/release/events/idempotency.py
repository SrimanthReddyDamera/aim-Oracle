"""
Event Idempotency & Duplicate Suppression (Brick 4.3)

Guarantees:
same external event -> one logical ORACLE event -> one impact analysis -> zero duplicate side effects.
Thread-safe in-memory registry with atomic check-and-register operations.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Dict, Optional, Tuple

from backend.release.events.models import EnterpriseEvent


class EventIdempotencyManager:
    """
    Thread-safe idempotency registry enforcing duplicate suppression across incoming enterprise events.
    """

    def __init__(self, ttl_seconds: float = 3600.0):
        self.ttl_seconds = ttl_seconds
        self._registry: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def compute_key(self, event: EnterpriseEvent) -> str:
        """Derive deterministic canonical idempotency key for an event."""
        return event.compute_idempotency_key()

    def register_if_absent(
        self,
        event: EnterpriseEvent,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Atomically check if an event has already been registered.
        Returns:
          (is_new, existing_record_if_duplicate)
        """
        key = self.compute_key(event)
        now = time.time()

        with self._lock:
            # Check existing
            if key in self._registry:
                rec = self._registry[key]
                # Check TTL
                if now - rec["registered_at"] < self.ttl_seconds:
                    rec["duplicate_count"] += 1
                    rec["last_seen_at"] = now
                    return False, rec

            # New event
            record = {
                "idempotency_key": key,
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "source": event.source,
                "source_event_id": event.source_event_id,
                "registered_at": now,
                "last_seen_at": now,
                "duplicate_count": 0,
                "impact_result": None,
            }
            self._registry[key] = record
            return True, None

    def store_impact_result(self, key: str, impact_result: Dict[str, Any]) -> None:
        """Attach impact analysis deliverable to cached idempotency record."""
        with self._lock:
            if key in self._registry:
                self._registry[key]["impact_result"] = impact_result

    def get_record(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._registry.get(key)

    def clear(self) -> None:
        with self._lock:
            self._registry.clear()
