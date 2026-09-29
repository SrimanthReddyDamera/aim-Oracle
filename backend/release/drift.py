"""
Continuous Evidence Drift Monitor (Brick 4.4)

Evaluates validity TTLs and expiration intervals for active enterprise evidence.
Triggers targeted DAG re-assessment without requiring inbound webhooks.
"""

from __future__ import annotations

import datetime
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from backend.release.events.lifecycle import EvidenceState
from backend.release.events.models import EnterpriseEvent, EnterpriseEventType
from backend.release.persistence.factory import DurableStoreBundle

logger = logging.getLogger("oracle.drift")


class ContinuousDriftMonitor:
    """Monitors evidence age and expiration windows, triggering targeted invalidation."""

    DEFAULT_TTL_POLICIES = {
        "github_actions": 14400,   # 4 hours for CI runs
        "ci": 14400,
        "semgrep": 86400,          # 24 hours for security scans
        "trivy": 86400,
        "security": 86400,
        "jira": 86400 * 3,         # 3 days for Jira tickets
        "code_review": 86400 * 7,  # 7 days for PR reviews
    }

    def __init__(
        self,
        store: DurableStoreBundle,
        event_router: Optional[Any] = None,
        ttl_policies: Optional[Dict[str, int]] = None,
    ):
        self.store = store
        self.event_router = event_router
        self.ttl_policies = dict(self.DEFAULT_TTL_POLICIES)
        if ttl_policies:
            self.ttl_policies.update(ttl_policies)

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def evaluate_drift(self, now_timestamp: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Scan active evidence, detect expired items based on validity windows and TTL policies.
        Transitions expired evidence to EXPIRED state and triggers targeted re-investigation.
        """
        now = now_timestamp or time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

        drift_reports: List[Dict[str, Any]] = []

        # 1. Query store for evidence past explicit valid_until
        expired_by_window = self.store.evidence.find_expired_evidence(now_iso)

        # 2. Query all active investigations and inspect evidence timestamps against TTLs
        all_investigations = self.store.investigations.list_investigations(limit=1000)

        for inv_summary in all_investigations:
            inv_id = inv_summary["investigation_id"]
            release_id = inv_summary["release_id"]
            evidence_items = self.store.evidence.list_evidence_for_investigation(inv_id)

            expired_ids_for_inv = []
            for ev in evidence_items:
                is_expired = False
                reason = ""
                valid_until_val = getattr(ev, "valid_until", None) or (ev.metadata or {}).get("valid_until")
                if valid_until_val:
                    vu_ts = self._parse_iso(valid_until_val)
                    if vu_ts and vu_ts < now:
                        is_expired = True
                        reason = f"Validity window expired at {valid_until_val}"

                # Check policy TTL
                timestamp_val = getattr(ev, "timestamp", None) or getattr(ev, "created_at", None) or (ev.metadata or {}).get("timestamp")
                if not is_expired and timestamp_val:
                    ev_ts = self._parse_iso(timestamp_val)
                    if ev_ts:
                        src_key = ev.source_type.lower()
                        ttl = self.ttl_policies.get(src_key, self.ttl_policies.get("ci", 14400))
                        if (now - ev_ts) > ttl:
                            is_expired = True
                            reason = f"Evidence age ({int(now - ev_ts)}s) exceeded policy TTL ({ttl}s)"

                if is_expired:
                    # Mark expired in store
                    self.store.evidence.update_evidence_state(
                        evidence_id=ev.evidence_id,
                        state=EvidenceState.EXPIRED,
                        reason=reason,
                    )
                    expired_ids_for_inv.append(ev.evidence_id)
                    drift_reports.append({
                        "evidence_id": ev.evidence_id,
                        "investigation_id": inv_id,
                        "release_id": release_id,
                        "reason": reason,
                    })

            # If any evidence in this investigation expired, trigger targeted re-investigation
            if expired_ids_for_inv and self.event_router:
                self._dispatch_drift_reinvestigation(release_id, expired_ids_for_inv, now_iso)

        return drift_reports

    def _dispatch_drift_reinvestigation(
        self,
        release_id: str,
        expired_evidence_ids: List[str],
        timestamp_iso: str,
    ) -> None:
        """Create a synthetic drift event and trigger targeted re-investigation via router."""
        drift_event = EnterpriseEvent(
            event_id=f"evt-drift-{release_id}-{int(time.time())}",
            source="oracle_drift_monitor",
            source_event_id=f"drift-{release_id}-{int(time.time())}",
            event_type=EnterpriseEventType.CI_COMPLETED,  # Triggers re-check of operational state
            timestamp=timestamp_iso,
            entity_type="release",
            entity_id=release_id,
            repository="",
            commit="",
            release_id=release_id,
            work_item_id="",
            service_id="",
            environment="production",
            payload={"expired_evidence_ids": expired_evidence_ids, "reason": "CONTINUOUS_EVIDENCE_DRIFT"},
            provenance={"generator": "ContinuousDriftMonitor", "timestamp": timestamp_iso},
        )
        self.store.events.append_event(drift_event)

        if hasattr(self.event_router, "handle_evidence_drift"):
            self.event_router.handle_evidence_drift(release_id, expired_evidence_ids)

    def start_background(self, interval_seconds: float = 60.0) -> None:
        if self._running:
            return
        self._running = True

        def loop():
            while self._running:
                try:
                    self.evaluate_drift()
                except Exception as e:
                    logger.error(f"Error in continuous drift monitor: {e}", exc_info=True)
                time.sleep(interval_seconds)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _parse_iso(self, ts_val: Any) -> Optional[float]:
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, datetime.datetime):
            return ts_val.timestamp()
        if isinstance(ts_val, str):
            try:
                # Replace trailing Z with UTC offset
                clean = ts_val.replace("Z", "+00:00")
                return datetime.datetime.fromisoformat(clean).timestamp()
            except Exception:
                return None
        return None
