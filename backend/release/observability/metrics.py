"""
Enterprise Prometheus Observability & Telemetry Subsystem (Brick 4.5)

Exposes standard Prometheus-compatible metrics:
- Counters & Gauges for operational health, webhook ingress, and worker throughput.
- Zero high-cardinality secrets or sensitive payload values in metric labels.
- Standard plaintext exposition for GET /metrics scraping.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple


class MetricType:
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class MetricsRegistry:
    """Thread-safe collector for ORACLE Prometheus operational metrics."""

    def __init__(self):
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._lock = threading.Lock()

        # Pre-populate all standard 13 ORACLE 4.5 operational metrics
        standard_metrics = [
            ("oracle_events_received_total", "counter"),
            ("oracle_events_duplicate_total", "counter"),
            ("oracle_events_failed_total", "counter"),
            ("oracle_event_processing_latency", "gauge"),
            ("oracle_investigations_active", "gauge"),
            ("oracle_investigations_completed_total", "counter"),
            ("oracle_decision_changes_total", "counter"),
            ("oracle_worker_tasks_pending", "gauge"),
            ("oracle_worker_tasks_failed", "counter"),
            ("oracle_worker_lease_recoveries_total", "counter"),
            ("oracle_evidence_expired_total", "counter"),
            ("oracle_action_reconciliation_total", "counter"),
            ("oracle_webhook_verification_failures_total", "counter"),
        ]
        for name, mtype in standard_metrics:
            if mtype == "counter":
                self._counters[(name, ())] = 0.0
            else:
                self._gauges[(name, ())] = 0.0

    def inc_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a Prometheus counter."""
        label_tuple = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            key = (name, label_tuple)
            self._counters[key] = self._counters.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a Prometheus gauge value."""
        label_tuple = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            key = (name, label_tuple)
            self._gauges[key] = value

    def get_counter_value(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Retrieve counter value."""
        label_tuple = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            return self._counters.get((name, label_tuple), 0.0)

    def get_gauge_value(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Retrieve gauge value."""
        label_tuple = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            return self._gauges.get((name, label_tuple), 0.0)

    def export_prometheus_text(self) -> str:
        """Export all registered metrics in standard Prometheus plaintext exposition format."""
        lines: List[str] = []
        with self._lock:
            # Documented descriptions
            descriptions = {
                "oracle_events_received_total": "Total number of enterprise events received across all ingress boundaries.",
                "oracle_events_duplicate_total": "Total number of duplicate events suppressed by database-enforced idempotency.",
                "oracle_events_failed_total": "Total number of failed event ingress attempts or normalization failures.",
                "oracle_event_processing_latency": "Recent event-to-worker processing latency in seconds.",
                "oracle_investigations_active": "Current number of in-flight active investigations.",
                "oracle_investigations_completed_total": "Total number of completed release investigations.",
                "oracle_decision_changes_total": "Total number of sovereign decision state transitions.",
                "oracle_worker_tasks_pending": "Current number of pending tasks in the worker queue.",
                "oracle_worker_tasks_failed": "Total number of failed worker task executions.",
                "oracle_worker_lease_recoveries_total": "Total number of expired worker leases recovered from dead workers.",
                "oracle_evidence_expired_total": "Total number of evidence items transitioned to EXPIRED state due to TTL or validity window.",
                "oracle_action_reconciliation_total": "Total number of governed actions transitioned to RECONCILIATION_REQUIRED.",
                "oracle_webhook_verification_failures_total": "Total number of failed webhook signature or replay validations.",
            }

            # Group counters by name
            counter_groups: Dict[str, List[Tuple[Tuple[Tuple[str, str], ...], float]]] = {}
            for (name, labels), val in self._counters.items():
                counter_groups.setdefault(name, []).append((labels, val))

            for name, entries in sorted(counter_groups.items()):
                desc = descriptions.get(name, f"ORACLE metric {name}")
                lines.append(f"# HELP {name} {desc}")
                lines.append(f"# TYPE {name} counter")
                for labels, val in entries:
                    if labels:
                        lbl_str = ",".join(f'{k}="{v}"' for k, v in labels)
                        lines.append(f"{name}{{{lbl_str}}} {val}")
                    else:
                        lines.append(f"{name} {val}")

            # Group gauges by name
            gauge_groups: Dict[str, List[Tuple[Tuple[Tuple[str, str], ...], float]]] = {}
            for (name, labels), val in self._gauges.items():
                gauge_groups.setdefault(name, []).append((labels, val))

            for name, entries in sorted(gauge_groups.items()):
                desc = descriptions.get(name, f"ORACLE metric {name}")
                lines.append(f"# HELP {name} {desc}")
                lines.append(f"# TYPE {name} gauge")
                for labels, val in entries:
                    if labels:
                        lbl_str = ",".join(f'{k}="{v}"' for k, v in labels)
                        lines.append(f"{name}{{{lbl_str}}} {val}")
                    else:
                        lines.append(f"{name} {val}")

        return "\n".join(lines) + "\n"


# Global singleton registry
GLOBAL_METRICS = MetricsRegistry()
