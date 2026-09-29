"""
Operational Telemetry & Audit Subsystem for Live Enterprise Connectors (Brick 4.2)

Captures structured operational telemetry across external provider queries and governed actions:
- Latency (ms)
- Provider and operation names
- Timestamp boundaries (ISO-8601)
- Retry attempts
- Circuit breaker state
- Evidence counts (admitted & rejected)
- Success / failure outcome

Strictly enforces zero credential leakage:
- Scrubbing tokens, passwords, Authorization headers, and query parameters via SecretRedactor.
"""

from __future__ import annotations

import contextlib
import threading
import time
from typing import Any, Dict, Iterator, List, Optional
from pydantic import BaseModel, Field

from backend.release.connectivity.credentials import GLOBAL_REDACTOR


class ProviderOperationTelemetry(BaseModel):
    """
    Structured operational telemetry record for an individual external call or aggregate check.
    """
    investigation_id: str = ""
    release_id: str = ""
    provider: str
    operation: str
    start_time: str
    end_time: str = ""
    latency_ms: float = 0.0
    success: bool = True
    retry_count: int = 0
    circuit_state: str = "CLOSED"
    evidence_count: int = 0
    rejected_evidence_count: int = 0
    decision: Optional[str] = None
    action_id: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Produce safe dictionary representation with guaranteed redacted error messages."""
        data = self.model_dump()
        if data.get("error_message"):
            data["error_message"] = GLOBAL_REDACTOR.redact(data["error_message"])
        return data


class InvestigationTelemetryLedger:
    """
    Thread-safe ledger aggregating provider operation telemetry for an investigation.
    """

    def __init__(self, investigation_id: str = "", release_id: str = ""):
        self.investigation_id = investigation_id
        self.release_id = release_id
        self._records: List[ProviderOperationTelemetry] = []
        self._lock = threading.RLock()

    def record(self, telemetry: ProviderOperationTelemetry) -> None:
        """Append a telemetry record after scrubbing any secrets in error strings."""
        if not telemetry.investigation_id:
            telemetry.investigation_id = self.investigation_id
        if not telemetry.release_id:
            telemetry.release_id = self.release_id

        if telemetry.error_message:
            telemetry.error_message = GLOBAL_REDACTOR.redact(telemetry.error_message)

        with self._lock:
            self._records.append(telemetry)

    @contextlib.contextmanager
    def record_operation(
        self,
        provider: str,
        operation: str,
        circuit_state: str = "CLOSED",
        retry_count: int = 0,
        action_id: Optional[str] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Context manager to time and capture an external operation.
        Yields a dict that the caller can populate with:
          - evidence_count: int
          - rejected_evidence_count: int
          - circuit_state: str
          - retry_count: int
        """
        start_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        t0 = time.perf_counter()
        context_data: Dict[str, Any] = {
            "evidence_count": 0,
            "rejected_evidence_count": 0,
            "circuit_state": circuit_state,
            "retry_count": retry_count,
            "error_message": None,
        }

        success = True
        err_msg = None
        try:
            yield context_data
        except Exception as ex:
            success = False
            err_msg = GLOBAL_REDACTOR.redact(str(ex))
            context_data["error_message"] = err_msg
            raise
        finally:
            t1 = time.perf_counter()
            end_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            latency = (t1 - t0) * 1000.0

            tel = ProviderOperationTelemetry(
                investigation_id=self.investigation_id,
                release_id=self.release_id,
                provider=provider,
                operation=operation,
                start_time=start_ts,
                end_time=end_ts,
                latency_ms=round(latency, 2),
                success=success,
                retry_count=context_data.get("retry_count", retry_count),
                circuit_state=context_data.get("circuit_state", circuit_state),
                evidence_count=context_data.get("evidence_count", 0),
                rejected_evidence_count=context_data.get("rejected_evidence_count", 0),
                action_id=action_id,
                error_message=context_data.get("error_message", err_msg),
            )
            self.record(tel)

    def get_records(self) -> List[ProviderOperationTelemetry]:
        with self._lock:
            return list(self._records)

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            records = list(self._records)

        total_ops = len(records)
        failed_ops = sum(1 for r in records if not r.success)
        total_latency = sum(r.latency_ms for r in records)
        avg_latency = round(total_latency / total_ops, 2) if total_ops > 0 else 0.0

        provider_counts: Dict[str, int] = {}
        for r in records:
            provider_counts[r.provider] = provider_counts.get(r.provider, 0) + 1

        return {
            "investigation_id": self.investigation_id,
            "release_id": self.release_id,
            "total_operations": total_ops,
            "failed_operations": failed_ops,
            "total_latency_ms": round(total_latency, 2),
            "average_latency_ms": avg_latency,
            "operations_by_provider": provider_counts,
            "records": [r.to_dict() for r in records],
        }
