"""
OpenTelemetry Distributed Tracing Subsystem (Brick 4.6)

Provides end-to-end distributed trace continuity across process boundaries:
HTTP Ingress -> Event Journal -> Worker Claim -> Entity Resolution -> Impact Analysis ->
DAG Investigation -> Provider Call -> Evidence Admission -> Decision -> Governed Action.

Attributes:
- trace_id, span_id, parent_span_id, correlation_id
- event_id, investigation_id, release_id, task_id, decision_id, action_id, tenant_id

Guarantees:
- Secrets, authorization headers, passwords, and raw webhook bodies are strictly excluded.
- Context injection and extraction support asynchronous worker boundaries.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oracle.observability.tracing")


class SpanStatus(str, Enum):
    OK = "OK"
    ERROR = "ERROR"
    UNSET = "UNSET"


@dataclass
class TraceContext:
    """Carries distributed tracing identifiers across asynchronous boundaries."""
    trace_id: str
    span_id: str
    correlation_id: str
    parent_span_id: Optional[str] = None
    sampled: bool = True

    def to_dict(self) -> Dict[str, str]:
        d = {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "correlation_id": self.correlation_id,
            "sampled": "1" if self.sampled else "0",
        }
        if self.parent_span_id:
            d["parent_span_id"] = self.parent_span_id
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional[TraceContext]:
        if not data:
            return None
        trace_id = data.get("trace_id") or data.get("traceparent")
        if not trace_id:
            return None
        return cls(
            trace_id=str(trace_id),
            span_id=str(data.get("span_id", secrets.token_hex(8))),
            correlation_id=str(data.get("correlation_id", secrets.token_hex(8))),
            parent_span_id=data.get("parent_span_id"),
            sampled=data.get("sampled") in (True, "1", "true"),
        )

    def create_child(self) -> TraceContext:
        """Create a child trace context referencing current span as parent."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=secrets.token_hex(8),
            correlation_id=self.correlation_id,
            parent_span_id=self.span_id,
            sampled=self.sampled,
        )


@dataclass
class SpanRecord:
    """Immutable record of an executed span."""
    name: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    correlation_id: str
    start_time: float
    end_time: float
    duration_ms: float
    status: SpanStatus
    attributes: Dict[str, Any]
    events: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "correlation_id": self.correlation_id,
            "start_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.start_time)),
            "end_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.end_time)),
            "duration_ms": round(self.duration_ms, 3),
            "status": self.status.value,
            "attributes": self.attributes,
            "error_message": self.error_message,
        }


SENSITIVE_ATTR_RE = re.compile(
    r"(secret|token|password|auth|authorization|credential|body|payload|raw)",
    re.IGNORECASE,
)


class Span:
    """Active span context manager."""

    def __init__(
        self,
        tracer: Tracer,
        name: str,
        context: TraceContext,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        self.tracer = tracer
        self.name = name
        self.context = context
        self.start_time = time.time()
        self.end_time: float = 0.0
        self.status = SpanStatus.OK
        self.error_message: Optional[str] = None
        self.attributes: Dict[str, Any] = {}
        self.events: List[Dict[str, Any]] = []

        if attributes:
            for k, v in attributes.items():
                self.set_attribute(k, v)

    def set_attribute(self, key: str, value: Any) -> None:
        """Set span attribute with strict secret exclusion."""
        if SENSITIVE_ATTR_RE.search(key):
            return  # Exclude sensitive keys entirely
        if isinstance(value, (str, int, float, bool)):
            self.attributes[key] = value
        elif value is None:
            self.attributes[key] = ""
        else:
            self.attributes[key] = str(value)[:256]

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        clean_attrs = {}
        if attributes:
            for k, v in attributes.items():
                if not SENSITIVE_ATTR_RE.search(k):
                    clean_attrs[k] = str(v)[:256]
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": clean_attrs,
        })

    def set_status(self, status: SpanStatus, error_message: Optional[str] = None) -> None:
        self.status = status
        self.error_message = error_message

    def end(self) -> SpanRecord:
        self.end_time = time.time()
        record = SpanRecord(
            name=self.name,
            trace_id=self.context.trace_id,
            span_id=self.context.span_id,
            parent_span_id=self.context.parent_span_id,
            correlation_id=self.context.correlation_id,
            start_time=self.start_time,
            end_time=self.end_time,
            duration_ms=(self.end_time - self.start_time) * 1000.0,
            status=self.status,
            attributes=dict(self.attributes),
            events=list(self.events),
            error_message=self.error_message,
        )
        self.tracer._record_span(record)
        return record

    def __enter__(self) -> Span:
        self._token = _CURRENT_CONTEXT.set(self.context)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is not None:
            self.set_status(SpanStatus.ERROR, error_message=str(exc_val))
        self.end()
        if hasattr(self, "_token"):
            _CURRENT_CONTEXT.reset(self._token)
        return False


_CURRENT_CONTEXT: contextvars.ContextVar[Optional[TraceContext]] = contextvars.ContextVar(
    "oracle_current_trace_context",
    default=None,
)


class Tracer:
    """Thread-safe distributed tracer and buffer."""

    def __init__(self, service_name: str = "oracle", max_buffer_spans: int = 5000):
        self.service_name = service_name
        self.max_buffer_spans = max_buffer_spans
        self._spans: List[SpanRecord] = []
        self._lock = threading.RLock()

    def current_context(self) -> Optional[TraceContext]:
        return _CURRENT_CONTEXT.get()

    def start_span(
        self,
        name: str,
        parent_context: Optional[TraceContext] = None,
        correlation_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Span:
        """Start a new span, linking to active parent or provided context."""
        active = parent_context or self.current_context()
        if active:
            ctx = active.create_child()
        else:
            ctx = TraceContext(
                trace_id=secrets.token_hex(16),
                span_id=secrets.token_hex(8),
                correlation_id=correlation_id or secrets.token_hex(8),
            )

        span = Span(tracer=self, name=name, context=ctx, attributes=attributes)
        span.set_attribute("service.name", self.service_name)
        return span

    def inject_context(self, carrier: Dict[str, Any], context: Optional[TraceContext] = None) -> Dict[str, Any]:
        """Inject trace context into dict or headers for cross-process propagation."""
        ctx = context or self.current_context()
        if ctx:
            carrier["trace_id"] = ctx.trace_id
            carrier["span_id"] = ctx.span_id
            carrier["correlation_id"] = ctx.correlation_id
            carrier["traceparent"] = f"00-{ctx.trace_id}-{ctx.span_id}-01"
        return carrier

    def extract_context(self, carrier: Dict[str, Any]) -> Optional[TraceContext]:
        """Extract trace context from headers, metadata, or dict."""
        if not carrier:
            return None
        # Support W3C traceparent (00-traceid-spanid-flags)
        traceparent = carrier.get("traceparent") or carrier.get("HTTP_TRACEPARENT")
        if traceparent and isinstance(traceparent, str):
            parts = traceparent.split("-")
            if len(parts) >= 4:
                return TraceContext(
                    trace_id=parts[1],
                    span_id=secrets.token_hex(8),
                    parent_span_id=parts[2],
                    correlation_id=str(carrier.get("correlation_id") or carrier.get("x-correlation-id") or secrets.token_hex(8)),
                )

        trace_id = carrier.get("trace_id") or carrier.get("x-trace-id")
        if trace_id:
            return TraceContext(
                trace_id=str(trace_id),
                span_id=secrets.token_hex(8),
                parent_span_id=carrier.get("span_id"),
                correlation_id=str(carrier.get("correlation_id") or carrier.get("x-correlation-id") or secrets.token_hex(8)),
            )
        return None

    def _record_span(self, record: SpanRecord) -> None:
        with self._lock:
            self._spans.append(record)
            if len(self._spans) > self.max_buffer_spans:
                self._spans.pop(0)

    def get_spans(
        self,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[SpanRecord]:
        """Query collected spans by trace, correlation, or investigation ID."""
        with self._lock:
            results = []
            for s in reversed(self._spans):
                if trace_id and s.trace_id != trace_id:
                    continue
                if correlation_id and s.correlation_id != correlation_id:
                    continue
                if investigation_id and s.attributes.get("investigation_id") != investigation_id:
                    continue
                results.append(s)
                if len(results) >= limit:
                    break
            return list(reversed(results))

    def clear(self) -> None:
        with self._lock:
            self._spans.clear()


# Global default tracer
GLOBAL_TRACER = Tracer("oracle-control-plane")
