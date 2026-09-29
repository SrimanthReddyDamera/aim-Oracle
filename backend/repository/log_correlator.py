"""
Log Correlation Engine (ORACLE 5.0 - Step 8b)

Correlates raw production/diagnostic log streams with:
- Timestamps and request/trace IDs
- Localized code paths, filenames, and function symbols
- Specific exception messages
Enforces the rule: Correlation evidence is only admitted when fields actually support it.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("oracle.repository.log_correlator")


class CorrelatedLogRecord(BaseModel):
    """Normalized representation of a log line correlated with the incident."""
    raw_line: str
    line_number: int
    timestamp: Optional[str] = None
    level: str = "INFO"
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    matched_symbol: Optional[str] = None
    relevance: str = "HIGH"


class CorrelatedLogResult(BaseModel):
    """Aggregate result of log stream correlation."""
    correlated_records: List[CorrelatedLogRecord] = Field(default_factory=list)
    primary_request_id: Optional[str] = None
    primary_timestamp: Optional[str] = None
    has_matching_errors: bool = False
    evidence_summary: str = ""


class LogCorrelator:
    """
    Correlates optional production logs with localized code failures.
    """

    TIMESTAMP_RE = re.compile(
        r"(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?|\b\d{2}:\d{2}:\d{2}\b)"
    )
    REQUEST_ID_RE = re.compile(r"\b(?:req_[a-zA-Z0-9_-]+|request[-_]id[:=]\s*([a-zA-Z0-9_-]+)|corr-[a-zA-Z0-9]+)\b", re.IGNORECASE)
    TRACE_ID_RE = re.compile(r"\b(?:trace[-_]id[:=]\s*([a-zA-Z0-9_-]+)|trace_[a-zA-Z0-9_-]+)\b", re.IGNORECASE)
    LEVEL_RE = re.compile(r"\b(ERROR|WARN|CRITICAL|FATAL|EXCEPTION)\b", re.IGNORECASE)

    @classmethod
    def correlate(
        cls,
        raw_logs: str,
        target_file: Optional[str] = None,
        target_function: Optional[str] = None,
        exception_type: Optional[str] = None,
    ) -> CorrelatedLogResult:
        if not raw_logs or not raw_logs.strip():
            return CorrelatedLogResult(evidence_summary="No logs provided.")

        records: List[CorrelatedLogRecord] = []
        req_ids: List[str] = []
        timestamps: List[str] = []

        file_stem = target_file.split("/")[-1] if target_file else None

        for idx, line in enumerate(raw_logs.split("\n"), 1):
            line_str = line.strip()
            if not line_str:
                continue

            ts_m = cls.TIMESTAMP_RE.search(line_str)
            req_m = cls.REQUEST_ID_RE.search(line_str)
            trace_m = cls.TRACE_ID_RE.search(line_str)
            lvl_m = cls.LEVEL_RE.search(line_str)

            ts = ts_m.group(0) if ts_m else None
            req_id = req_m.group(0) if req_m else None
            trace_id = trace_m.group(0) if trace_m else None
            level = lvl_m.group(1).upper() if lvl_m else "INFO"

            if ts:
                timestamps.append(ts)
            if req_id:
                req_ids.append(req_id)

            # Check matching symbols
            matched_symbol = None
            is_relevant = False

            if level in {"ERROR", "CRITICAL", "FATAL", "EXCEPTION"}:
                is_relevant = True

            if file_stem and file_stem in line_str:
                matched_symbol = file_stem
                is_relevant = True
            elif target_function and target_function in line_str:
                matched_symbol = target_function
                is_relevant = True
            elif exception_type and exception_type in line_str:
                matched_symbol = exception_type
                is_relevant = True

            if is_relevant:
                records.append(
                    CorrelatedLogRecord(
                        raw_line=line_str,
                        line_number=idx,
                        timestamp=ts,
                        level=level,
                        request_id=req_id,
                        trace_id=trace_id,
                        matched_symbol=matched_symbol,
                        relevance="CRITICAL" if level in {"ERROR", "CRITICAL"} else "HIGH",
                    )
                )

        has_errs = any(r.level in {"ERROR", "CRITICAL"} for r in records)
        primary_req = req_ids[0] if req_ids else None
        primary_ts = timestamps[0] if timestamps else None

        summary = f"Correlated {len(records)} relevant log entries across log stream."
        if primary_req:
            summary += f" Associated Request ID: {primary_req}."

        return CorrelatedLogResult(
            correlated_records=records[:25],
            primary_request_id=primary_req,
            primary_timestamp=primary_ts,
            has_matching_errors=has_errs,
            evidence_summary=summary,
        )
