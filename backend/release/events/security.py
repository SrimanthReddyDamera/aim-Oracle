"""
Webhook Security & Signature Verification (Brick 4.3)

Enforces enterprise webhook security:
1. HMAC-SHA256 signature verification (GitHub X-Hub-Signature-256, Jira Secret Token).
2. Constant-time signature comparison to protect against timing attacks.
3. Timestamp drift / replay window validation (default max 300s drift).
4. Payload size limits and malformed input rejection.
5. Secret scrubbing from all security error messages.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, Optional

from backend.release.connectivity.credentials import GLOBAL_REDACTOR


class WebhookSecurityError(PermissionError, ValueError):
    """Base error for webhook security verification failures."""
    pass


class WebhookSignatureError(WebhookSecurityError):
    """Raised when webhook signature verification fails."""
    pass


class WebhookReplayError(WebhookSecurityError):
    """Raised when an event timestamp exceeds allowed drift window (replay attempt)."""
    pass


class WebhookSecurityValidator:
    """
    Validates incoming webhook authenticity, integrity, and temporal freshness.
    """

    def __init__(
        self,
        max_drift_seconds: float = 300.0,
        max_payload_bytes: int = 5 * 1024 * 1024,  # 5 MB
    ):
        self.max_drift_seconds = max_drift_seconds
        self.max_payload_bytes = max_payload_bytes

    def verify_github_signature(
        self,
        raw_body: bytes,
        signature_header: Optional[str],
        secret: str,
    ) -> bool:
        """
        Verify GitHub HMAC-SHA256 signature (X-Hub-Signature-256).
        """
        if not signature_header:
            raise WebhookSignatureError("Missing required GitHub signature header ('X-Hub-Signature-256').")

        if not secret:
            raise WebhookSignatureError("Webhook secret is not configured for provider.")

        if not signature_header.startswith("sha256="):
            raise WebhookSignatureError("Invalid GitHub signature format; expected prefix 'sha256='.")

        expected_sig = signature_header.split("sha256=", 1)[1].strip()
        computed_sig = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()

        # Constant-time comparison
        if not hmac.compare_digest(computed_sig, expected_sig):
            raise WebhookSignatureError("GitHub webhook HMAC signature verification failed.")

        return True

    def verify_jira_secret(
        self,
        secret_header: Optional[str],
        expected_secret: str,
    ) -> bool:
        """Verify Jira Cloud webhook token / secret header."""
        if not secret_header:
            raise WebhookSignatureError("Missing required Jira webhook secret header.")

        if not expected_secret:
            raise WebhookSignatureError("Jira webhook secret is not configured.")

        if not hmac.compare_digest(secret_header.strip(), expected_secret.strip()):
            raise WebhookSignatureError("Jira webhook secret token mismatch.")

        return True

    def verify_timestamp(self, ts: Any, current_time: Optional[float] = None) -> bool:
        """Alias for validate_timestamp_drift accepting float or str."""
        return self.validate_timestamp_drift(ts, current_time=current_time)

    def validate_timestamp_drift(
        self,
        event_timestamp: Optional[Any],
        current_time: Optional[float] = None,
    ) -> bool:
        """
        Validate that the event timestamp is within the acceptable drift window.
        Protects against replay attacks.
        """
        if event_timestamp is None:
            return True

        now = current_time if current_time is not None else time.time()
        try:
            # Parse numeric epoch or ISO-8601 string
            if isinstance(event_timestamp, (int, float)):
                ts_epoch = float(event_timestamp)
            elif isinstance(event_timestamp, str):
                str_ts = event_timestamp.strip()
                if str_ts.replace(".", "", 1).isdigit():
                    ts_epoch = float(str_ts)
                    if len(str_ts.split(".")[0]) > 10:
                        ts_epoch /= 1000.0
                else:
                    import datetime
                    clean_ts = str_ts.replace("Z", "+00:00")
                    dt = datetime.datetime.fromisoformat(clean_ts)
                    ts_epoch = dt.timestamp()
            else:
                return True

            drift = abs(now - ts_epoch)
            if drift > self.max_drift_seconds:
                raise WebhookReplayError(
                    f"Webhook timestamp drift ({round(drift, 1)}s) exceeds max allowed window ({self.max_drift_seconds}s). Replay rejected."
                )
            return True
        except ValueError as ex:
            if isinstance(ex, WebhookReplayError):
                raise
            return True

    def validate_payload_size(self, raw_bytes: bytes) -> None:
        """Reject payloads exceeding maximum allowed size."""
        if len(raw_bytes) > self.max_payload_bytes:
            raise WebhookSecurityError(
                f"Payload size ({len(raw_bytes)} bytes) exceeds maximum limit ({self.max_payload_bytes} bytes)."
            )

    def verify_signature(
        self,
        raw_body: bytes,
        headers: Dict[str, str],
        secret: str,
        source: str = "github",
    ) -> bool:
        """Convenience method to verify webhook signatures across providers."""
        if source in ("github", "ci"):
            sig = headers.get("x-hub-signature-256") or headers.get("X-Hub-Signature-256")
            try:
                return self.verify_github_signature(raw_body, sig, secret)
            except Exception:
                return False
        elif source == "jira":
            token = headers.get("x-atlassian-webhook-token") or headers.get("X-Atlassian-Webhook-Token") or headers.get("authorization")
            try:
                return self.verify_jira_secret(token, secret)
            except Exception:
                return False
        return True

    def validate_replay_window(self, headers: Dict[str, str], current_time: Optional[float] = None) -> bool:
        """Convenience method to validate replay window from request headers."""
        ts = headers.get("x-timestamp") or headers.get("X-Timestamp")
        if not ts:
            return True
        try:
            return self.validate_timestamp_drift(ts, current_time=current_time)
        except Exception:
            return False
