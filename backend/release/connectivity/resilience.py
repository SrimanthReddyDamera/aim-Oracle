"""
Network Resilience & Reliability Primitives for Enterprise Connectivity (Brick 4.1)

Provides production-grade resilience patterns for external enterprise APIs:
1. CircuitBreaker (CLOSED, OPEN, HALF_OPEN states with failure thresholds and recovery windows)
2. ResilientHttpClient (wrapped httpx.Client with bounded retry, exponential backoff, rate-limit handling)
3. Structured Provider Errors (ProviderAuthenticationError, ProviderRateLimitError, ProviderTimeoutError, ProviderOutageError)
4. Secret Scrubbing (prevents credential leakage in URLs, headers, and logs)
"""

from __future__ import annotations

import re
import threading
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import httpx


# -----------------------------------------------------------------------------
# 1. STRUCTURED PROVIDER EXCEPTIONS
# -----------------------------------------------------------------------------

class ProviderNetworkError(Exception):
    """Base exception for all external provider network failures."""
    def __init__(self, message: str, provider_id: str = "", status_code: Optional[int] = None):
        super().__init__(message)
        self.provider_id = provider_id
        self.status_code = status_code


class ProviderAuthenticationError(ProviderNetworkError):
    """Raised when authentication fails (HTTP 401 / 403 or invalid/expired token)."""
    pass


class ProviderRateLimitError(ProviderNetworkError):
    """Raised when provider returns HTTP 429 Too Many Requests."""
    def __init__(self, message: str, retry_after: float = 1.0, provider_id: str = ""):
        super().__init__(message, provider_id=provider_id, status_code=429)
        self.retry_after = retry_after


class ProviderTimeoutError(ProviderNetworkError):
    """Raised when request times out."""
    pass


class ProviderOutageError(ProviderNetworkError):
    """Raised when provider returns 5xx or connection is refused."""
    pass


class CircuitBreakerOpenError(ProviderNetworkError):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""
    def __init__(self, provider_id: str, remaining_cooldown: float):
        super().__init__(
            f"Circuit breaker is OPEN for provider '{provider_id}'. Remaining cooldown: {remaining_cooldown:.1f}s",
            provider_id=provider_id,
        )
        self.remaining_cooldown = remaining_cooldown


# -----------------------------------------------------------------------------
# 2. CIRCUIT BREAKER
# -----------------------------------------------------------------------------

class CircuitState(str, Enum):
    CLOSED    = "CLOSED"      # Normal operation, passes calls through
    OPEN      = "OPEN"        # Tripped after failures, immediately rejects calls
    HALF_OPEN = "HALF_OPEN"   # Probing service with limited calls to test recovery


class CircuitBreaker:
    """
    Thread-safe circuit breaker protecting against cascading failures.
    Transitions:
      CLOSED -> failure_threshold reached -> OPEN
      OPEN -> recovery_timeout elapsed -> HALF_OPEN
      HALF_OPEN -> success -> CLOSED
      HALF_OPEN -> failure -> OPEN
    """

    def __init__(
        self,
        provider_id: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 5.0,
    ):
        self.provider_id = provider_id
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._lock = threading.RLock()

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._consecutive_successes: int = 0

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._consecutive_successes = 0
            return self._state

    def record_success(self) -> None:
        """Record successful call, resetting failures or closing half-open circuit."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._consecutive_successes += 1
                if self._consecutive_successes >= 2:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record failure, tripping circuit if threshold is reached."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._state == CircuitState.HALF_OPEN or self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN

    def check_permission(self) -> None:
        """Check if request is allowed. Raises CircuitBreakerOpenError if OPEN."""
        with self._lock:
            current_state = self.state
            if current_state == CircuitState.OPEN:
                remaining = max(0.0, self.recovery_timeout - (time.time() - self._last_failure_time))
                raise CircuitBreakerOpenError(self.provider_id, remaining)

    def reset(self) -> None:
        """Manually reset to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = 0.0
            self._consecutive_successes = 0


# -----------------------------------------------------------------------------
# 3. RESILIENT HTTP CLIENT
# -----------------------------------------------------------------------------

def scrub_secrets(text: str) -> str:
    """Scrub sensitive bearer tokens, passwords, and API keys from text."""
    # Scrub Authorization Bearer / Basic
    text = re.sub(r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r"(token\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", text, flags=re.IGNORECASE)
    # Scrub query parameters e.g. ?token=... or &api_key=...
    text = re.sub(r"((?:token|key|secret|password)=)[^&\s]+", r"\1[REDACTED]", text, flags=re.IGNORECASE)
    return text


class ResilientHttpClient:
    """
    Hardened HTTP client with:
    - Bounded retries & exponential backoff
    - Rate limit inspection (HTTP 429 & Retry-After)
    - Per-provider CircuitBreaker
    - Automatic secret redaction in exception messages and URLs
    """

    def __init__(
        self,
        provider_id: str,
        base_url: str = "",
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.2,
        circuit_breaker: Optional[CircuitBreaker] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.provider_id = provider_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.circuit_breaker = circuit_breaker or CircuitBreaker(provider_id=provider_id)
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            transport=transport,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        """
        Execute an HTTP request through resilience gates.
        """
        # 1. Circuit breaker pre-check
        self.circuit_breaker.check_permission()

        if self.base_url and not (url.startswith("http://") or url.startswith("https://")):
            request_url = f"{self.base_url}/{url.lstrip('/')}"
        elif not (url.startswith("http://") or url.startswith("https://")):
            request_url = f"https://api.{self.provider_id}.local/{url.lstrip('/')}"
        else:
            request_url = url

        req_timeout = timeout or self.timeout
        attempt = 0
        last_exception: Optional[Exception] = None

        while attempt < self.max_retries:
            attempt += 1
            try:
                resp = self._client.request(
                    method=method,
                    url=request_url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    timeout=req_timeout,
                )

                # Authentication Failure: 401 / 403 (do not retry; fail immediately)
                if resp.status_code in (401, 403):
                    self.circuit_breaker.record_failure()
                    safe_url = scrub_secrets(str(resp.url))
                    raise ProviderAuthenticationError(
                        f"Authentication failed for provider '{self.provider_id}' on {safe_url}: HTTP {resp.status_code}",
                        provider_id=self.provider_id,
                        status_code=resp.status_code,
                    )

                # Rate Limit: 429 Too Many Requests
                if resp.status_code == 429:
                    retry_header = resp.headers.get("Retry-After", "1.0")
                    try:
                        retry_after = float(retry_header)
                    except ValueError:
                        retry_after = 1.0
                    self.circuit_breaker.record_failure()
                    raise ProviderRateLimitError(
                        f"Rate limit exceeded for provider '{self.provider_id}' on {scrub_secrets(str(resp.url))}. Retry after {retry_after}s",
                        retry_after=retry_after,
                        provider_id=self.provider_id,
                    )

                # Server Errors: 500, 502, 503, 504 (retryable)
                if resp.status_code >= 500:
                    self.circuit_breaker.record_failure()
                    if attempt >= self.max_retries:
                        raise ProviderOutageError(
                            f"Provider '{self.provider_id}' outage on {scrub_secrets(str(resp.url))}: HTTP {resp.status_code}",
                            provider_id=self.provider_id,
                            status_code=resp.status_code,
                        )
                    sleep_sec = self.backoff_factor * (2 ** (attempt - 1))
                    time.sleep(sleep_sec)
                    continue

                # Successful HTTP Response
                self.circuit_breaker.record_success()
                return resp

            except (httpx.TimeoutException, TimeoutError) as exc:
                self.circuit_breaker.record_failure()
                last_exception = exc
                if attempt >= self.max_retries:
                    raise ProviderTimeoutError(
                        f"Request timed out for provider '{self.provider_id}' after {attempt} attempts: {scrub_secrets(str(exc))}",
                        provider_id=self.provider_id,
                    ) from exc
                time.sleep(self.backoff_factor * (2 ** (attempt - 1)))

            except (httpx.NetworkError, httpx.ConnectError) as exc:
                self.circuit_breaker.record_failure()
                last_exception = exc
                if attempt >= self.max_retries:
                    raise ProviderOutageError(
                        f"Connection failed for provider '{self.provider_id}' after {attempt} attempts: {scrub_secrets(str(exc))}",
                        provider_id=self.provider_id,
                    ) from exc
                time.sleep(self.backoff_factor * (2 ** (attempt - 1)))

        if last_exception:
            raise ProviderNetworkError(
                f"Provider '{self.provider_id}' request failed: {scrub_secrets(str(last_exception))}",
                provider_id=self.provider_id,
            ) from last_exception

        raise ProviderNetworkError(f"Provider '{self.provider_id}' unknown failure", provider_id=self.provider_id)
