"""
ORACLE Base External Evidence Provider (Brick 3.9)
Abstract scaffolding for remote enterprise datastores (Jira, Linear, GitHub, Slack).
Encapsulates timeout boundaries, circuit breaking, error handling, and evidence normalization.
"""

from abc import abstractmethod
import hashlib
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.evidence.models import Evidence
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult


class ExternalEvidenceProvider(EvidenceProvider):
    """
    Base class for remote network-backed evidence providers.
    Enforces timeout isolation, circuit-breaking thresholds, in-memory TTL query caching,
    and standardized normalization.
    """

    def __init__(
        self,
        provider_id: str,
        timeout_seconds: float = 2.5,
        circuit_breaker_threshold: int = 3,
        circuit_reset_timeout: float = 60.0,
        ttl_seconds: float = 60.0,
        use_cache: bool = True,
    ):
        self._provider_id = provider_id
        self.timeout_seconds = timeout_seconds
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_reset_timeout = circuit_reset_timeout
        self.ttl_seconds = ttl_seconds
        self.use_cache = use_cache

        self._consecutive_failures = 0
        self._circuit_open_timestamp: Optional[float] = None
        self.last_error: Optional[str] = None

        # Thread-safe in-memory TTL cache: key -> (timestamp, results)
        self._cache: Dict[str, Tuple[float, List[Tuple[Evidence, float]]]] = {}
        self._cache_lock = threading.Lock()

    def _build_cache_key(self, query: str, k: int, filters: Optional[Dict[str, Any]]) -> str:
        clean_q = " ".join(query.strip().lower().split())
        f_repr = str(sorted(filters.items())) if filters else ""
        return f"{clean_q}::k={k}::filters={f_repr}"

    def _get_cached_search(
        self, query: str, k: int, filters: Optional[Dict[str, Any]]
    ) -> Optional[Tuple[List[Tuple[Evidence, float]], float]]:
        if not self.use_cache:
            return None
        key = self._build_cache_key(query, k, filters)
        now = time.time()
        with self._cache_lock:
            if key in self._cache:
                ts, results = self._cache[key]
                if (now - ts) < self.ttl_seconds:
                    return results, 0.05  # sub-millisecond cached response
                else:
                    del self._cache[key]
        return None

    def _set_cached_search(
        self, query: str, k: int, filters: Optional[Dict[str, Any]], results: List[Tuple[Evidence, float]]
    ) -> None:
        if not self.use_cache or not results:
            return
        key = self._build_cache_key(query, k, filters)
        with self._cache_lock:
            self._cache[key] = (time.time(), results)

    def clear_cache(self) -> None:
        """Purge all cached queries."""
        with self._cache_lock:
            self._cache.clear()

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {
            ProviderCapability.LEXICAL_SEARCH,
            ProviderCapability.NETWORK_REMOTE,
            ProviderCapability.STRUCTURED_FILTER,
        }

    def is_circuit_open(self) -> bool:
        """Check if circuit breaker is open (tripped)."""
        if self._consecutive_failures >= self.circuit_breaker_threshold:
            if self._circuit_open_timestamp:
                elapsed = time.time() - self._circuit_open_timestamp
                if elapsed > self.circuit_reset_timeout:
                    # Half-open: allow one probe
                    return False
            return True
        return False

    def record_success(self) -> None:
        """Record successful call, resetting circuit breaker counters."""
        self._consecutive_failures = 0
        self._circuit_open_timestamp = None
        self.last_error = None

    def record_failure(self, error: Optional[str] = None) -> None:
        """Record failed call and trip circuit breaker if threshold exceeded."""
        self._consecutive_failures += 1
        self.last_error = error or "Failure"
        if self._consecutive_failures >= self.circuit_breaker_threshold and not self._circuit_open_timestamp:
            self._circuit_open_timestamp = time.time()

    def normalize_evidence(
        self,
        source_id: str,
        source_type: str,
        content: str,
        uri: Optional[str] = None,
        source_path: str = "",
        chunk_index: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
    ) -> Evidence:
        """Helper to create standardized immutable Evidence chunks with valid hashes and byte offsets."""
        raw_bytes = content.encode("utf-8")
        content_hash = hashlib.sha256(raw_bytes).hexdigest()
        evidence_id = f"{source_type}:{source_id}#c{chunk_index:03d}"
        iso_time = created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return Evidence(
            evidence_id=evidence_id,
            source_id=source_id,
            source_type=source_type,
            uri=uri,
            content=content,
            content_hash=content_hash,
            source_path=source_path,
            chunk_index=chunk_index,
            start_offset=0,
            end_offset=len(raw_bytes),
            metadata=metadata or {},
            created_at=iso_time,
        )

    def search_provider(
        self,
        query: str,
        k: int = 4,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ProviderSearchResult]:
        results, _ = self.search(query, k=k, filters=filters)
        return [
            ProviderSearchResult(
                evidence_id=ev.evidence_id,
                source_type=ev.source_type,
                source_id=ev.source_id,
                content=ev.content,
                uri=ev.uri,
                score=score,
                metadata=ev.metadata,
                evidence=ev,
            )
            for ev, score in results
        ]

    @abstractmethod
    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """Subclasses must implement actual datastore or remote API search."""
        pass
