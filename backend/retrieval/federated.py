"""
ORACLE Federated Evidence Provider (Brick 3.9)
Coordinates parallel multi-source retrieval across heterogeneous datastores
(SQLite/FTS5, Jira, Linear, GitHub, Slack) with Reciprocal Rank Fusion (RRF),
timeout isolation, circuit-breaker awareness, and multi-tier deduplication.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pydantic import BaseModel, Field

from backend.core.security import redact_sensitive_text
from backend.evidence.models import Evidence
from backend.retrieval.base_external import ExternalEvidenceProvider
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult
from backend.retrieval.registry import EvidenceProviderRegistry, ProviderStatus


class FederatedSearchTelemetry(BaseModel):
    """Deterministic telemetry for a multi-source federated search dispatch."""
    providers_queried: List[str] = Field(default_factory=list)
    providers_responded: List[str] = Field(default_factory=list)
    provider_failures: Dict[str, str] = Field(default_factory=dict)
    candidates_per_provider: Dict[str, int] = Field(default_factory=dict)
    raw_candidates_count: int = 0
    deduplicated_count: int = 0
    fused_candidates_count: int = 0
    fusion_scores: Dict[str, float] = Field(default_factory=dict)
    latency_ms: float = 0.0


class FederatedEvidenceProvider(EvidenceProvider):
    """
    Federated retrieval coordinator that presents a single unified EvidenceProvider
    interface to the Investigation Controller while fanning out queries across
    multiple independent child providers.
    """

    def __init__(
        self,
        providers: Optional[List[EvidenceProvider]] = None,
        registry: Optional[EvidenceProviderRegistry] = None,
        provider_weights: Optional[Dict[str, float]] = None,
        max_workers: int = 4,
        rrf_k: int = 60,
    ):
        if registry:
            self.registry = registry
        else:
            self.registry = EvidenceProviderRegistry()
            if providers:
                for idx, p in enumerate(providers):
                    self.registry.register(p, is_default=(idx == 0))

        self.provider_weights = provider_weights or {}
        self.max_workers = max_workers
        self.rrf_k = rrf_k
        self._provider_id = "federated_provider"
        self._telemetry_lock = threading.Lock()
        self._last_telemetry: Optional[FederatedSearchTelemetry] = None
        self._all_telemetry: List[FederatedSearchTelemetry] = []
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)

    def close(self) -> None:
        """Shutdown persistent worker thread pool."""
        self._executor.shutdown(wait=False)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        """Union of all capabilities supported across healthy child providers."""
        all_caps: Set[ProviderCapability] = set()
        for p in self.registry.get_all():
            all_caps.update(p.capabilities)
        return all_caps

    def get_last_telemetry(self) -> Optional[FederatedSearchTelemetry]:
        """Retrieve telemetry from the most recent search dispatch."""
        with self._telemetry_lock:
            return self._last_telemetry

    def get_all_telemetry(self) -> List[FederatedSearchTelemetry]:
        """Retrieve history of all search telemetry events for this instance."""
        with self._telemetry_lock:
            return list(self._all_telemetry)

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """
        Execute search across active providers.
        Fast-path optimization: if exactly 1 provider is registered, directly delegates
        to avoid any threading overhead or score distortion.
        """
        t0 = time.perf_counter()
        providers = self.registry.get_all()

        # Capability-driven provider pruning (fully generic & domain-agnostic)
        if filters and "required_capabilities" in filters:
            req = filters["required_capabilities"]
            if isinstance(req, (set, list, tuple)):
                req_set = set(req)
                providers = [p for p in providers if req_set.issubset(p.capabilities)]

        if not providers:
            telem = FederatedSearchTelemetry(latency_ms=0.0)
            with self._telemetry_lock:
                self._last_telemetry = telem
                self._all_telemetry.append(telem)
            return [], (time.perf_counter() - t0) * 1000.0

        # Optimization: single provider passthrough guarantees exact numerical backward compatibility
        if len(providers) == 1:
            single = providers[0]
            if isinstance(single, ExternalEvidenceProvider) and single.is_circuit_open():
                telem = FederatedSearchTelemetry(
                    providers_queried=[single.provider_id],
                    provider_failures={single.provider_id: "CircuitOpen"},
                    latency_ms=0.0,
                )
                with self._telemetry_lock:
                    self._last_telemetry = telem
                    self._all_telemetry.append(telem)
                return [], (time.perf_counter() - t0) * 1000.0

            res_list, elapsed_ms = single.search(query, k=k, filters=filters)
            telem = FederatedSearchTelemetry(
                providers_queried=[single.provider_id],
                providers_responded=[single.provider_id],
                candidates_per_provider={single.provider_id: len(res_list)},
                raw_candidates_count=len(res_list),
                deduplicated_count=0,
                fused_candidates_count=len(res_list),
                fusion_scores={ev.evidence_id: score for ev, score in res_list},
                latency_ms=round(elapsed_ms, 2),
            )
            with self._telemetry_lock:
                self._last_telemetry = telem
                self._all_telemetry.append(telem)
            return res_list, elapsed_ms

        # Multi-provider parallel dispatch
        candidate_lists: List[Tuple[str, List[Tuple[Evidence, float]]]] = []
        providers_queried: List[str] = [p.provider_id for p in providers]
        providers_responded: List[str] = []
        provider_failures: Dict[str, str] = {}
        candidates_per_provider: Dict[str, int] = {}
        timeout_budget = 3.0  # default hard ceiling for federated fanout

        future_to_provider = {}
        for p in providers:
            # Check circuit breaker if remote external provider
            if isinstance(p, ExternalEvidenceProvider) and p.is_circuit_open():
                self.registry.set_status(p.provider_id, ProviderStatus.CIRCUIT_OPEN)
                provider_failures[p.provider_id] = "CircuitOpen"
                continue

            timeout = getattr(p, "timeout_seconds", timeout_budget)
            future = self._executor.submit(p.search, query, k=max(k, 8), filters=filters)
            future_to_provider[future] = (p, timeout)

        for future in as_completed(future_to_provider):
            p, timeout = future_to_provider[future]
            try:
                res_list, _ = future.result(timeout=timeout)
                if isinstance(p, ExternalEvidenceProvider) and p._consecutive_failures > 0:
                    err_name = getattr(p, "last_error", "ProviderError") or "ProviderError"
                    safe_err = redact_sensitive_text(str(err_name))
                    provider_failures[p.provider_id] = safe_err
                    candidates_per_provider[p.provider_id] = 0
                    if p.is_circuit_open():
                        self.registry.set_status(p.provider_id, ProviderStatus.CIRCUIT_OPEN)
                    else:
                        self.registry.set_status(p.provider_id, ProviderStatus.DEGRADED)
                else:
                    candidate_lists.append((p.provider_id, res_list))
                    providers_responded.append(p.provider_id)
                    candidates_per_provider[p.provider_id] = len(res_list)
                    self.registry.set_status(p.provider_id, ProviderStatus.HEALTHY)
            except Exception as exc:
                err_name = exc.__class__.__name__
                safe_err = redact_sensitive_text(str(err_name))
                provider_failures[p.provider_id] = safe_err
                candidates_per_provider[p.provider_id] = 0

                # Handle circuit breakers and degraded status
                if isinstance(p, ExternalEvidenceProvider):
                    p.record_failure(safe_err)
                    if p.is_circuit_open():
                        self.registry.set_status(p.provider_id, ProviderStatus.CIRCUIT_OPEN)
                    else:
                        self.registry.set_status(p.provider_id, ProviderStatus.DEGRADED)
                else:
                    self.registry.set_status(p.provider_id, ProviderStatus.DEGRADED)

        # Sort candidate lists by provider_id to guarantee deterministic RRF iteration order
        candidate_lists.sort(key=lambda item: item[0])

        # Reciprocal Rank Fusion (RRF) & Multi-Tier Deduplication
        fused_candidates, dedup_count, fusion_scores = self._fuse_and_deduplicate_with_stats(
            candidate_lists, k=k
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        raw_count = sum(len(hits) for _, hits in candidate_lists)
        telem = FederatedSearchTelemetry(
            providers_queried=providers_queried,
            providers_responded=providers_responded,
            provider_failures=provider_failures,
            candidates_per_provider=candidates_per_provider,
            raw_candidates_count=raw_count,
            deduplicated_count=dedup_count,
            fused_candidates_count=len(fused_candidates),
            fusion_scores=fusion_scores,
            latency_ms=round(elapsed_ms, 2),
        )
        with self._telemetry_lock:
            self._last_telemetry = telem
            self._all_telemetry.append(telem)

        return fused_candidates, elapsed_ms

    def _fuse_and_deduplicate(
        self,
        candidate_lists: List[Tuple[str, List[Tuple[Evidence, float]]]],
        k: int,
    ) -> List[Tuple[Evidence, float]]:
        fused, _, _ = self._fuse_and_deduplicate_with_stats(candidate_lists, k=k)
        return fused

    def _fuse_and_deduplicate_with_stats(
        self,
        candidate_lists: List[Tuple[str, List[Tuple[Evidence, float]]]],
        k: int,
    ) -> Tuple[List[Tuple[Evidence, float]], int, Dict[str, float]]:
        """
        Merges multi-source rankings via Reciprocal Rank Fusion (RRF) with exact
        content_hash and canonical identity deduplication.
        Returns: (scored_pairs, deduplicated_count, fusion_scores)
        """
        rrf_scores: Dict[str, float] = {}
        evidence_by_id: Dict[str, Evidence] = {}
        seen_content_hashes: Dict[str, str] = {}  # content_hash -> primary evidence_id
        dedup_count = 0

        for provider_id, hits in candidate_lists:
            weight = self.provider_weights.get(provider_id, 1.0)
            for rank, (ev, raw_score) in enumerate(hits, start=1):
                # Tier 1 Deduplication: Exact SHA-256 content match
                if ev.content_hash in seen_content_hashes:
                    primary_id = seen_content_hashes[ev.content_hash]
                    # Accumulate RRF rank to the primary chunk
                    rrf_scores[primary_id] = rrf_scores.get(primary_id, 0.0) + (weight / (self.rrf_k + rank))
                    dedup_count += 1
                    continue

                seen_content_hashes[ev.content_hash] = ev.evidence_id
                evidence_by_id[ev.evidence_id] = ev
                rrf_scores[ev.evidence_id] = rrf_scores.get(ev.evidence_id, 0.0) + (weight / (self.rrf_k + rank))

        # Scale RRF scores into positive range and sort descending
        scored_pairs: List[Tuple[Evidence, float]] = []
        fusion_scores: Dict[str, float] = {}
        for eid, score in rrf_scores.items():
            ev = evidence_by_id[eid]
            normalized_score = round(score * 100.0, 3)
            scored_pairs.append((ev, normalized_score))
            fusion_scores[eid] = normalized_score

        # Sort descending by score; on ties sort deterministically by evidence_id
        scored_pairs.sort(key=lambda item: (-item[1], item[0].evidence_id))
        return scored_pairs[:k], dedup_count, fusion_scores

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

    def health_check(self) -> bool:
        """Federation is healthy if at least one child provider is healthy."""
        checks = self.registry.health_check_all()
        return any(checks.values()) if checks else True
