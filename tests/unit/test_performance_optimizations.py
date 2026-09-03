"""
Unit tests for ORACLE Performance Optimizations:
1. In-memory TTL query caching on ExternalEvidenceProvider
2. Persistent ThreadPoolExecutor in FederatedEvidenceProvider
3. Capability-driven provider pruning
4. Concurrent multi-gap execution in InvestigationController
"""

import time
import httpx
import pytest

from backend.evidence.models import Evidence
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    InformationGap,
    InvestigationBudget,
    InvestigationState,
)
from backend.retrieval.adapters.config import JiraConfig
from backend.retrieval.adapters.jira import JiraEvidenceProvider
from backend.retrieval.base_external import ExternalEvidenceProvider
from backend.retrieval.federated import FederatedEvidenceProvider
from backend.retrieval.provider import ProviderCapability


class MockFastProvider(ExternalEvidenceProvider):
    def __init__(self, pid: str, response_text: str = "Sample response text"):
        super().__init__(provider_id=pid, ttl_seconds=0.5, use_cache=True)
        self.call_count = 0
        self.response_text = response_text

    def health_check(self) -> bool:
        return True

    def search(self, query: str, k: int = 5, filters=None):
        cached = self._get_cached_search(query, k, filters)
        if cached is not None:
            return cached

        self.call_count += 1
        time.sleep(0.01)  # 10ms simulated work
        ev = self.normalize_evidence(
            source_id="TEST-1",
            source_type=self._provider_id,
            content=f"{self.response_text} for {query}",
        )
        hits = [(ev, 3.5)]
        self._set_cached_search(query, k, filters, hits)
        return hits, 10.0


def test_external_provider_ttl_cache_hit_and_speed():
    """Verify repeat queries return cached results in sub-millisecond time."""
    prov = MockFastProvider("cache_test")

    # First search: cache miss
    hits1, lat1 = prov.search("Redis clustering", k=5)
    assert len(hits1) == 1
    assert prov.call_count == 1

    # Second search: cache hit
    hits2, lat2 = prov.search("Redis clustering", k=5)
    assert len(hits2) == 1
    assert prov.call_count == 1  # No additional backend call
    assert lat2 < 1.0  # Sub-millisecond return
    assert hits1[0][0].evidence_id == hits2[0][0].evidence_id

    # Test clear_cache
    prov.clear_cache()
    hits3, lat3 = prov.search("Redis clustering", k=5)
    assert len(hits3) == 1
    assert prov.call_count == 2  # Fresh backend call


def test_external_provider_cache_expiry():
    """Verify cached entries expire after ttl_seconds."""
    prov = MockFastProvider("expiry_test")
    prov.ttl_seconds = 0.1  # 100ms TTL

    prov.search("Kafka partition lag", k=3)
    assert prov.call_count == 1

    # Immediate search -> hit
    prov.search("Kafka partition lag", k=3)
    assert prov.call_count == 1

    # Wait for TTL expiry
    time.sleep(0.15)
    prov.search("Kafka partition lag", k=3)
    assert prov.call_count == 2  # Cache expired and re-fetched


def test_persistent_thread_pool_reuse():
    """Verify FederatedEvidenceProvider reuses worker pool without recreation."""
    p1 = MockFastProvider("p1")
    p2 = MockFastProvider("p2")
    federated = FederatedEvidenceProvider(providers=[p1, p2], max_workers=2)

    executor_id = id(federated._executor)

    # First search
    federated.search("payment gateway", k=4)
    assert id(federated._executor) == executor_id

    # Second search
    federated.search("order processing", k=4)
    assert id(federated._executor) == executor_id

    federated.close()


def test_capability_driven_provider_pruning():
    """
    Verify generic capability filtering routes queries strictly to matching providers,
    bypassing remote network providers when only local cache is required.
    """
    class LocalDocProvider(ExternalEvidenceProvider):
        @property
        def capabilities(self):
            return {ProviderCapability.LEXICAL_SEARCH, ProviderCapability.LOCAL_CACHE}

        def health_check(self) -> bool:
            return True

        def search(self, query, k=5, filters=None):
            ev = self.normalize_evidence("DOC-1", "doc", "Local documentation content")
            return [(ev, 4.0)], 1.0

    class RemoteCloudProvider(ExternalEvidenceProvider):
        def __init__(self):
            super().__init__(provider_id="remote_cloud")
            self.called = False

        @property
        def capabilities(self):
            return {ProviderCapability.LEXICAL_SEARCH, ProviderCapability.NETWORK_REMOTE}

        def health_check(self) -> bool:
            return True

        def search(self, query, k=5, filters=None):
            self.called = True
            ev = self.normalize_evidence("REMOTE-1", "cloud", "Remote cloud content")
            return [(ev, 4.0)], 50.0

    local_p = LocalDocProvider("local_doc")
    remote_p = RemoteCloudProvider()

    fed = FederatedEvidenceProvider(providers=[local_p, remote_p])

    # Search requiring LOCAL_CACHE capability
    hits, _ = fed.search(
        "Architecture overview",
        k=5,
        filters={"required_capabilities": {ProviderCapability.LOCAL_CACHE}},
    )

    telem = fed.get_last_telemetry()
    assert telem is not None
    assert "local_doc" in telem.providers_queried
    assert "remote_cloud" not in telem.providers_queried
    assert remote_p.called is False  # Remote cloud provider was completely bypassed!
    assert len(hits) == 1
    assert hits[0][0].source_type == "doc"


def test_controller_batch_multi_gap_retrieval():
    """
    Verify InvestigationController executes multiple candidate gaps concurrently
    in a single hop when max_batch_gaps > 1.
    """
    p = MockFastProvider("batch_prov")
    controller = InvestigationController(retriever=p, max_batch_gaps=2)

    step_count = 0

    def reasoning_agent_fn(state: InvestigationState):
        nonlocal step_count
        step_count += 1
        if step_count == 1:
            # Propose 2 distinct actionable gaps
            gap1 = InformationGap(gap_id="GAP-A", description="Gap A", targeted_query="Topic Alpha query")
            gap2 = InformationGap(gap_id="GAP-B", description="Gap B", targeted_query="Topic Beta query")
            return False, "Investigating two gaps in batch", [gap1, gap2], []
        return True, "Sufficient", [], []

    package = controller.run_investigation(
        objective="Investigate Project Phoenix Alpha and Beta",
        reasoning_agent_fn=reasoning_agent_fn,
        initial_k=4,
    )

    assert package is not None
    # Check that in Hop 1, BOTH gaps were executed
    hop1_gap_events = [
        e for e in package.investigation_trace
        if e.hop == 1 and e.event_type == "ACTIONABLE_GAP_EXECUTED"
    ]
    assert len(hop1_gap_events) == 2
    executed_queries = {e.details["query"] for e in hop1_gap_events}
    assert "Topic Alpha query" in executed_queries
    assert "Topic Beta query" in executed_queries
