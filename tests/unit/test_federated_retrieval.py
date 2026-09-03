"""
Unit Tests for Brick 3.9: Federated Retrieval & Evidence Provider Registry
Validates:
  1. EvidenceProviderRegistry registration, lookup, and capability discovery.
  2. Single-provider passthrough guarantee (exact backward compatibility with SQLiteFTS5Retriever).
  3. Multi-source parallel dispatch & Reciprocal Rank Fusion (RRF) ranking.
  4. Fault tolerance: Timeout isolation (Jira timeout does not crash search).
  5. Circuit-breaker tripping upon repeated failures.
  6. Multi-tier cross-source content-hash deduplication.
  7. InvestigationController execution with FederatedEvidenceProvider.
"""

import json
from pathlib import Path
import pytest

from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.models import InvestigationBudget, InvestigationState
from backend.retrieval.base_external import ExternalEvidenceProvider
from backend.retrieval.federated import FederatedEvidenceProvider
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
from backend.retrieval.provider import ProviderCapability
from backend.retrieval.registry import EvidenceProviderRegistry, ProviderStatus
from tests.mocks.mock_enterprise_providers import MockGitHubProvider, MockJiraProvider, MockSlackProvider

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def sqlite_retriever(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("fed_test") / "fts.db"
    retriever = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever.index_evidence(all_chunks)
    return retriever


def test_registry_registration_and_capability_discovery(sqlite_retriever):
    """Verify provider registration, default designation, and capability querying."""
    registry = EvidenceProviderRegistry()
    registry.register(sqlite_retriever, is_default=True)

    jira = MockJiraProvider()
    registry.register(jira)

    assert registry.list_providers() == ["sqlite_fts5", "mock_jira"]
    assert registry.get_default() == sqlite_retriever
    assert registry.get("mock_jira") == jira

    # Capability query
    lexical_providers = registry.get_by_capability(ProviderCapability.LEXICAL_SEARCH)
    assert len(lexical_providers) == 2

    remote_providers = registry.get_by_capability(ProviderCapability.NETWORK_REMOTE)
    assert len(remote_providers) == 1
    assert remote_providers[0] == jira


def test_federated_single_provider_backward_compatibility(sqlite_retriever):
    """
    PASSTHROUGH INVARIANT:
    When wrapping a single provider, FederatedEvidenceProvider delegates directly
    and produces numerically identical output to the underlying provider.
    """
    fed = FederatedEvidenceProvider(providers=[sqlite_retriever])
    query = "Project Phoenix launch cutover window"

    direct_hits, _ = sqlite_retriever.search(query, k=5)
    fed_hits, _ = fed.search(query, k=5)

    assert len(direct_hits) == len(fed_hits)
    for (d_ev, d_sc), (f_ev, f_sc) in zip(direct_hits, fed_hits):
        assert d_ev.evidence_id == f_ev.evidence_id
        assert d_sc == f_sc


def test_federated_multi_source_rrf_merging(sqlite_retriever):
    """Verify multi-provider query dispatch and reciprocal rank fusion."""
    mock_jira = MockJiraProvider(
        issues=[
            {
                "key": "PAY-101",
                "summary": "Payment Gateway v2 mTLS datastore requirements",
                "status": "Closed",
                "description": "Enforces mTLS 1.3 across all TCP datastore connections.",
            }
        ]
    )

    fed = FederatedEvidenceProvider(
        providers=[sqlite_retriever, mock_jira],
    )

    hits, _ = fed.search("Payment Gateway mTLS requirements", k=5)
    assert len(hits) > 0

    sources = {ev.source_type for ev, _ in hits}
    assert "document" in sources
    assert "jira" in sources


def test_federated_timeout_fault_tolerance(sqlite_retriever):
    """
    FAULT TOLERANCE INVARIANT:
    A timing-out remote provider must NOT crash the federated search;
    healthy local results must be returned seamlessly.
    """
    timing_out_jira = MockJiraProvider(simulate_timeout=True)
    fed = FederatedEvidenceProvider(providers=[sqlite_retriever, timing_out_jira])

    hits, elapsed_ms = fed.search("Project Phoenix", k=4)
    # Search must succeed with local results
    assert len(hits) > 0
    assert all(ev.source_type == "document" for ev, _ in hits)


def test_federated_circuit_breaker_tripping():
    """Verify circuit breaker trips after consecutive failures and stops dispatching."""
    failing_jira = MockJiraProvider(simulate_error=True)
    slack = MockSlackProvider(messages=[{"channel": "general", "text": "Phoenix launch status"}])

    fed = FederatedEvidenceProvider(providers=[failing_jira, slack])

    # Call 3 times to exceed circuit_breaker_threshold
    for _ in range(3):
        fed.search("Phoenix", k=2)

    assert failing_jira.is_circuit_open() is True
    assert fed.registry.get_status(failing_jira.provider_id) == ProviderStatus.CIRCUIT_OPEN


def test_federated_cross_source_content_hash_deduplication():
    """Verify exact duplicate content across providers is deduplicated via content_hash."""
    duplicate_text = "Standard cutover procedure: verified 48 hours of soak tests."
    jira = MockJiraProvider(
        issues=[{"key": "REL-1", "summary": duplicate_text, "description": duplicate_text}]
    )
    slack = MockSlackProvider(
        messages=[{"channel": "releases", "text": duplicate_text}]
    )

    fed = FederatedEvidenceProvider(providers=[jira, slack])
    hits, _ = fed.search("Standard cutover procedure", k=5)

    # Identical content hashes must be deduplicated into a single entry
    content_hashes = [ev.content_hash for ev, _ in hits]
    assert len(content_hashes) == len(set(content_hashes))


def test_controller_integration_with_federated_provider(sqlite_retriever):
    """Verify InvestigationController functions seamlessly when injected with FederatedEvidenceProvider."""
    jira = MockJiraProvider(
        issues=[
            {
                "key": "CR-904",
                "summary": "Emergency Redis v7 Upgrade Decision",
                "status": "Rejected",
                "description": "CAB unanimously rejected CR-904 for Friday morning launch.",
            }
        ]
    )
    fed = FederatedEvidenceProvider(providers=[sqlite_retriever, jira])
    controller = InvestigationController(
        retriever=fed,
        budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
    )

    def mock_step(state: InvestigationState):
        return False, "", [], []

    package = controller.run_investigation(
        objective="Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        reasoning_agent_fn=mock_step,
        initial_k=8,
    )

    assert len(package.evidence_items) >= 4
    assert package.termination_reason is not None
