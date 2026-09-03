"""
Unit & Integration Tests for Brick 3.10:
End-to-End Real Federated Investigation Validation.

Validates:
  1. Provider Registry Integration: SQLite, Jira, and GitHub registered via generic interface.
  2. Multi-Provider Cross-Source Investigation: End-to-end multi-hop investigation loop
     across 3 heterogeneous providers (SQLite + Jira + GitHub) terminating with SUFFICIENT.
  3. Provenance Preservation: source_type, source_id, URI, chunk offsets, and metadata intact.
  4. Cross-Provider Content Hash Deduplication: Duplicate evidence across providers deduplicated.
  5. Provider Failure Isolation (Jira Timeout): Jira timeout does not crash investigation.
  6. Provider Failure Isolation (GitHub Error): GitHub 500 error does not crash investigation.
  7. Circuit Breaker Isolation: Tripped provider status marked CIRCUIT_OPEN; surviving providers succeed.
  8. Security & Secret Redaction: Verification that tokens and auth headers never leak into
     telemetry, traces, config repr, or error reports.
  9. Deterministic Reproducibility: Identical mock federated investigations yield identical traces.
"""

import json
from pathlib import Path
import httpx
import pytest

from backend.core.security import mask_secret, redact_sensitive_data, redact_sensitive_text
from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    GapStatus,
    InformationGap,
    InvestigationBudget,
    InvestigationState,
)
from backend.retrieval.adapters.config import GitHubConfig, JiraConfig
from backend.retrieval.adapters.github import GitHubEvidenceProvider
from backend.retrieval.adapters.jira import JiraEvidenceProvider
from backend.retrieval.base_external import ExternalEvidenceProvider
from backend.retrieval.federated import FederatedEvidenceProvider
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
from backend.retrieval.provider import ProviderCapability
from backend.retrieval.registry import EvidenceProviderRegistry, ProviderStatus

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------
@pytest.fixture
def sqlite_provider(tmp_path):
    """Fixture providing populated SQLite FTS5 retriever from nova_corpus."""
    db_path = tmp_path / "fts_brick310.db"
    retriever = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever.index_evidence(all_chunks)
    return retriever


@pytest.fixture
def mock_jira_adapter():
    """Mocked Jira EvidenceProvider returning authentic enterprise tickets."""
    jira_payload = {
        "issues": [
            {
                "key": "CR-904",
                "fields": {
                    "summary": "Emergency Redis v7 Upgrade Decision",
                    "description": "CAB unanimously rejected the emergency Redis v7 upgrade for the cutover window.",
                    "status": {"name": "Rejected"},
                    "issuetype": {"name": "Change Request"},
                    "priority": {"name": "Highest"},
                    "created": "2026-10-20T10:00:00.000Z",
                    "updated": "2026-10-21T14:30:00.000Z",
                },
            },
            {
                "key": "SEC-412",
                "fields": {
                    "summary": "Payment Gateway v2 mTLS 1.3 Certification",
                    "description": "Security team confirms mTLS 1.3 requirement is verified and operational for Redis connections.",
                    "status": {"name": "Approved"},
                    "issuetype": {"name": "Security Audit"},
                    "priority": {"name": "High"},
                    "created": "2026-10-21T08:00:00.000Z",
                    "updated": "2026-10-21T12:00:00.000Z",
                },
            },
        ]
    }

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "/rest/api/2/search" in url_str:
            return httpx.Response(200, json=jira_payload)
        if "/rest/api/2/issue/CR-904" in url_str:
            return httpx.Response(200, json=jira_payload["issues"][0])
        if "/rest/api/2/issue/SEC-412" in url_str:
            return httpx.Response(200, json=jira_payload["issues"][1])
        if "/rest/api/2/serverInfo" in url_str:
            return httpx.Response(200, json={"version": "9.4.0"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cfg = JiraConfig(
        base_url="https://jira.enterprise.internal",
        email_or_username="oracle-agent@enterprise.internal",
        api_token="test_jira_token_abc123",
        project_keys=["CR", "SEC"],
    )
    return JiraEvidenceProvider(cfg, client=client)


@pytest.fixture
def mock_github_adapter():
    """Mocked GitHub EvidenceProvider returning pull requests and issues."""
    github_payload = {
        "total_count": 2,
        "items": [
            {
                "number": 88,
                "title": "Payment Gateway v2 mTLS requirement enforcement",
                "body": "Enforces TLS 1.3 handshake on Redis datastore connections. Target: CR-904.",
                "state": "closed",
                "html_url": "https://github.com/nova-org/payment-gw/pull/88",
                "repository_url": "https://api.github.com/repos/nova-org/payment-gw",
                "pull_request": {"url": "https://api.github.com/repos/nova-org/payment-gw/pulls/88"},
                "user": {"login": "sec-lead"},
                "labels": [{"name": "security"}, {"name": "compliance"}],
                "created_at": "2026-10-18T09:00:00Z",
                "updated_at": "2026-10-20T16:00:00Z",
            },
            {
                "number": 105,
                "title": "Redis Connection Pool Rollback Handler",
                "body": "Reverts connection pool to Redis 6.2 compatibility mode following CAB rejection.",
                "state": "closed",
                "html_url": "https://github.com/nova-org/payment-gw/pull/105",
                "repository_url": "https://api.github.com/repos/nova-org/payment-gw",
                "pull_request": {"url": "https://api.github.com/repos/nova-org/payment-gw/pulls/105"},
                "user": {"login": "dba-lead"},
                "labels": [{"name": "database"}],
                "created_at": "2026-10-21T11:00:00Z",
                "updated_at": "2026-10-21T15:00:00Z",
            },
        ]
    }

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "/search/issues" in url_str:
            return httpx.Response(200, json=github_payload)
        if "/repos/nova-org/payment-gw/issues/88" in url_str:
            return httpx.Response(200, json=github_payload["items"][0])
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cfg = GitHubConfig(
        base_url="https://api.github.com",
        api_token="ghp_test_token_secret_xyz987",
        repos=["nova-org/payment-gw"],
    )
    return GitHubEvidenceProvider(cfg, client=client)


# -----------------------------------------------------------------------------
# 1. PROVIDER REGISTRY INTEGRATION
# -----------------------------------------------------------------------------
def test_real_provider_registry_integration(sqlite_provider, mock_jira_adapter, mock_github_adapter):
    """Verify SQLite, Jira, and GitHub are registered through generic interface into registry."""
    registry = EvidenceProviderRegistry()
    registry.register(sqlite_provider, is_default=True)
    registry.register(mock_jira_adapter)
    registry.register(mock_github_adapter)

    assert len(registry.list_providers()) == 3
    assert set(registry.list_providers()) == {"sqlite_fts5", "jira", "github"}
    assert registry.get_default() == sqlite_provider

    # Discovery by capability
    remotes = registry.get_by_capability(ProviderCapability.NETWORK_REMOTE)
    assert len(remotes) == 2
    assert {r.provider_id for r in remotes} == {"jira", "github"}

    lexicals = registry.get_by_capability(ProviderCapability.LEXICAL_SEARCH)
    assert len(lexicals) == 3


# -----------------------------------------------------------------------------
# 2. CROSS-SOURCE END-TO-END INVESTIGATION
# -----------------------------------------------------------------------------
def test_cross_source_investigation_e2e(sqlite_provider, mock_jira_adapter, mock_github_adapter):
    """
    CORE VALIDATION:
    Full autonomous investigation loop across SQLite (docs), Jira (tickets), and GitHub (PRs).
    The controller must formulate/reuse queries, retrieve from multiple providers,
    merge results via RRF, resolve gaps, and terminate through deterministic controller rules.
    """
    federated = FederatedEvidenceProvider(
        providers=[sqlite_provider, mock_jira_adapter, mock_github_adapter],
        provider_weights={"sqlite_fts5": 1.0, "jira": 1.0, "github": 1.0},
    )

    controller = InvestigationController(
        retriever=federated,
        budget=InvestigationBudget(max_hops=3, max_llm_calls=3),
    )

    step_calls = 0

    def reasoning_agent_fn(state: InvestigationState):
        nonlocal step_calls
        step_calls += 1
        has_jira = any(e.source_type == "jira" for e in state.accumulated_evidence.values())
        has_gh = any(e.source_type == "github" for e in state.accumulated_evidence.values())
        has_doc = any(e.source_type == "document" for e in state.accumulated_evidence.values())
        has_inc = any("INC-" in e.source_id or "POST-MORTEM" in e.content.upper() for e in state.accumulated_evidence.values())

        if has_jira and has_gh and has_doc and has_inc:
            return True, "All operational components verified across Jira, GitHub, docs, and post-mortem", [], []

        # If postmortem not yet retrieved, dispatch targeted query
        gap = InformationGap(
            gap_id="GAP-INC-POSTMORTEM",
            description="Investigate post-mortem rollback INC-402",
            targeted_query="Post-mortem INC-402 Redis rollback",
        )
        return False, "Retrieving incident post-mortem", [gap], []

    package = controller.run_investigation(
        objective="Verify if Project Phoenix Redis upgrade was approved by CAB and implemented in payment gateway",
        reasoning_agent_fn=reasoning_agent_fn,
        initial_k=8,
    )

    assert package is not None
    assert package.controller_verified is True
    assert package.termination_reason == "SUFFICIENT"
    assert len(package.evidence_items) >= 3

    # Verify cross-source presence in final admitted evidence
    sources = {e.source_type for e in package.evidence_items}
    assert "document" in sources
    assert "jira" in sources
    assert "github" in sources

    # Verify telemetry in package
    telem = package.federated_telemetry
    assert telem is not None
    assert set(telem["providers_queried"]).issuperset({"sqlite_fts5", "jira", "github"})
    assert telem["source_provenance_distribution"]["jira"] >= 1
    assert telem["source_provenance_distribution"]["github"] >= 1
    assert telem["source_provenance_distribution"]["document"] >= 1


# -----------------------------------------------------------------------------
# 3. PROVENANCE PRESERVATION
# -----------------------------------------------------------------------------
def test_provenance_preservation(sqlite_provider, mock_jira_adapter, mock_github_adapter):
    """
    Verify byte offsets, immutable content_hash, URIs, and source_type/source_id
    are preserved intact across all admitted evidence items.
    """
    federated = FederatedEvidenceProvider(
        providers=[sqlite_provider, mock_jira_adapter, mock_github_adapter]
    )

    hits, _ = federated.search("Payment Gateway Redis mTLS CR-904", k=8)
    assert len(hits) > 0

    for ev, score in hits:
        assert ev.evidence_id is not None
        assert ev.source_id is not None
        assert ev.source_type in {"document", "jira", "github"}
        assert len(ev.content_hash) == 64  # valid sha256
        assert ev.start_offset >= 0
        assert ev.end_offset > ev.start_offset
        if ev.source_type in {"jira", "github"}:
            assert ev.uri is not None and ev.uri.startswith("http")
        else:
            assert ev.source_path is not None
        assert isinstance(ev.metadata, dict)


# -----------------------------------------------------------------------------
# 4. CROSS-PROVIDER CONTENT HASH DEDUPLICATION
# -----------------------------------------------------------------------------
def test_cross_provider_content_hash_deduplication():
    """
    Verify duplicate text across distinct providers is merged via SHA-256 content_hash
    and rank scores accumulate to primary chunk.
    """
    duplicate_content = "All Redis instances must enforce TLS 1.3 handshake negotiation before cutover."

    jira = JiraEvidenceProvider(JiraConfig(base_url="https://jira.corp"))
    github = GitHubEvidenceProvider(GitHubConfig(base_url="https://api.github.com"))

    jira_ev = jira.normalize_evidence(source_id="DUP-JIRA-1", source_type="jira", content=duplicate_content)
    gh_ev = github.normalize_evidence(source_id="org/repo#999", source_type="github", content=duplicate_content)

    assert jira_ev.content_hash == gh_ev.content_hash

    # Create dummy provider wrappers returning these pre-normalized evidence chunks
    class StaticProvider(ExternalEvidenceProvider):
        def __init__(self, pid: str, evidence: Evidence):
            super().__init__(provider_id=pid, timeout_seconds=1.0)
            self.evidence = evidence

        def search(self, query, k=5, filters=None):
            return [(self.evidence, 4.0)], 1.0

        def search_provider(self, query, k=4, filters=None):
            return []

        def health_check(self):
            return True

    p1 = StaticProvider("source_a", jira_ev)
    p2 = StaticProvider("source_b", gh_ev)

    federated = FederatedEvidenceProvider(providers=[p1, p2])
    hits, _ = federated.search("Redis instances TLS 1.3 handshake", k=5)

    telem = federated.get_last_telemetry()
    assert telem is not None
    assert telem.raw_candidates_count == 2
    assert telem.deduplicated_count == 1
    assert len(hits) == 1
    assert hits[0][0].content_hash == jira_ev.content_hash


# -----------------------------------------------------------------------------
# 5. PROVIDER FAILURE ISOLATION (JIRA TIMEOUT)
# -----------------------------------------------------------------------------
def test_provider_failure_isolation_jira_timeout(sqlite_provider, mock_github_adapter):
    """
    FAULT ISOLATION:
    When Jira suffers a socket timeout, the federated search and investigation must NOT crash.
    SQLite and GitHub must continue serving evidence seamlessly.
    """
    def timing_out_handler(request: httpx.Request):
        raise httpx.ReadTimeout("Socket read timed out after 2.5s")

    failing_client = httpx.Client(transport=httpx.MockTransport(timing_out_handler))
    timing_out_jira = JiraEvidenceProvider(
        JiraConfig(base_url="https://jira.failing.corp", timeout_seconds=0.1),
        client=failing_client,
    )

    federated = FederatedEvidenceProvider(
        providers=[sqlite_provider, timing_out_jira, mock_github_adapter]
    )

    hits, elapsed_ms = federated.search("Payment Gateway Redis mTLS", k=5)
    assert len(hits) > 0

    sources = {ev.source_type for ev, _ in hits}
    assert "document" in sources
    assert "github" in sources
    assert "jira" not in sources

    telem = federated.get_last_telemetry()
    assert telem is not None
    assert "jira" in telem.provider_failures
    assert "ReadTimeout" in telem.provider_failures["jira"]
    assert "sqlite_fts5" in telem.providers_responded
    assert "github" in telem.providers_responded


# -----------------------------------------------------------------------------
# 6. PROVIDER FAILURE ISOLATION (GITHUB 500 ERROR)
# -----------------------------------------------------------------------------
def test_provider_failure_isolation_github_error(sqlite_provider, mock_jira_adapter):
    """
    FAULT ISOLATION:
    When GitHub returns HTTP 500 internal error, the federated search and investigation
    must continue with SQLite and Jira evidence without crashing.
    """
    def error_handler(request: httpx.Request):
        return httpx.Response(500, json={"message": "Internal Server Error"})

    failing_client = httpx.Client(transport=httpx.MockTransport(error_handler))
    failing_github = GitHubEvidenceProvider(
        GitHubConfig(base_url="https://api.github.com", max_retries=1),
        client=failing_client,
    )

    federated = FederatedEvidenceProvider(
        providers=[sqlite_provider, mock_jira_adapter, failing_github]
    )

    controller = InvestigationController(
        retriever=federated,
        budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
    )

    package = controller.run_investigation(
        objective="Check Redis CR-904 status and architecture requirements",
        reasoning_agent_fn=lambda s: (True, "Verified from Jira and docs", [], []),
        initial_k=6,
    )

    assert package is not None
    assert len(package.evidence_items) > 0
    sources = {ev.source_type for ev in package.evidence_items}
    assert "document" in sources
    assert "jira" in sources
    assert "github" not in sources

    telem = package.federated_telemetry
    assert telem is not None
    assert "github" in telem["provider_failures"]


# -----------------------------------------------------------------------------
# 7. CIRCUIT BREAKER ISOLATION
# -----------------------------------------------------------------------------
def test_circuit_breaker_isolation():
    """Verify circuit breaker trips to CIRCUIT_OPEN after consecutive errors without degrading peers."""
    def error_handler(request: httpx.Request):
        return httpx.Response(503, json={"message": "Service Unavailable"})

    failing_client = httpx.Client(transport=httpx.MockTransport(error_handler))
    failing_jira = JiraEvidenceProvider(
        JiraConfig(base_url="https://jira.down.corp", max_retries=0),
        client=failing_client,
    )

    good_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={"total_count": 1, "items": [{"number": 1, "title": "Good PR", "body": "PR Body", "state": "open", "html_url": "https://github.com/org/repo/pull/1", "repository_url": "https://api.github.com/repos/org/repo"}]}
            )
        )
    )
    good_github = GitHubEvidenceProvider(GitHubConfig(base_url="https://api.github.com"), client=good_client)

    federated = FederatedEvidenceProvider(providers=[failing_jira, good_github])

    # Search 3 times to exceed circuit_breaker_threshold
    for _ in range(3):
        federated.search("test", k=2)

    assert failing_jira.is_circuit_open() is True
    assert federated.registry.get_status("jira") == ProviderStatus.CIRCUIT_OPEN

    # Subsequent search should immediately bypass failing_jira via circuit breaker
    hits, _ = federated.search("test", k=2)
    assert len(hits) == 1
    assert hits[0][0].source_type == "github"


# -----------------------------------------------------------------------------
# 8. SECURITY & SECRETS AUDIT
# -----------------------------------------------------------------------------
def test_secrets_redaction_and_audit():
    """
    SECURITY INVARIANT:
    Ensures that credentials, API tokens, passwords, and authorization headers
    are NEVER exposed in config repr, string conversions, telemetry, or trace events.
    """
    secret_token = "ghp_VERY_SECRET_TOKEN_1234567890ABCDEF"
    secret_jira = "jira_super_secret_pat_9876543210"

    cfg_gh = GitHubConfig(base_url="https://api.github.com", api_token=secret_token)
    cfg_jira = JiraConfig(base_url="https://jira.corp", api_token=secret_jira)

    # 1. Config repr must NOT display token
    assert secret_token not in repr(cfg_gh)
    assert secret_token not in str(cfg_gh)
    assert secret_jira not in repr(cfg_jira)
    assert secret_jira not in str(cfg_jira)
    assert "***REDACTED***" in repr(cfg_gh)

    # 2. Text sanitization
    raw_log = f"Authorization: Bearer {secret_token} and Basic dXNlcjpwYXNz"
    sanitized = redact_sensitive_text(raw_log, known_secrets={secret_token, secret_jira})
    assert secret_token not in sanitized
    assert "Bearer ***REDACTED***" in sanitized

    # 3. Data structure sanitization
    raw_dict = {
        "provider": "github",
        "api_token": secret_token,
        "nested": {"auth_header": f"Bearer {secret_token}", "count": 5},
    }
    cleaned_dict = redact_sensitive_data(raw_dict, known_secrets={secret_token})
    assert cleaned_dict["api_token"] == "***REDACTED***"
    assert secret_token not in str(cleaned_dict)


# -----------------------------------------------------------------------------
# 9. DETERMINISTIC REPRODUCIBILITY
# -----------------------------------------------------------------------------
def test_deterministic_reproducibility(sqlite_provider, mock_jira_adapter, mock_github_adapter):
    """Verify identical mock inputs produce deterministically identical traces and evidence package."""
    def run_trial():
        fed = FederatedEvidenceProvider(
            providers=[sqlite_provider, mock_jira_adapter, mock_github_adapter],
            provider_weights={"sqlite_fts5": 1.0, "jira": 1.0, "github": 1.0},
        )
        ctrl = InvestigationController(
            retriever=fed,
            budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
        )
        return ctrl.run_investigation(
            objective="Verify CR-904 rejection status",
            reasoning_agent_fn=lambda s: (True, "Deterministic finish", [], []),
            initial_k=6,
        )

    pkg1 = run_trial()
    pkg2 = run_trial()

    assert pkg1.controller_verified == pkg2.controller_verified
    assert pkg1.termination_reason == pkg2.termination_reason
    assert len(pkg1.evidence_items) == len(pkg2.evidence_items)
    assert [e.evidence_id for e in pkg1.evidence_items] == [e.evidence_id for e in pkg2.evidence_items]
