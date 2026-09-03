"""
Unit Tests for Brick 3.9: Real Jira and GitHub EvidenceProvider Adapters
Validates:
  1. Jira authentication headers (Basic vs Bearer).
  2. Jira JQL synthesis and text sanitization.
  3. Jira rate-limit (HTTP 429) backoff and retry.
  4. Jira evidence normalization (byte offsets, SHA-256 hash, URI, metadata).
  5. Jira direct entity lookup.
  6. GitHub authentication headers and query qualifier construction.
  7. GitHub rate-limit (X-RateLimit-Remaining) backoff.
  8. GitHub evidence normalization (PR vs Issue detection, URI, byte offsets).
  9. GitHub direct entity lookup.
 10. Multi-source federated search combining SQLite, Jira, and GitHub simultaneously.
"""

import json
from pathlib import Path
import httpx
import pytest

from backend.evidence.parser import MarkdownEvidenceParser
from backend.retrieval.adapters.config import GitHubConfig, JiraConfig
from backend.retrieval.adapters.github import GitHubEvidenceProvider
from backend.retrieval.adapters.jira import JiraEvidenceProvider
from backend.retrieval.federated import FederatedEvidenceProvider
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


# -----------------------------------------------------------------------------
# JIRA ADAPTER TESTS
# -----------------------------------------------------------------------------
def test_jira_auth_headers_basic_and_bearer():
    """Verify Basic Auth and Bearer token headers generation."""
    basic_cfg = JiraConfig(
        base_url="https://jira.corp.internal",
        email_or_username="testuser@corp.internal",
        api_token="secr3t_tok3n",
    )
    basic_provider = JiraEvidenceProvider(basic_cfg)
    headers = basic_provider._build_headers()
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")

    bearer_cfg = JiraConfig(
        base_url="https://jira.corp.internal",
        api_token="bearer_pat_token",
    )
    bearer_provider = JiraEvidenceProvider(bearer_cfg)
    b_headers = bearer_provider._build_headers()
    assert b_headers["Authorization"] == "Bearer bearer_pat_token"


def test_jira_jql_synthesis_and_sanitization():
    """Verify safe JQL query generation with project scoping and character sanitization."""
    cfg = JiraConfig(
        base_url="https://jira.corp.internal",
        project_keys=["PROJ", "CORE"],
    )
    provider = JiraEvidenceProvider(cfg)

    # Free text with special chars
    jql = provider._build_jql("critical cache failure (redis:6.0) & rollback!")
    assert 'project in ("PROJ", "CORE")' in jql
    assert 'text ~ "critical cache failure redis 6.0 rollback"' in jql
    assert "order by updated desc" in jql

    # Query with explicit issue key
    jql_key = provider._build_jql("Investigate status of CR-904")
    assert 'key in ("CR-904")' in jql_key


def test_jira_search_and_evidence_normalization():
    """Verify mock HTTP search response parsing and Evidence normalization."""
    mock_payload = {
        "issues": [
            {
                "key": "CR-904",
                "fields": {
                    "summary": "Emergency Redis v7 Upgrade",
                    "description": "DBA team unanimously rejected the proposed change window.",
                    "status": {"name": "Rejected"},
                    "issuetype": {"name": "Change Request"},
                    "priority": {"name": "High"},
                    "created": "2026-10-20T10:00:00.000Z",
                    "updated": "2026-10-21T14:30:00.000Z",
                },
            }
        ]
    }

    def handler(request: httpx.Request):
        if "/rest/api/2/search" in str(request.url):
            return httpx.Response(200, json=mock_payload)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    cfg = JiraConfig(base_url="https://jira.corp.internal")
    provider = JiraEvidenceProvider(cfg, client=client)

    hits, latency = provider.search("Emergency Redis CR-904", k=5)
    assert len(hits) == 1
    ev, score = hits[0]

    assert ev.evidence_id == "jira:CR-904#c000"
    assert ev.source_id == "CR-904"
    assert ev.source_type == "jira"
    assert ev.uri == "https://jira.corp.internal/browse/CR-904"
    assert ev.start_offset == 0
    assert ev.end_offset == len(ev.content.encode("utf-8"))
    assert len(ev.content_hash) == 64
    assert ev.metadata["status"] == "Rejected"
    assert "DBA team unanimously rejected" in ev.content
    assert score > 0.0


def test_jira_rate_limit_backoff_and_retry():
    """Verify HTTP 429 response triggers backoff retry and succeeds."""
    attempts = 0

    def handler(request: httpx.Request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0.1"})
        return httpx.Response(
            200,
            json={"issues": [{"key": "TICK-1", "fields": {"summary": "Rate limited ticket"}}]},
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    cfg = JiraConfig(base_url="https://jira.corp.internal", max_retries=2)
    provider = JiraEvidenceProvider(cfg, client=client)

    hits, _ = provider.search("Rate limited ticket", k=1)
    assert attempts == 2
    assert len(hits) == 1
    assert hits[0][0].source_id == "TICK-1"


def test_jira_direct_entity_lookup():
    """Verify direct O(1) ticket key lookup via issue endpoint."""
    def handler(request: httpx.Request):
        if "/rest/api/2/issue/CR-904" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "key": "CR-904",
                    "fields": {
                        "summary": "Direct lookup summary",
                        "description": "Direct lookup description",
                        "status": {"name": "Approved"},
                    },
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    cfg = JiraConfig(base_url="https://jira.corp.internal")
    provider = JiraEvidenceProvider(cfg, client=client)

    ev = provider.lookup_entity("CR-904")
    assert ev is not None
    assert ev.source_id == "CR-904"
    assert ev.metadata["status"] == "Approved"


# -----------------------------------------------------------------------------
# GITHUB ADAPTER TESTS
# -----------------------------------------------------------------------------
def test_github_auth_and_search_query_building():
    """Verify GitHub Search API query generation with repo scoping and auth headers."""
    cfg = GitHubConfig(
        base_url="https://api.github.com",
        api_token="ghp_test_token_12345",
        repos=["octocat/Hello-World", "octocat/Spoon-Knife"],
    )
    provider = GitHubEvidenceProvider(cfg)

    headers = provider._build_headers()
    assert headers["Authorization"] == "Bearer ghp_test_token_12345"

    q_str = provider._build_search_query("memory leak crash", filters={"state": "open", "type": "pr"})
    assert "memory leak crash" in q_str
    assert "repo:octocat/Hello-World repo:octocat/Spoon-Knife" in q_str
    assert "state:open" in q_str
    assert "type:pr" in q_str


def test_github_search_and_evidence_normalization():
    """Verify GitHub Search API mock parsing, PR vs Issue identification, and Evidence normalization."""
    mock_payload = {
        "total_count": 1,
        "items": [
            {
                "number": 42,
                "title": "Upgrade cache client to support mTLS 1.3",
                "body": "Fixes handshake negotiation timeout under peak traffic.",
                "state": "closed",
                "html_url": "https://github.com/my-org/payment-service/pull/42",
                "repository_url": "https://api.github.com/repos/my-org/payment-service",
                "pull_request": {"url": "https://api.github.com/repos/my-org/payment-service/pulls/42"},
                "user": {"login": "dev-lead"},
                "labels": [{"name": "security"}, {"name": "p0"}],
                "created_at": "2026-10-15T09:00:00Z",
                "updated_at": "2026-10-18T16:00:00Z",
                "comments": 5,
            }
        ],
    }

    def handler(request: httpx.Request):
        if "/search/issues" in str(request.url):
            return httpx.Response(200, json=mock_payload)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    cfg = GitHubConfig(base_url="https://api.github.com")
    provider = GitHubEvidenceProvider(cfg, client=client)

    hits, _ = provider.search("mTLS 1.3 handshake", k=5)
    assert len(hits) == 1
    ev, score = hits[0]

    assert ev.evidence_id == "github:my-org/payment-service#42#c000"
    assert ev.source_id == "my-org/payment-service#42"
    assert ev.source_type == "github"
    assert ev.uri == "https://github.com/my-org/payment-service/pull/42"
    assert ev.metadata["is_pr"] is True
    assert ev.metadata["state"] == "closed"
    assert ev.metadata["author"] == "dev-lead"
    assert "security" in ev.metadata["labels"]
    assert "Type: Pull Request #42" in ev.content
    assert ev.start_offset == 0
    assert ev.end_offset == len(ev.content.encode("utf-8"))
    assert len(ev.content_hash) == 64


def test_github_rate_limit_handling():
    """Verify GitHub rate limit response (HTTP 403 with X-RateLimit-Remaining: 0) backoff and recovery."""
    attempts = 0

    def handler(request: httpx.Request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                403,
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"},
                json={"message": "API rate limit exceeded"},
            )
        return httpx.Response(
            200,
            json={"items": [{"number": 1, "title": "Resolved Issue", "repository_url": "https://api.github.com/repos/org/repo"}]},
        )

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    cfg = GitHubConfig(base_url="https://api.github.com", max_retries=2)
    provider = GitHubEvidenceProvider(cfg, client=client)

    hits, _ = provider.search("Resolved", k=1)
    assert attempts == 2
    assert len(hits) == 1
    assert hits[0][0].source_id == "org/repo#1"


def test_github_direct_entity_lookup():
    """Verify direct O(1) lookup via owner/repo#number."""
    def handler(request: httpx.Request):
        if "/repos/org/core/issues/100" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "number": 100,
                    "title": "Direct Issue Title",
                    "body": "Direct Issue Body",
                    "state": "open",
                    "html_url": "https://github.com/org/core/issues/100",
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)

    cfg = GitHubConfig(base_url="https://api.github.com")
    provider = GitHubEvidenceProvider(cfg, client=client)

    ev = provider.lookup_entity("org/core#100")
    assert ev is not None
    assert ev.source_id == "org/core#100"
    assert ev.metadata["number"] == 100


# -----------------------------------------------------------------------------
# MULTI-SOURCE FEDERATION TEST (SQLITE + JIRA + GITHUB)
# -----------------------------------------------------------------------------
def test_federated_multi_source_with_real_adapters(tmp_path):
    """
    FEDERATION INTEGRATION:
    Demonstrates FederatedEvidenceProvider simultaneously querying:
      1. SQLite FTS5 (local documentation chunks)
      2. JiraEvidenceProvider (remote tickets)
      3. GitHubEvidenceProvider (remote pull requests)
    and merging all three into a coherent, Reciprocal Rank Fusion result set.
    """
    # 1. SQLite FTS5 Provider
    db_path = tmp_path / "multi_fts.db"
    sqlite_provider = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    sqlite_provider.index_evidence(all_chunks)

    # 2. Jira Provider (Mock Transport)
    jira_payload = {
        "issues": [
            {
                "key": "CR-904",
                "fields": {
                    "summary": "Emergency Redis v7 Upgrade Decision",
                    "description": "CAB unanimously rejected the emergency change request.",
                    "status": {"name": "Rejected"},
                    "issuetype": {"name": "Change Request"},
                    "priority": {"name": "Highest"},
                },
            }
        ]
    }
    jira_client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=jira_payload))
    )
    jira_provider = JiraEvidenceProvider(
        JiraConfig(base_url="https://jira.corp.internal"), client=jira_client
    )

    # 3. GitHub Provider (Mock Transport)
    github_payload = {
        "items": [
            {
                "number": 88,
                "title": "Payment Gateway v2 mTLS requirement enforcement",
                "body": "Enforces TLS handshake on Redis datastore connections.",
                "state": "merged",
                "html_url": "https://github.com/nova/payment-gw/pull/88",
                "repository_url": "https://api.github.com/repos/nova/payment-gw",
                "pull_request": {"url": "..."},
                "user": {"login": "sec-eng"},
            }
        ]
    }
    github_client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=github_payload))
    )
    github_provider = GitHubEvidenceProvider(
        GitHubConfig(base_url="https://api.github.com"), client=github_client
    )

    # Federated Coordinator
    federated = FederatedEvidenceProvider(
        providers=[sqlite_provider, jira_provider, github_provider],
        provider_weights={"sqlite_fts5": 1.0, "jira": 1.0, "github": 1.0},
    )

    hits, latency_ms = federated.search("Redis mTLS requirements CR-904", k=10)
    assert len(hits) > 0

    sources = {ev.source_type for ev, _ in hits}
    assert "document" in sources
    assert "jira" in sources
    assert "github" in sources

    # Check evidence ID structure across sources
    doc_ids = [ev.evidence_id for ev, _ in hits if ev.source_type == "document"]
    jira_ids = [ev.evidence_id for ev, _ in hits if ev.source_type == "jira"]
    gh_ids = [ev.evidence_id for ev, _ in hits if ev.source_type == "github"]

    assert any("DOC-NOVA-" in d for d in doc_ids)
    assert "jira:CR-904#c000" in jira_ids
    assert "github:nova/payment-gw#88#c000" in gh_ids
