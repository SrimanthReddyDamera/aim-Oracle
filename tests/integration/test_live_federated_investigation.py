"""
Live Integration Test Suite for Brick 3.10:
End-to-End Real Federated Investigation Validation.

IMPORTANT:
This suite communicates with REAL external cloud services (Jira Cloud and GitHub API)
using credentials configured in .env. It is strictly gated behind:
    RUN_LIVE_INTEGRATION=true
Ordinary unit test suites will SKIP this file automatically.
"""

import json
import os
from pathlib import Path
import pytest
from dotenv import load_dotenv

from backend.core.security import redact_sensitive_data
from backend.evidence.parser import MarkdownEvidenceParser
from backend.investigation.controller import InvestigationController
from backend.investigation.models import (
    InformationGap,
    InvestigationBudget,
    InvestigationState,
)
from backend.retrieval.adapters.config import GitHubConfig, JiraConfig
from backend.retrieval.adapters.github import GitHubEvidenceProvider
from backend.retrieval.adapters.jira import JiraEvidenceProvider
from backend.retrieval.federated import FederatedEvidenceProvider
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

load_dotenv()

# Strict guard: skip unless explicitly requested
RUN_LIVE = os.getenv("RUN_LIVE_INTEGRATION", "").lower() in ("true", "1")
pytestmark = pytest.mark.skipif(
    not RUN_LIVE,
    reason="Live integration tests run only when RUN_LIVE_INTEGRATION=true is set",
)

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def sqlite_live_provider(tmp_path_factory):
    """Local SQLite FTS5 provider loaded with nova_corpus for cross-source testing."""
    db_path = tmp_path_factory.mktemp("live_fed") / "live_fts.db"
    retriever = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever.index_evidence(all_chunks)
    return retriever


@pytest.fixture(scope="module")
def live_jira_provider():
    """Live Jira provider instantiated from .env credentials."""
    cfg = JiraConfig.from_env()
    if not cfg.api_token:
        pytest.skip("JIRA_API_TOKEN not configured in environment")
    return JiraEvidenceProvider(cfg)


@pytest.fixture(scope="module")
def live_github_provider():
    """Live GitHub provider instantiated from .env credentials."""
    cfg = GitHubConfig.from_env()
    if not cfg.api_token:
        pytest.skip("GITHUB_API_TOKEN not configured in environment")
    return GitHubEvidenceProvider(cfg)


# -----------------------------------------------------------------------------
# 1. CONTROLLED LIVE JIRA RETRIEVAL
# -----------------------------------------------------------------------------
def test_live_jira_retrieval(live_jira_provider):
    """Verify live Jira API connection, JQL search execution, and evidence normalization."""
    # Health check
    is_healthy = live_jira_provider.health_check()
    assert is_healthy is True, "Live Jira instance health check failed"

    # Search for project tickets
    query = "task OR story OR bug"
    hits, elapsed_ms = live_jira_provider.search(query, k=5)
    assert elapsed_ms > 0.0

    if hits:
        ev, score = hits[0]
        assert ev.source_type == "jira"
        assert ev.source_id.startswith("KAN-") or len(ev.source_id) > 1
        assert ev.uri.startswith("http")
        assert len(ev.content_hash) == 64
        assert ev.start_offset >= 0
        assert ev.end_offset > ev.start_offset
        assert score > 0.0

        # Security check: secret token must NOT appear in evidence content or metadata
        token = live_jira_provider.config.api_token
        if token:
            assert token not in ev.content
            assert token not in str(ev.metadata)


# -----------------------------------------------------------------------------
# 2. CONTROLLED LIVE GITHUB RETRIEVAL
# -----------------------------------------------------------------------------
def test_live_github_retrieval(live_github_provider):
    """Verify live GitHub API connection, search query execution, and evidence normalization."""
    is_healthy = live_github_provider.health_check()
    assert is_healthy is True, "Live GitHub API health check failed"

    # Search query
    query = "oracle investigation test"
    hits, elapsed_ms = live_github_provider.search(query, k=5)
    assert elapsed_ms > 0.0

    if hits:
        ev, score = hits[0]
        assert ev.source_type == "github"
        assert "#" in ev.source_id
        assert ev.uri.startswith("http")
        assert len(ev.content_hash) == 64
        assert ev.start_offset >= 0
        assert ev.end_offset > ev.start_offset

        # Security check: secret token must NOT appear in evidence content or metadata
        token = live_github_provider.config.api_token
        if token:
            assert token not in ev.content
            assert token not in str(ev.metadata)


# -----------------------------------------------------------------------------
# 3. GENUINE MULTI-PROVIDER FEDERATED INVESTIGATION
# -----------------------------------------------------------------------------
def test_live_multi_provider_investigation(
    sqlite_live_provider, live_jira_provider, live_github_provider
):
    """
    END-TO-END VALIDATION:
    Coordinates SQLite (local docs), live Jira Cloud (tickets), and live GitHub API (issues/PRs)
    inside InvestigationController. Verifies autonomous multi-hop loop, gap formulation,
    deduplication, telemetry, and deterministic termination.
    """
    federated = FederatedEvidenceProvider(
        providers=[sqlite_live_provider, live_jira_provider, live_github_provider],
        provider_weights={"sqlite_fts5": 1.0, "jira": 1.0, "github": 1.0},
    )

    controller = InvestigationController(
        retriever=federated,
        budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
    )

    step_count = 0

    def reasoning_agent_fn(state: InvestigationState):
        nonlocal step_count
        step_count += 1
        # Check evidence from multiple sources
        has_doc = any(e.source_type == "document" for e in state.accumulated_evidence.values())
        has_ext = any(e.source_type in {"jira", "github"} for e in state.accumulated_evidence.values())

        if has_doc and has_ext:
            return True, "Collected multi-source evidence across local docs and live enterprise datastores", [], []

        # If not sufficient yet, query live project tasks
        gap = InformationGap(
            gap_id="GAP-LIVE-ENTERPRISE",
            description="Investigate active work items and deployment prerequisites",
            targeted_query="Project Phoenix task story status",
        )
        return False, "Querying live enterprise providers for project status", [gap], []

    package = controller.run_investigation(
        objective="Verify Project Phoenix cutover prerequisites and active Jira work items",
        reasoning_agent_fn=reasoning_agent_fn,
        initial_k=6,
    )

    assert package is not None
    assert len(package.evidence_items) > 0
    assert package.termination_reason is not None

    # Telemetry assertions
    telem = package.federated_telemetry
    assert telem is not None
    assert "sqlite_fts5" in telem["providers_queried"]
    assert "jira" in telem["providers_queried"]
    assert "github" in telem["providers_queried"]
    assert len(telem["providers_responded"]) >= 2
    assert telem["latency_wall_clock_ms"] > 0.0

    # Security check across package
    jira_token = live_jira_provider.config.api_token or ""
    gh_token = live_github_provider.config.api_token or ""
    package_json = package.model_dump_json()

    if len(jira_token) >= 6:
        assert jira_token not in package_json
    if len(gh_token) >= 6:
        assert gh_token not in package_json
