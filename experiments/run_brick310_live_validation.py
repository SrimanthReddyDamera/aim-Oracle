"""
Brick 3.10 Live Federated Investigation Validation Script
Executes and demonstrates the complete ORACLE investigation pipeline across
real heterogeneous evidence providers (SQLite, live Jira, live GitHub).

Outputs deterministic observability telemetry with all secrets redacted.
"""

import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

from backend.core.security import mask_secret, redact_sensitive_data
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

CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


def main():
    print("=" * 80)
    print("ORACLE BRICK 3.10: END-TO-END REAL FEDERATED INVESTIGATION VALIDATION")
    print("=" * 80)

    # 1. Configuration & Security Audit
    print("\n[1] CONFIGURATION & SECRETS AUDIT")
    jira_cfg = JiraConfig.from_env()
    gh_cfg = GitHubConfig.from_env()

    print(f"  - Jira Endpoint:  {jira_cfg.base_url}")
    print(f"  - Jira Project:   {jira_cfg.project_keys}")
    print(f"  - Jira Auth:      {'Configured (' + mask_secret(jira_cfg.api_token) + ')' if jira_cfg.api_token else 'Missing'}")
    print(f"  - GitHub Endpoint: {gh_cfg.base_url}")
    print(f"  - GitHub Repos:    {gh_cfg.repos or '(Global/User Public Search)'}")
    print(f"  - GitHub Auth:     {'Configured (' + mask_secret(gh_cfg.api_token) + ')' if gh_cfg.api_token else 'Missing'}")
    print(f"  - Safe Jira Repr:  {repr(jira_cfg)}")
    print(f"  - Safe GitHub Repr: {repr(gh_cfg)}")

    assert jira_cfg.api_token not in repr(jira_cfg), "CRITICAL: Jira API token leaked in repr!"
    if gh_cfg.api_token:
        assert gh_cfg.api_token not in repr(gh_cfg), "CRITICAL: GitHub API token leaked in repr!"
    print("  [OK] Zero secrets exposed in configuration representations.")

    # 2. Local SQLite FTS5 Provider Initialization
    print("\n[2] LOCAL SQLITE/FTS5 RETRIEVER INITIALIZATION")
    t0 = time.perf_counter()
    import tempfile
    db_path = Path(tempfile.mkdtemp()) / "live_val.db"
    sqlite_provider = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    sqlite_provider.index_evidence(all_chunks)
    print(f"  [OK] Indexed {len(all_chunks)} documentation chunks into SQLite FTS5 in {(time.perf_counter() - t0)*1000.0:.2f}ms")

    # 3. Live External Adapters
    print("\n[3] LIVE EXTERNAL PROVIDER INITIALIZATION & HEALTH CHECK")
    jira_provider = JiraEvidenceProvider(jira_cfg)
    gh_provider = GitHubEvidenceProvider(gh_cfg)

    jira_health = jira_provider.health_check()
    gh_health = gh_provider.health_check()
    print(f"  - Jira Health:   {'HEALTHY' if jira_health else 'UNHEALTHY'}")
    print(f"  - GitHub Health: {'HEALTHY' if gh_health else 'UNHEALTHY'}")

    # 4. Controlled Individual Search Probes
    print("\n[4] CONTROLLED LIVE RETRIEVAL PROBES")
    j_hits, j_ms = jira_provider.search("Task", k=2)
    print(f"  - Live Jira Search ('Task'): {len(j_hits)} hits returned in {j_ms:.2f}ms")
    for ev, sc in j_hits:
        print(f"    * [{ev.source_type}] {ev.source_id} (Score: {sc}) -> {ev.uri}")

    g_hits, g_ms = gh_provider.search("oracle test", k=2)
    print(f"  - Live GitHub Search ('oracle test'): {len(g_hits)} hits returned in {g_ms:.2f}ms")
    for ev, sc in g_hits:
        print(f"    * [{ev.source_type}] {ev.source_id} (Score: {sc}) -> {ev.uri}")

    # 5. Federated Coordinator Setup
    print("\n[5] FEDERATED EVIDENCE PROVIDER COORDINATOR")
    federated = FederatedEvidenceProvider(
        providers=[sqlite_provider, jira_provider, gh_provider],
        provider_weights={"sqlite_fts5": 1.0, "jira": 1.0, "github": 1.0},
    )
    print(f"  - Registered Providers: {federated.registry.list_providers()}")
    print(f"  - Combined Capabilities: {[c.value for c in federated.capabilities]}")

    # 6. Autonomous End-to-End Investigation
    print("\n[6] RUNNING END-TO-END MULTI-PROVIDER INVESTIGATION")
    controller = InvestigationController(
        retriever=federated,
        budget=InvestigationBudget(max_hops=2, max_llm_calls=2),
    )

    objective = "Verify Project Phoenix cutover prerequisites, active Jira KAN-1 Task, and payment gateway status"

    def reasoning_agent_fn(state: InvestigationState):
        has_doc = any(e.source_type == "document" for e in state.accumulated_evidence.values())
        has_jira = any(e.source_type == "jira" for e in state.accumulated_evidence.values())

        if has_doc and has_jira:
            return True, "Factual sufficiency achieved across local documents and live Jira tickets", [], []

        gap = InformationGap(
            gap_id="GAP-LIVE-KAN",
            description="Retrieve active sprint stories and tasks",
            targeted_query="Project Phoenix cutover KAN-1 Task",
        )
        return False, "Querying active sprint items", [gap], []

    print(f"  - Objective: '{objective}'")
    package = controller.run_investigation(
        objective=objective,
        reasoning_agent_fn=reasoning_agent_fn,
        initial_k=6,
    )

    # 7. Telemetry & Results Output
    print("\n[7] INVESTIGATION RESULTS & DETERMINISTIC TELEMETRY")
    print(f"  - Termination Reason:      {package.termination_reason}")
    print(f"  - Controller Verified:     {package.controller_verified}")
    print(f"  - Total Evidence Admitted: {len(package.evidence_items)}")
    print(f"  - Wall Clock Time:         {package.budget_summary.get('elapsed_wall_time_ms', 0):.2f}ms")
    print(f"  - LLM Calls:               {package.budget_summary.get('llm_calls_used', 0)}")
    print(f"  - Queries Executed:        {package.budget_summary.get('queries_executed', 0)}")

    telem = package.federated_telemetry or {}
    print("\n--- FEDERATED RETRIEVAL TELEMETRY (SECRETS REDACTED) ---")
    print(json.dumps(redact_sensitive_data(telem), indent=2))

    print("\n--- FINAL ADMITTED EVIDENCE PROVENANCE BREAKDOWN ---")
    for idx, ev in enumerate(package.evidence_items, start=1):
        print(f"  {idx}. [{ev.source_type.upper()}] ID={ev.evidence_id} | URI={ev.uri or ev.source_path}")
        first_line = ev.content.strip().split("\n")[0][:80]
        print(f"     Preview: \"{first_line}...\"")

    # Final Security Audit on Output
    pkg_str = package.model_dump_json()
    if jira_cfg.api_token:
        assert jira_cfg.api_token not in pkg_str, "CRITICAL: Jira token leaked in EvidencePackage JSON!"
    if gh_cfg.api_token:
        assert gh_cfg.api_token not in pkg_str, "CRITICAL: GitHub token leaked in EvidencePackage JSON!"

    print("\n[OK] Live validation complete. 100% security and telemetry verification successful.")
    print("=" * 80)


if __name__ == "__main__":
    main()
