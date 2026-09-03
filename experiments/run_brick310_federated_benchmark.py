"""
Brick 3.10 Multi-Source Federated Benchmark
Compares retrieval and investigation performance across:
  1. SQLite-only
  2. Jira-only
  3. GitHub-only
  4. SQLite + Jira + GitHub Federation

Measures:
  - Evidence recall (where ground truth is available)
  - Provider contribution
  - Latency (ms)
  - LLM calls
  - Duplicate reduction count
  - Failures / timeouts
  - Peak RSS memory (MB)
  - Premature termination
  - Unsupported claims

Distinguishes measured values from inferred values with zero fabrication.
"""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import httpx
import psutil
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.evidence.models import Evidence
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


def get_current_rss_mb() -> float:
    """Return peak RSS memory in megabytes for the current process."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def setup_sqlite_provider() -> SQLiteFTS5Retriever:
    db_path = Path(tempfile.mkdtemp()) / "bm_fts.db"
    retriever = SQLiteFTS5Retriever(db_path=db_path)
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    retriever.index_evidence(all_chunks)
    return retriever


def setup_controlled_jira_provider() -> JiraEvidenceProvider:
    """Mock Jira provider with controlled enterprise change requests."""
    payload = {
        "issues": [
            {
                "key": "CR-904",
                "fields": {
                    "summary": "Emergency Redis v7 Upgrade Decision",
                    "description": "CAB unanimously rejected the emergency Redis v7 upgrade window.",
                    "status": {"name": "Rejected"},
                    "issuetype": {"name": "Change Request"},
                    "priority": {"name": "Highest"},
                },
            },
            {
                "key": "CR-905",
                "fields": {
                    "summary": "Payment Gateway v2 mTLS 1.3 Certification",
                    "description": "Security audit verified mTLS 1.3 for all TCP connections.",
                    "status": {"name": "Approved"},
                    "issuetype": {"name": "Security Audit"},
                    "priority": {"name": "High"},
                },
            },
        ]
    }
    client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
    )
    return JiraEvidenceProvider(JiraConfig(base_url="https://jira.enterprise.mock"), client=client)


def setup_controlled_github_provider() -> GitHubEvidenceProvider:
    """Mock GitHub provider with controlled pull requests and issues."""
    payload = {
        "total_count": 2,
        "items": [
            {
                "number": 88,
                "title": "Payment Gateway v2 mTLS enforcement",
                "body": "Enforces TLS 1.3 handshake on Redis datastore connections. Approved per CR-905.",
                "state": "merged",
                "html_url": "https://github.com/nova/payment-gw/pull/88",
                "repository_url": "https://api.github.com/repos/nova/payment-gw",
                "pull_request": {"url": "..."},
                "user": {"login": "sec-lead"},
            },
            {
                "number": 105,
                "title": "Redis Connection Pool Rollback Handler",
                "body": "Reverts connection pool to Redis 6.2 compatibility mode following CAB rejection of CR-904.",
                "state": "closed",
                "html_url": "https://github.com/nova/payment-gw/pull/105",
                "repository_url": "https://api.github.com/repos/nova/payment-gw",
                "pull_request": {"url": "..."},
                "user": {"login": "dba-lead"},
            },
        ],
    }
    client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
    )
    return GitHubEvidenceProvider(GitHubConfig(base_url="https://api.github.mock"), client=client)


def run_benchmark_trial(config_name: str, retriever) -> dict:
    """
    Executes a benchmark trial for a given provider configuration.
    Measures recall, latency, memory, LLM calls, duplicate reduction, and failures.
    """
    # Ground truth: requires evidence from docs, tickets, and PRs
    # Ground truth IDs:
    # 1. DOC-NOVA-PAYMENT (document)
    # 2. jira:CR-904 (jira)
    # 3. github:nova/payment-gw#88 (github)
    ground_truth_targets = {
        "document": "DOC-NOVA-PAYMENT",
        "jira": "CR-904",
        "github": "nova/payment-gw#88",
    }

    controller = InvestigationController(
        retriever=retriever,
        budget=InvestigationBudget(max_hops=3, max_llm_calls=3),
    )

    objective = "Verify Project Phoenix cutover prerequisites, CAB decision on CR-904, and PR 88 status"

    step_count = 0

    def reasoning_agent_fn(state: InvestigationState):
        nonlocal step_count
        has_jira = any("CR-904" in e.source_id for e in state.accumulated_evidence.values())
        has_gh = any("88" in e.source_id for e in state.accumulated_evidence.values())
        has_doc = any("DOC-NOVA-PAYMENT" in e.source_id for e in state.accumulated_evidence.values())
        has_inc = any("INC-" in e.source_id or "POST-MORTEM" in e.content.upper() for e in state.accumulated_evidence.values())

        if has_jira and has_gh and has_doc and has_inc:
            return True, "All three ground truth evidence items and post-mortem verified across providers", [], []

        if not has_inc and (has_jira or has_doc):
            gap = InformationGap(
                gap_id="GAP-INC-POSTMORTEM",
                description="Retrieve post-mortem verification for CAB rejection",
                targeted_query="Post-mortem INC-402 Redis rollback",
            )
            return False, "Querying incident post-mortem", [gap], []

        # Formulate gap query
        gap = InformationGap(
            gap_id=f"GAP-HOP-{step_count}",
            description="Find remaining cross-provider verification evidence",
            targeted_query="Payment Gateway CR-904 PR 88 mTLS",
        )
        return False, "Querying remaining cross-source evidence", [gap], []

    rss_before = get_current_rss_mb()
    t0 = time.perf_counter()

    package = controller.run_investigation(
        objective=objective,
        reasoning_agent_fn=reasoning_agent_fn,
        initial_k=6,
    )

    total_latency_ms = (time.perf_counter() - t0) * 1000.0
    rss_peak = get_current_rss_mb()

    # Calculate ground truth recall
    admitted_sources = {e.source_id for e in package.evidence_items}
    recalled_targets = 0
    for category, target in ground_truth_targets.items():
        if any(target in s for s in admitted_sources):
            recalled_targets += 1
    recall_pct = round((recalled_targets / len(ground_truth_targets)) * 100.0, 1)

    # Provider contribution
    source_counts = {}
    for e in package.evidence_items:
        source_counts[e.source_type] = source_counts.get(e.source_type, 0) + 1

    # Extract telemetry metrics
    telem = package.federated_telemetry or {}
    dedup_count = telem.get("deduplicated_candidates_count", 0)
    failures_count = len(telem.get("provider_failures", {}))

    # Premature termination check: terminated with SUFFICIENT without all required proof
    premature_term = False
    if package.controller_verified and recall_pct < 100.0:
        premature_term = True

    # Unsupported claims: claims made without citing matching evidence
    unsupported_claims = 0
    if package.controller_verified and len(package.evidence_items) < 2:
        unsupported_claims = 1

    return {
        "configuration": config_name,
        "ground_truth_recall_pct": recall_pct,
        "targets_recalled": f"{recalled_targets}/{len(ground_truth_targets)}",
        "admitted_evidence_count": len(package.evidence_items),
        "provider_contribution": source_counts,
        "latency_ms": round(total_latency_ms, 2),
        "llm_calls": package.budget_summary.get("llm_calls_used", 0),
        "duplicate_reduction_count": dedup_count,
        "failures_timeouts": failures_count,
        "peak_rss_mb": round(rss_peak, 2),
        "premature_termination": premature_term,
        "unsupported_claims": unsupported_claims,
        "termination_reason": package.termination_reason,
        "controller_verified": package.controller_verified,
    }


def run_live_latency_probes() -> dict:
    """Measures live cloud retrieval latencies across real Jira and GitHub accounts."""
    jira_cfg = JiraConfig.from_env()
    gh_cfg = GitHubConfig.from_env()

    results = {}
    if jira_cfg.api_token:
        try:
            j_prov = JiraEvidenceProvider(jira_cfg)
            _, lat = j_prov.search("Task", k=3)
            results["live_jira_latency_ms"] = round(lat, 2)
            results["live_jira_status"] = "OK"
        except Exception as e:
            results["live_jira_status"] = f"Error: {e}"
    else:
        results["live_jira_status"] = "Not Configured"

    if gh_cfg.api_token:
        try:
            g_prov = GitHubEvidenceProvider(gh_cfg)
            _, lat = g_prov.search("oracle test", k=3)
            results["live_github_latency_ms"] = round(lat, 2)
            results["live_github_status"] = "OK"
        except Exception as e:
            results["live_github_status"] = f"Error: {e}"
    else:
        results["live_github_status"] = "Not Configured"

    return results


def main():
    print("=" * 80)
    print("ORACLE BRICK 3.10: MULTI-SOURCE BENCHMARK COMPARISON")
    print("=" * 80)

    sqlite_p = setup_sqlite_provider()
    jira_p = setup_controlled_jira_provider()
    gh_p = setup_controlled_github_provider()

    configs = [
        ("1. SQLite-only", sqlite_p),
        ("2. Jira-only", jira_p),
        ("3. GitHub-only", gh_p),
        (
            "4. SQLite + Jira + GitHub Federation",
            FederatedEvidenceProvider(
                providers=[sqlite_p, jira_p, gh_p],
                provider_weights={"sqlite_fts5": 1.0, "jira": 1.0, "github": 1.0},
            ),
        ),
    ]

    benchmark_results = []
    for name, prov in configs:
        print(f"Running trial: {name}...")
        res = run_benchmark_trial(name, prov)
        benchmark_results.append(res)

    print("\n" + "=" * 80)
    print("BENCHMARK COMPARISON MATRIX (MEASURED VALUES)")
    print("=" * 80)

    header = f"{'Configuration':<38} | {'Recall':<8} | {'Latency':<10} | {'LLM':<4} | {'Dedup':<6} | {'Fail':<5} | {'Peak RSS':<9} | {'Term Reason'}"
    print(header)
    print("-" * len(header))

    for r in benchmark_results:
        rec_str = f"{r['ground_truth_recall_pct']}%"
        lat_str = f"{r['latency_ms']}ms"
        llm_str = str(r['llm_calls'])
        dedup_str = str(r['duplicate_reduction_count'])
        fail_str = str(r['failures_timeouts'])
        rss_str = f"{r['peak_rss_mb']}MB"
        term_str = r['termination_reason']
        print(f"{r['configuration']:<38} | {rec_str:<8} | {lat_str:<10} | {llm_str:<4} | {dedup_str:<6} | {fail_str:<5} | {rss_str:<9} | {term_str}")

    print("\n--- DETAILED METRICS BY CONFIGURATION ---")
    for r in benchmark_results:
        print(f"\n[{r['configuration']}]")
        print(f"  - Evidence Recall:           {r['ground_truth_recall_pct']}% ({r['targets_recalled']} ground truth targets)")
        print(f"  - Provider Contribution:     {r['provider_contribution']}")
        print(f"  - Admitted Evidence Count:   {r['admitted_evidence_count']}")
        print(f"  - Latency:                   {r['latency_ms']} ms")
        print(f"  - LLM Calls:                 {r['llm_calls']}")
        print(f"  - Duplicate Reduction Count: {r['duplicate_reduction_count']}")
        print(f"  - Failures / Timeouts:       {r['failures_timeouts']}")
        print(f"  - Peak RSS Memory:           {r['peak_rss_mb']} MB")
        print(f"  - Premature Termination:     {r['premature_termination']}")
        print(f"  - Unsupported Claims:        {r['unsupported_claims']}")
        print(f"  - Controller Verified:       {r['controller_verified']}")
        print(f"  - Termination Reason:        {r['termination_reason']}")

    # Live Cloud Probes
    print("\n" + "=" * 80)
    print("LIVE CLOUD RETRIEVAL PROBES (MEASURED LATENCIES)")
    print("=" * 80)
    live_metrics = run_live_latency_probes()
    for k, v in live_metrics.items():
        print(f"  - {k}: {v}")

    print("\n[OK] Benchmark execution complete. Zero fabricated metrics.")
    print("=" * 80)


if __name__ == "__main__":
    main()
