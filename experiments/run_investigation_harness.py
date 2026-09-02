"""
ORACLE Brick 3.3: Live Investigation Evaluation Harness Runner
Runs the full 8-scenario benchmark across all operational archetypes:
  1. Direct Investigation
  2. Multi-Hop Investigation
  3. Contradiction / Reconciliation
  4. Temporal Invalidation
  5. Reference Resolution
  6. Distractor-Heavy
  7. Unanswerable Question
  8. Insufficient Evidence

Produces machine-readable JSON and human-readable scorecards.
Zero LLM involvement in evaluation.
"""

import json
import os
import sys
import time
from pathlib import Path
import psutil

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.evidence.parser import MarkdownEvidenceParser
from backend.inference.ollama_provider import OllamaProvider
from backend.investigation.engine import InvestigationEngine
from backend.investigation.evaluator import InvestigationEvaluator
from backend.investigation.models import InvestigationBudget
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

BENCHMARK_SPEC_PATH = project_root / "tests" / "test_data" / "nova_investigation_benchmark_v1.json"
CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
STORAGE_DB = project_root / "storage" / "oracle_eval_harness_fts.db"
OUTPUT_JSON_PATH = project_root / "experiments" / "investigation_eval_harness_results.json"


def run_harness():
    print("=" * 105, flush=True)
    print("           ORACLE BRICK 3.3: SYSTEMATIC INVESTIGATION EVALUATION HARNESS", flush=True)
    print("           Deterministic Ground-Truth Auditing | 8 Operational Archetypes", flush=True)
    print("=" * 105, flush=True)

    # 1. Load Corpus into SQLite FTS5 Index
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))

    if STORAGE_DB.exists():
        STORAGE_DB.unlink()
    retriever = SQLiteFTS5Retriever(db_path=STORAGE_DB)
    retriever.index_evidence(all_chunks)
    print(f"[+] Indexed {len(all_chunks)} chunks into temporary evaluation database.", flush=True)

    # 2. Initialize LLM Provider & Investigation Engine
    provider = OllamaProvider()
    assert provider.health_check(), "Ollama is not running!"
    print(f"[+] Provider connected: {provider.default_model} (Local CPU)", flush=True)

    budget = InvestigationBudget(
        max_hops=3,
        max_llm_calls=3,
        max_queries=6,
        max_total_chunks=15,
        max_wall_time_seconds=30.0,
    )

    engine = InvestigationEngine(
        retriever=retriever,
        llm_provider=provider,
        budget=budget,
    )
    evaluator = InvestigationEvaluator()

    # 3. Load Benchmark Specification
    benchmark_data = json.loads(BENCHMARK_SPEC_PATH.read_text(encoding="utf-8"))
    scenarios = benchmark_data["scenarios"]
    print(f"[+] Loaded {len(scenarios)} evaluation scenarios across 8 archetypes.\n", flush=True)

    results = []
    process = psutil.Process(os.getpid())

    total_start = time.perf_counter()

    for idx, sc in enumerate(scenarios, 1):
        sc_id = sc["scenario_id"]
        arch = sc["archetype"]
        obj = sc["objective"]

        print(f"[{idx}/{len(scenarios)}] [{sc_id}] ({arch}): '{obj[:65]}...'", flush=True)

        mem_before = process.memory_info().rss / (1024 * 1024)
        t0 = time.perf_counter()

        package = engine.investigate(obj)

        elapsed_s = time.perf_counter() - t0
        mem_after = process.memory_info().rss / (1024 * 1024)

        # Evaluate deterministically
        eval_res = evaluator.evaluate_scenario(
            scenario_spec=sc,
            package=package,
            elapsed_seconds=elapsed_s,
            ram_rss_mb=mem_after,
        )

        results.append(eval_res.model_dump())

        print(f"    - Failure Class:       {eval_res.failure_class.value}", flush=True)
        print(f"    - Recall:              {eval_res.required_evidence_recall:.1f}% ({len(eval_res.required_evidence_found)}/{len(sc['required_evidence_ids'])})", flush=True)
        if eval_res.contradictory_evidence_discovered is not None:
            print(f"    - Contradiction Disc:  {eval_res.contradictory_evidence_discovered:.1f}%", flush=True)
        print(f"    - Noise Ratio:         {eval_res.irrelevant_evidence_ratio:.1f}%", flush=True)
        print(f"    - Controller Verified: {eval_res.controller_verified} (Premature: {eval_res.premature_termination})", flush=True)
        print(f"    - Termination:         {eval_res.termination_reason}", flush=True)
        print(f"    - Hops / LLM Calls:    {eval_res.hops_used} / {eval_res.llm_calls_used}", flush=True)
        print(f"    - Wall Time / RAM:     {eval_res.elapsed_seconds:.2f}s / {eval_res.ram_rss_mb:.1f} MB", flush=True)
        print(f"    - Diagnosis:           {eval_res.failure_diagnosis}\n", flush=True)

    total_time = time.perf_counter() - total_start

    # 4. Save Machine-Readable JSON
    harness_output = {
        "benchmark_metadata": {
            "name": benchmark_data["benchmark_name"],
            "version": benchmark_data["version"],
            "brick": benchmark_data["brick"],
            "total_scenarios": len(scenarios),
            "total_wall_clock_seconds": round(total_time, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "aggregate_metrics": compute_aggregates(results),
        "scenario_results": results,
    }

    OUTPUT_JSON_PATH.write_text(json.dumps(harness_output, indent=2), encoding="utf-8")
    print(f"[+] Machine-readable results saved to: {OUTPUT_JSON_PATH}\n", flush=True)

    # 5. Render Scorecard Table
    print_scorecard(harness_output)


def compute_aggregates(results: list) -> dict:
    n = len(results)
    if n == 0:
        return {}

    avg_recall = sum(r["required_evidence_recall"] for r in results) / n
    contra_cases = [r for r in results if r["contradictory_evidence_discovered"] is not None]
    avg_contra = sum(r["contradictory_evidence_discovered"] for r in contra_cases) / len(contra_cases) if contra_cases else None
    avg_noise = sum(r["irrelevant_evidence_ratio"] for r in results) / n

    verified_success_count = sum(1 for r in results if r["successful_termination"])
    premature_count = sum(1 for r in results if r["premature_termination"])
    unsupported_count = sum(1 for r in results if r["unsupported_claim"])
    max_hop_count = sum(1 for r in results if r["max_hop_termination"])
    stagnation_count = sum(1 for r in results if r["stagnation_detected"])

    taxonomy_counts = {}
    for r in results:
        fc = r["failure_class"]
        taxonomy_counts[fc] = taxonomy_counts.get(fc, 0) + 1

    return {
        "mean_evidence_recall_pct": round(avg_recall, 1),
        "mean_contradiction_recall_pct": round(avg_contra, 1) if avg_contra is not None else None,
        "mean_irrelevant_noise_ratio_pct": round(avg_noise, 1),
        "verified_success_rate_pct": round((verified_success_count / n) * 100.0, 1),
        "premature_termination_rate_pct": round((premature_count / n) * 100.0, 1),
        "unsupported_claim_rate_pct": round((unsupported_count / n) * 100.0, 1),
        "max_hop_termination_rate_pct": round((max_hop_count / n) * 100.0, 1),
        "stagnation_termination_rate_pct": round((stagnation_count / n) * 100.0, 1),
        "total_llm_calls": sum(r["llm_calls_used"] for r in results),
        "mean_scenario_latency_seconds": round(sum(r["elapsed_seconds"] for r in results) / n, 2),
        "failure_taxonomy_distribution": taxonomy_counts,
    }


def print_scorecard(harness_output: dict):
    agg = harness_output["aggregate_metrics"]
    res = harness_output["scenario_results"]

    print("=" * 115)
    print("                               BRICK 3.3 SYSTEMATIC BENCHMARK SCORECARD")
    print("=" * 115)
    header = f"{'Scenario ID':<15} | {'Archetype':<24} | {'Recall':<8} | {'Verified':<8} | {'Premature':<9} | {'Time (s)':<8} | {'Failure Class'}"
    print(header)
    print("-" * 115)
    for r in res:
        row = (
            f"{r['scenario_id']:<15} | "
            f"{r['archetype'][:24]:<24} | "
            f"{r['required_evidence_recall']:>6.1f}% | "
            f"{str(r['controller_verified']):<8} | "
            f"{str(r['premature_termination']):<9} | "
            f"{r['elapsed_seconds']:>6.2f}s | "
            f"{r['failure_class']}"
        )
        print(row)
    print("=" * 115)

    print("\n--- AGGREGATE EVALUATION METRICS ---")
    print(f"Mean Required Evidence Recall:       {agg['mean_evidence_recall_pct']}%")
    if agg['mean_contradiction_recall_pct'] is not None:
        print(f"Mean Contradiction Discovery:        {agg['mean_contradiction_recall_pct']}%")
    print(f"Mean Irrelevant Noise Ratio:         {agg['mean_irrelevant_noise_ratio_pct']}%")
    print(f"Verified Success Rate:               {agg['verified_success_rate_pct']}%")
    print(f"Premature Termination Rate:          {agg['premature_termination_rate_pct']}% (Target: 0.0%)")
    print(f"Unsupported Claim Rate:              {agg['unsupported_claim_rate_pct']}% (Target: 0.0%)")
    print(f"Max-Hop Termination Rate:            {agg['max_hop_termination_rate_pct']}%")
    print(f"Stagnation Termination Rate:         {agg['stagnation_termination_rate_pct']}%")
    print(f"Mean Scenario Latency:               {agg['mean_scenario_latency_seconds']}s")
    print(f"Total LLM Calls:                     {agg['total_llm_calls']}")
    print("\n--- FAILURE TAXONOMY DISTRIBUTION ---")
    for k, v in agg['failure_taxonomy_distribution'].items():
        print(f"  - {k:<30}: {v} cases ({round((v/len(res))*100, 1)}%)")
    print("=" * 115)


if __name__ == "__main__":
    run_harness()
