"""
Brick 3.6A: Retrieval Window Controlled Experiment Runner
Tests initial retrieval window k in [4, 6, 8, 10, 12] across the frozen 8-scenario benchmark.
Measures:
  1. Mean required evidence recall
  2. Per-scenario required evidence recall
  3. Distractor / irrelevant evidence ratio
  4. Contradiction discovery
  5. Premature termination rate
  6. Unsupported claim rate
  7. Investigation failure count
  8. Total LLM calls
  9. Total wall-clock latency
  10. Average LLM latency
  11. Peak RSS
  12. Total unique evidence chunks admitted
  13. Required chunks recovered from ranks > 4
  14. Noise drowning ratio
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
import psutil

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.inference.ollama_provider import OllamaProvider
from backend.investigation.engine import InvestigationEngine
from backend.investigation.evaluator import InvestigationEvaluator
from backend.investigation.models import EvidencePackage, InvestigationBudget
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

BENCHMARK_SPEC_PATH = project_root / "tests" / "test_data" / "nova_investigation_benchmark_v1.json"
CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
OUTPUT_JSON_PATH = project_root / "experiments" / "retrieval_window_experiment_results.json"


def run_experiment():
    print("=" * 105, flush=True)
    print("      ORACLE BRICK 3.6A: RETRIEVAL WINDOW CONTROLLED EXPERIMENT (k in [4, 6, 8, 10, 12])", flush=True)
    print("      Testing Initial Candidate Admission Depth | Frozen Benchmark | Local CPU qwen2.5:3b", flush=True)
    print("=" * 105, flush=True)

    # 1. Load Corpus into SQLite FTS5 Index
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))

    retriever = SQLiteFTS5Retriever(":memory:")
    retriever.index_evidence(all_chunks)
    print(f"[+] Indexed {len(all_chunks)} chunks into evaluation database.", flush=True)

    # 2. Initialize LLM Provider & Investigation Engine
    provider = OllamaProvider(default_model="qwen2.5:3b", timeout=120.0)
    assert provider.health_check(), "Ollama is not running!"
    print(f"[+] Provider connected: {provider.default_model} (Local CPU, timeout=120s)", flush=True)

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

    benchmark_data = json.loads(BENCHMARK_SPEC_PATH.read_text(encoding="utf-8"))
    scenarios = benchmark_data["scenarios"]

    k_values = [4, 6, 8, 10, 12]

    # Load existing incremental results if present
    experiment_results: Dict[str, Any] = {}
    if OUTPUT_JSON_PATH.exists():
        try:
            experiment_results = json.loads(OUTPUT_JSON_PATH.read_text(encoding="utf-8"))
            print(f"[+] Found existing results for: {list(experiment_results.keys())}", flush=True)
        except Exception:
            experiment_results = {}

    process = psutil.Process(os.getpid())

    for k in k_values:
        k_key = f"k_{k}"
        if k_key in experiment_results and len(experiment_results[k_key].get("scenario_evaluations", [])) == len(scenarios):
            print(f"\n[+] Skipping already completed k = {k} (Mean Recall: {experiment_results[k_key]['mean_required_evidence_recall']}%)", flush=True)
            continue

        print(f"\n{'='*105}", flush=True)
        print(f"   >>> TESTING CANDIDATE WINDOW: k = {k} <<<", flush=True)
        print(f"{'='*105}", flush=True)

        k_start_time = time.perf_counter()
        scenario_evals = []
        peak_rss_mb = 0.0
        recovered_from_gt4_count = 0
        total_unique_chunks_admitted: set = set()
        llm_latencies: List[float] = []

        for idx, sc in enumerate(scenarios, 1):
            sid = sc["scenario_id"]
            arch = sc["archetype"]
            obj = sc["objective"]
            req_ids = sc["required_evidence_ids"]

            print(f"[{idx}/8] ({sid} | k={k}): '{obj[:60]}...'", flush=True)

            t0 = time.perf_counter()
            mem_now = process.memory_info().rss / (1024 * 1024)
            peak_rss_mb = max(peak_rss_mb, mem_now)

            try:
                # Call controller directly passing initial_k=k without modifying production files
                package = engine.controller.run_investigation(
                    objective=obj,
                    reasoning_agent_fn=engine._call_llm_for_step,
                    initial_k=k,
                )
            except Exception as exc:
                elapsed_s = time.perf_counter() - t0
                print(f"      [TIMEOUT/EXCEPTION]: {exc} -> Graceful timeout package recorded", flush=True)
                init_hits, _ = retriever.search(obj, k=k)
                init_chunks = [h for h, _ in init_hits]
                package = EvidencePackage(
                    objective=obj,
                    termination_reason="BUDGET_EXHAUSTED_TIMEOUT",
                    controller_verified=False,
                    budget_summary={
                        "hops_used": 1,
                        "llm_calls_used": 1,
                        "queries_executed": 1,
                        "zero_yield_queries_count": 0,
                        "total_chunks_collected": len(init_chunks),
                        "elapsed_wall_time_ms": round(elapsed_s * 1000, 2),
                    },
                    evidence_items=init_chunks,
                    graph_edges=[],
                    gap_history=[],
                    investigation_trace=[],
                    gaps=[],
                )

            elapsed_s = time.perf_counter() - t0
            mem_after = process.memory_info().rss / (1024 * 1024)
            peak_rss_mb = max(peak_rss_mb, mem_after)

            # Measure LLM latency for this scenario
            if package.budget_summary.get("llm_calls_used", 0) > 0:
                avg_llm_lat = elapsed_s / package.budget_summary["llm_calls_used"]
                llm_latencies.append(avg_llm_lat)

            # Track admitted chunks
            admitted_eids = {e.evidence_id for e in package.evidence_items}
            total_unique_chunks_admitted.update(admitted_eids)

            # Check if any required chunks were recovered from ranks 5..k
            init_hits, _ = retriever.search(obj, k=k)
            for rank, (h, _) in enumerate(init_hits, 1):
                if rank > 4 and h.evidence_id in req_ids:
                    recovered_from_gt4_count += 1
                    print(f"      [RECOVERY]: {h.evidence_id} recovered at Rank {rank} in Turn 0!", flush=True)

            # Evaluate against frozen benchmark evaluator
            eval_res = evaluator.evaluate_scenario(
                scenario_spec=sc,
                package=package,
                elapsed_seconds=elapsed_s,
                ram_rss_mb=mem_after,
            )
            scenario_evals.append(eval_res.model_dump())

            print(f"      - Failure Class: {eval_res.failure_class.value} | Recall: {eval_res.required_evidence_recall:.1f}% | Time: {elapsed_s:.2f}s", flush=True)

        k_elapsed = time.perf_counter() - k_start_time

        # Compute aggregate metrics for this k
        recalls = [r["required_evidence_recall"] for r in scenario_evals]
        mean_recall = sum(recalls) / len(recalls) if recalls else 0.0

        contra_scores = [r["contradictory_evidence_discovered"] for r in scenario_evals if r["contradictory_evidence_discovered"] is not None]
        mean_contra = sum(contra_scores) / len(contra_scores) if contra_scores else 0.0

        noises = [r["irrelevant_evidence_ratio"] for r in scenario_evals]
        mean_noise = sum(noises) / len(noises) if noises else 0.0

        premature_count = sum(1 for r in scenario_evals if r["premature_termination"])
        unsupported_count = sum(1 for r in scenario_evals if r["unsupported_claim"])
        failure_count = sum(1 for r in scenario_evals if r["failure_class"] == "FailureClass.INVESTIGATION_FAILURE")
        total_llm_calls = sum(r["llm_calls_used"] for r in scenario_evals)
        avg_llm_latency = sum(llm_latencies) / len(llm_latencies) if llm_latencies else 0.0

        experiment_results[k_key] = {
            "k": k,
            "mean_required_evidence_recall": round(mean_recall, 1),
            "per_scenario_recall": {r["scenario_id"]: r["required_evidence_recall"] for r in scenario_evals},
            "mean_noise_ratio": round(mean_noise, 1),
            "mean_contradiction_discovery": round(mean_contra, 1),
            "premature_termination_rate": round(premature_count / len(scenario_evals) * 100.0, 1),
            "unsupported_claim_rate": round(unsupported_count / len(scenario_evals) * 100.0, 1),
            "investigation_failures_count": failure_count,
            "total_llm_calls": total_llm_calls,
            "total_wall_clock_seconds": round(k_elapsed, 2),
            "average_llm_latency_seconds": round(avg_llm_latency, 2),
            "peak_rss_mb": round(peak_rss_mb, 1),
            "unique_chunks_admitted_count": len(total_unique_chunks_admitted),
            "recovered_from_ranks_gt_4": recovered_from_gt4_count,
            "scenario_evaluations": scenario_evals,
        }

        # Save incrementally after each k
        OUTPUT_JSON_PATH.write_text(json.dumps(experiment_results, indent=2), encoding="utf-8")
        print(f"\n[SUMMARY for k={k}]: Mean Recall: {mean_recall:.1f}% | Noise: {mean_noise:.1f}% | Latency: {k_elapsed:.1f}s | Recovered >Rank4: {recovered_from_gt4_count}", flush=True)

    print(f"\n[+] Experiment complete! Raw results saved to: {OUTPUT_JSON_PATH}", flush=True)


if __name__ == "__main__":
    run_experiment()
