"""
Brick 3.6B: Adaptive Retrieval Policy Controlled Experiment
Simulates the generic, deterministic adaptive retrieval expansion policy (k=8 -> 10)
against the frozen 8-scenario benchmark.
Compares:
  A. Static k=8
  B. Static k=10
  C. Adaptive k=8 -> 10
"""

import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple
import psutil

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.inference.ollama_provider import OllamaProvider
from backend.investigation.engine import InvestigationEngine
from backend.investigation.evaluator import InvestigationEvaluator
from backend.investigation.models import (
    EvidencePackage,
    GapStatus,
    GapType,
    InformationGap,
    InvestigationBudget,
    InvestigationSession,
)
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

BENCHMARK_SPEC_PATH = project_root / "tests" / "test_data" / "nova_investigation_benchmark_v1.json"
CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
OUTPUT_JSON_PATH = project_root / "experiments" / "adaptive_retrieval_experiment_results.json"
PREV_EXP_PATH = project_root / "experiments" / "retrieval_window_experiment_results.json"


class AdaptiveRetrievalPolicy:
    """
    Generic, domain-agnostic deterministic retrieval expansion policy.
    Initial search: k=8.
    Expansion: k=10 if any deterministic trigger fires.
    """

    @staticmethod
    def should_expand(
        initial_hits: List[Tuple[Evidence, float]],
        session: InvestigationSession,
        candidate_pool: List[Tuple[Evidence, float]],
    ) -> Tuple[bool, str]:
        """
        Evaluates domain-agnostic deterministic triggers for expanding candidate window from 8 to 10.
        Returns: (should_expand, trigger_name)
        """
        if len(initial_hits) < 8:
            return False, "NONE_INSUFFICIENT_INITIAL_CANDIDATES"

        scores = [score for _, score in initial_hits]
        chunks = [chunk for chunk, _ in initial_hits]

        # Trigger 5: Source Monopolization / Concentration
        # If >= 62.5% (5/8) of chunks come from a single source, expand to admit diverse sources
        source_counts = Counter(c.source_id for c in chunks)
        top_source, count = source_counts.most_common(1)[0]
        concentration = count / len(chunks)
        if concentration >= 0.625:
            return True, f"TRIGGER_5_SOURCE_MONOPOLIZATION (Source '{top_source}' holds {concentration*100:.1f}%)"

        # Trigger 6: Score Tail Flatness (Decay Ratio)
        # If candidate 8 score is >= 50% of candidate 4 score, the relevance curve is flat
        score_decay_ratio = scores[7] / scores[3] if scores[3] > 0 else 0.0
        if score_decay_ratio >= 0.50 and scores[7] >= 2.5:
            return True, f"TRIGGER_6_SCORE_TAIL_FLATNESS (Ratio c8/c4={score_decay_ratio:.2f} >= 0.50)"

        # Trigger 4/7: Unresolved Reference / Token Affinity in Expansion Window
        # Inspect candidates in ranks 9..10 without LLM call
        expansion_candidates = candidate_pool[8:10]
        unresolved_refs = {r.upper() for r in session.unresolved_references}
        for rank_offset, (cand, _) in enumerate(expansion_candidates, 9):
            cand_upper = cand.content.upper()
            for ref in unresolved_refs:
                if ref in cand_upper:
                    return True, f"TRIGGER_7_GAP_REFERENCE_AFFINITY (Candidate at Rank {rank_offset} matches '{ref}')"

        # Trigger 3: Suspected Contradiction with Single Perspective
        # If session has an open contradiction gap with <= 1 evidence item
        contra_gaps = [g for g in session.gaps.values() if g.gap_type == GapType.CONTRADICTION_RECONCILIATION]
        if contra_gaps and len(session.discovered_evidence) <= 4:
            return True, "TRIGGER_3_CONTRADICTION_URGENCY (Contradiction suspected but unbalanced evidence)"

        return False, "NONE_STABLE_WINDOW"


def run_adaptive_experiment():
    print("=" * 105, flush=True)
    print("      ORACLE BRICK 3.6B: ADAPTIVE RETRIEVAL POLICY CONTROLLED EXPERIMENT", flush=True)
    print("      Evaluating Generic Deterministic Policy: k=8 -> 10 Expansion | Frozen Benchmark", flush=True)
    print("=" * 105, flush=True)

    # 1. Index Corpus
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))

    retriever = SQLiteFTS5Retriever(":memory:")
    retriever.index_evidence(all_chunks)

    provider = OllamaProvider(default_model="qwen2.5:3b", timeout=120.0)
    assert provider.health_check(), "Ollama is not running!"

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

    # 2. Load Static Baseline Results
    static_results = json.loads(PREV_EXP_PATH.read_text(encoding="utf-8"))
    k8_res = static_results["k_8"]
    k10_res = static_results["k_10"]

    # 3. Run Adaptive Policy
    adaptive_evals = []
    expansion_decisions = []
    unique_chunks_admitted: set = set()
    total_candidates_admitted = 0
    recovered_from_expansion = 0
    unnecessary_expansions = 0
    llm_latencies = []
    peak_rss_mb = 0.0

    process = psutil.Process(os.getpid())
    start_total = time.perf_counter()

    for idx, sc in enumerate(scenarios, 1):
        sid = sc["scenario_id"]
        arch = sc["archetype"]
        obj = sc["objective"]
        req_ids = set(sc["required_evidence_ids"])

        print(f"\n[{idx}/8] ({sid} | Adaptive): '{obj[:65]}...'", flush=True)

        # Pre-flight candidate check for the adaptive trigger
        candidate_pool, _ = retriever.search(obj, k=10)
        initial_hits = candidate_pool[:8]

        # Initialize lightweight session to simulate pre-turn gaps
        temp_session = InvestigationSession(session_id="pre", objective=obj)
        for e, _ in initial_hits:
            temp_session.discovered_evidence[e.evidence_id] = e
        temp_session.unresolved_references.update(engine.controller.scanner.find_unresolved_references(temp_session.discovered_evidence))
        edges = engine.controller.scanner.detect_deterministic_edges(list(temp_session.discovered_evidence.values()))
        engine.controller._derive_and_update_gaps(temp_session, edges)

        # Evaluate Deterministic Policy
        should_expand, reason = AdaptiveRetrievalPolicy.should_expand(
            initial_hits=initial_hits,
            session=temp_session,
            candidate_pool=candidate_pool,
        )

        chosen_k = 10 if should_expand else 8
        expansion_decisions.append({
            "scenario_id": sid,
            "chosen_k": chosen_k,
            "expanded": should_expand,
            "trigger_reason": reason,
        })

        print(f"      [DECISION]: Chosen k={chosen_k} | Expanded: {should_expand} | Trigger: {reason}", flush=True)

        # Execute investigation with chosen_k
        t0 = time.perf_counter()
        mem_now = process.memory_info().rss / (1024 * 1024)
        peak_rss_mb = max(peak_rss_mb, mem_now)

        try:
            package = engine.controller.run_investigation(
                objective=obj,
                reasoning_agent_fn=engine._call_llm_for_step,
                initial_k=chosen_k,
            )
        except Exception as exc:
            elapsed_s = time.perf_counter() - t0
            print(f"      [TIMEOUT/EXCEPTION]: {exc} -> Graceful timeout package recorded", flush=True)
            init_hits, _ = retriever.search(obj, k=chosen_k)
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

        if package.budget_summary.get("llm_calls_used", 0) > 0:
            llm_latencies.append(elapsed_s / package.budget_summary["llm_calls_used"])

        admitted_eids = {e.evidence_id for e in package.evidence_items}
        unique_chunks_admitted.update(admitted_eids)
        total_candidates_admitted += chosen_k

        # Check recovery & unnecessary expansion
        if should_expand:
            # Did ranks 9-10 contain required evidence?
            expansion_eids = {h.evidence_id for h, _ in candidate_pool[8:10]}
            gained_reqs = expansion_eids.intersection(req_ids)
            if gained_reqs:
                recovered_from_expansion += len(gained_reqs)
                print(f"      [BENEFIT]: Gained required chunk(s) {gained_reqs} via expansion!", flush=True)
            else:
                unnecessary_expansions += 1
                print(f"      [UNNECESSARY]: Expansion fired but ranks 9-10 held no required evidence.", flush=True)

        eval_res = evaluator.evaluate_scenario(
            scenario_spec=sc,
            package=package,
            elapsed_seconds=elapsed_s,
            ram_rss_mb=mem_after,
        )
        adaptive_evals.append(eval_res.model_dump())

        print(f"      - Failure Class: {eval_res.failure_class.value} | Recall: {eval_res.required_evidence_recall:.1f}% | Time: {elapsed_s:.2f}s", flush=True)

    total_adaptive_time = time.perf_counter() - start_total

    # 4. Compute Aggregate Metrics for Adaptive
    recalls = [r["required_evidence_recall"] for r in adaptive_evals]
    mean_recall = sum(recalls) / len(recalls) if recalls else 0.0

    contra_scores = [r["contradictory_evidence_discovered"] for r in adaptive_evals if r["contradictory_evidence_discovered"] is not None]
    mean_contra = sum(contra_scores) / len(contra_scores) if contra_scores else 0.0

    premature_count = sum(1 for r in adaptive_evals if r["premature_termination"])
    unsupported_count = sum(1 for r in adaptive_evals if r["unsupported_claim"])
    failure_count = sum(1 for r in adaptive_evals if r["failure_class"] == "FailureClass.INVESTIGATION_FAILURE")
    total_llm_calls = sum(r["llm_calls_used"] for r in adaptive_evals)
    avg_llm_lat = sum(llm_latencies) / len(llm_latencies) if llm_latencies else 0.0

    num_expansions = sum(1 for d in expansion_decisions if d["expanded"])
    avg_candidates_admitted = total_candidates_admitted / len(scenarios)

    adaptive_summary = {
        "mean_required_evidence_recall": round(mean_recall, 1),
        "per_scenario_recall": {r["scenario_id"]: r["required_evidence_recall"] for r in adaptive_evals},
        "mean_contradiction_discovery": round(mean_contra, 1),
        "premature_termination_rate": round(premature_count / len(scenarios) * 100.0, 1),
        "unsupported_claim_rate": round(unsupported_count / len(scenarios) * 100.0, 1),
        "investigation_failures_count": failure_count,
        "total_llm_calls": total_llm_calls,
        "total_wall_clock_seconds": round(total_adaptive_time, 2),
        "average_llm_latency_seconds": round(avg_llm_lat, 2),
        "peak_rss_mb": round(peak_rss_mb, 1),
        "average_candidates_admitted": round(avg_candidates_admitted, 1),
        "number_of_expansions": num_expansions,
        "unnecessary_expansions": unnecessary_expansions,
        "evidence_recovered_by_expansion": recovered_from_expansion,
        "expansion_decisions": expansion_decisions,
        "scenario_evaluations": adaptive_evals,
    }

    final_comparison = {
        "static_k8": k8_res,
        "static_k10": k10_res,
        "adaptive_k8_to_10": adaptive_summary,
    }

    OUTPUT_JSON_PATH.write_text(json.dumps(final_comparison, indent=2), encoding="utf-8")
    print(f"\n[+] Adaptive Experiment complete! Saved results to {OUTPUT_JSON_PATH}", flush=True)


if __name__ == "__main__":
    run_adaptive_experiment()
