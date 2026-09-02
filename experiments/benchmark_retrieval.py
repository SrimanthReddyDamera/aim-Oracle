"""
ORACLE Brick 2B Comparative Retrieval Benchmark Runner
Executes an empirical, independent evaluation of all three candidate retrieval architectures:
  - Candidate A: SQLite FTS5 (Pure Lexical BM25)
  - Candidate B: SQLite + Local Dense Vectors (In-Process NumPy Cosine)
  - Candidate C: LanceDB (Columnar Arrow Hybrid Search)

Operates on the Initial Controlled Evaluation Suite v1 (23 queries, 6 topologies).
Produces reproducible machine-readable results in:
  experiments/retrieval_benchmark_results.json
"""

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
import psutil
import numpy as np

# Ensure project root in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.evidence.models import Evidence
from backend.evidence.parser import MarkdownEvidenceParser
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
from backend.retrieval.sqlite_vector_retriever import SQLiteVectorRetriever
from backend.retrieval.lancedb_retriever import LanceDBRetriever

CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
EVAL_SET_PATH = project_root / "tests" / "test_data" / "nova_eval_set_v1.json"
CACHE_PATH = project_root / "tests" / "test_data" / "nova_embeddings_cache.json"
RESULTS_PATH = project_root / "experiments" / "retrieval_benchmark_results.json"
STORAGE_DIR = project_root / "storage"


def get_dir_size_bytes(path: Path) -> int:
    """Calculate total byte size of a file or directory."""
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    return sum(f.stat().st_size for f in path.glob("**/*") if f.is_file())


def get_ram_rss_mb() -> float:
    """Current process RSS memory in MB."""
    return psutil.Process().memory_info().rss / (1024 * 1024)


def compute_metrics_at_k(
    retrieved_chunks: List[Evidence],
    primary_ids: List[str],
    contradictory_ids: List[str],
    k: int,
) -> Dict[str, float]:
    """Compute precision, recall, completeness, and contradiction discovery at K."""
    top_k = retrieved_chunks[:k]
    top_k_ids = set(e.evidence_id for e in top_k)

    # 1. Recall: fraction of primary supporting evidence found
    if primary_ids:
        primary_found = len(top_k_ids.intersection(primary_ids))
        recall = primary_found / len(primary_ids)
        completeness = 1.0 if primary_found == len(primary_ids) else 0.0
    else:
        # Unanswerable queries: recall is 1.0 if no false positive claims required
        recall = 1.0
        completeness = 1.0

    # 2. Precision: fraction of top-k that is useful (primary OR relevant contradictory)
    useful_targets = set(primary_ids).union(contradictory_ids)
    if top_k:
        useful_found = len(top_k_ids.intersection(useful_targets))
        precision = useful_found / len(top_k)
    else:
        precision = 1.0 if not useful_targets else 0.0

    # 3. Contradiction Recall
    if contradictory_ids:
        contra_found = len(top_k_ids.intersection(contradictory_ids))
        contra_recall = contra_found / len(contradictory_ids)
    else:
        contra_recall = None

    return {
        "recall": recall,
        "precision": precision,
        "completeness": completeness,
        "contradiction_recall": contra_recall,
    }


def run_candidate_benchmark(
    candidate_name: str,
    retriever: Any,
    evidence_list: List[Evidence],
    eval_test_cases: List[Dict[str, Any]],
    embeddings_cache: Dict[str, Any],
    storage_path: Path,
    is_vector: bool = False,
    is_hybrid: bool = False,
) -> Dict[str, Any]:
    print(f"\n[{candidate_name}] Starting Independent Evaluation...")
    ram_start = get_ram_rss_mb()

    # 1. Indexing phase
    if is_vector or is_hybrid:
        build_time_ms = retriever.index_evidence(evidence_list, embeddings_cache["chunk_embeddings"])
    else:
        build_time_ms = retriever.index_evidence(evidence_list)

    disk_bytes = get_dir_size_bytes(storage_path)
    ram_peak = get_ram_rss_mb()
    ram_delta_mb = max(0.0, ram_peak - ram_start)

    print(f"    - Index Build Time: {build_time_ms:.2f} ms")
    print(f"    - Disk Footprint:   {disk_bytes / 1024:.1f} KB")
    print(f"    - RAM Delta:        {ram_delta_mb:.2f} MB")

    # 2. Cold-start query probe (Query 1)
    q0 = eval_test_cases[0]["query"]
    q0_vec = embeddings_cache["query_embeddings"].get(q0, [0.0]*768)

    if is_hybrid:
        _, cold_latency_ms = retriever.search(q0, q0_vec, k=5)
    elif is_vector:
        _, cold_latency_ms = retriever.search(q0_vec, k=5)
    else:
        _, cold_latency_ms = retriever.search(q0, k=5)

    print(f"    - Cold Query Latency: {cold_latency_ms:.2f} ms")

    # 3. Repeated warm evaluation across all 23 queries (5 iterations)
    warm_latencies_ms = []
    query_details = []

    for tc in eval_test_cases:
        qid = tc["question_id"]
        q_str = tc["query"]
        q_vec = embeddings_cache["query_embeddings"].get(q_str, [0.0]*768)

        primary_ids = tc["evidence_classification"]["primary_supporting_evidence"]
        contra_ids = tc["evidence_classification"]["relevant_contradictory_or_stale_evidence"]

        # Run 5 timed passes per query
        latencies_for_q = []
        last_results = []
        for _ in range(5):
            if is_hybrid:
                res, lat_ms = retriever.search(q_str, q_vec, k=8)
            elif is_vector:
                res, lat_ms = retriever.search(q_vec, k=8)
            else:
                res, lat_ms = retriever.search(q_str, k=8)
            latencies_for_q.append(lat_ms)
            last_results = res

        median_lat_ms = float(np.median(latencies_for_q))
        warm_latencies_ms.append(median_lat_ms)

        # Compute metrics at K=3, 5, 8
        retrieved_ev = [item[0] for item in last_results]
        retrieved_scores = [item[1] for item in last_results]

        m3 = compute_metrics_at_k(retrieved_ev, primary_ids, contra_ids, k=3)
        m5 = compute_metrics_at_k(retrieved_ev, primary_ids, contra_ids, k=5)
        m8 = compute_metrics_at_k(retrieved_ev, primary_ids, contra_ids, k=8)

        query_details.append({
            "question_id": qid,
            "topology": tc["topology"],
            "query": q_str,
            "latency_ms": round(median_lat_ms, 2),
            "max_score": round(float(retrieved_scores[0]), 4) if retrieved_scores else 0.0,
            "retrieved_ids_top5": [e.evidence_id for e in retrieved_ev[:5]],
            "k3": m3,
            "k5": m5,
            "k8": m8,
        })

    # Aggregated metrics calculation at K=5
    all_recalls_5 = [q["k5"]["recall"] for q in query_details if q["topology"] != "unanswerable_out_of_bounds"]
    all_prec_5 = [q["k5"]["precision"] for q in query_details if q["topology"] != "unanswerable_out_of_bounds"]
    all_compl_5 = [q["k5"]["completeness"] for q in query_details if q["topology"] != "unanswerable_out_of_bounds"]

    multihop_compl_5 = [
        q["k5"]["completeness"] for q in query_details if q["topology"] == "multi_hop_causal"
    ]

    contra_recalls = [
        q["k5"]["contradiction_recall"]
        for q in query_details
        if q["k5"]["contradiction_recall"] is not None
    ]

    unanswerable_scores = [
        q["max_score"] for q in query_details if q["topology"] == "unanswerable_out_of_bounds"
    ]

    mean_recall_5 = float(np.mean(all_recalls_5)) if all_recalls_5 else 0.0
    mean_prec_5 = float(np.mean(all_prec_5)) if all_prec_5 else 0.0
    mean_compl_5 = float(np.mean(all_compl_5)) if all_compl_5 else 0.0
    mean_multihop_compl_5 = float(np.mean(multihop_compl_5)) if multihop_compl_5 else 0.0
    mean_contra_recall = float(np.mean(contra_recalls)) if contra_recalls else 0.0
    max_unanswerable_score = max(unanswerable_scores) if unanswerable_scores else 0.0

    p95_lat_ms = float(np.percentile(warm_latencies_ms, 95))
    mean_lat_ms = float(np.mean(warm_latencies_ms))

    retriever.close()

    return {
        "candidate_name": candidate_name,
        "build_time_ms": round(build_time_ms, 2),
        "disk_kb": round(disk_bytes / 1024, 1),
        "ram_delta_mb": round(ram_delta_mb, 2),
        "cold_latency_ms": round(cold_latency_ms, 2),
        "warm_mean_latency_ms": round(mean_lat_ms, 2),
        "warm_p95_latency_ms": round(p95_lat_ms, 2),
        "mean_recall_k5": round(mean_recall_5 * 100, 1),
        "mean_precision_k5": round(mean_prec_5 * 100, 1),
        "mean_completeness_k5": round(mean_compl_5 * 100, 1),
        "multihop_completeness_k5": round(mean_multihop_compl_5 * 100, 1),
        "contradiction_recall": round(mean_contra_recall * 100, 1) if contra_recalls else None,
        "unanswerable_max_score": round(max_unanswerable_score, 4),
        "query_details": query_details,
    }


def main():
    print("=" * 80)
    print("      ORACLE BRICK 2B: EMPIRICAL RETRIEVAL BENCHMARK EXECUTION")
    print("=" * 80)

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Ingest Evidence Chunks
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    evidence_list = []
    for doc in manifest["documents"]:
        evidence_list.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    print(f"[+] Loaded {len(evidence_list)} normalized Evidence chunks from NOVA corpus.")

    # 2. Ingest 23 Evaluation Queries
    eval_set = json.loads(EVAL_SET_PATH.read_text(encoding="utf-8"))
    test_cases = eval_set["test_cases"]
    print(f"[+] Loaded {len(test_cases)} evaluation test cases from {EVAL_SET_PATH.name}.")

    # 3. Ingest Vector Cache
    assert CACHE_PATH.exists(), f"Vector cache missing! Run generate_embeddings_cache.py first: {CACHE_PATH}"
    embeddings_cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    print(f"[+] Loaded pre-computed embeddings cache ({embeddings_cache['dimensions']} dimensions).")

    # --- Execute Candidate A: SQLite FTS5 ---
    fts5_path = STORAGE_DIR / "oracle_fts5.db"
    if fts5_path.exists():
        fts5_path.unlink()
    cand_a_retriever = SQLiteFTS5Retriever(db_path=fts5_path)
    res_a = run_candidate_benchmark(
        candidate_name="Candidate A: SQLite FTS5",
        retriever=cand_a_retriever,
        evidence_list=evidence_list,
        eval_test_cases=test_cases,
        embeddings_cache=embeddings_cache,
        storage_path=fts5_path,
        is_vector=False,
        is_hybrid=False,
    )

    # --- Execute Candidate B: SQLite + Local Vectors ---
    vec_path = STORAGE_DIR / "oracle_vectors.db"
    if vec_path.exists():
        vec_path.unlink()
    cand_b_retriever = SQLiteVectorRetriever(db_path=vec_path)
    res_b = run_candidate_benchmark(
        candidate_name="Candidate B: SQLite + Vector",
        retriever=cand_b_retriever,
        evidence_list=evidence_list,
        eval_test_cases=test_cases,
        embeddings_cache=embeddings_cache,
        storage_path=vec_path,
        is_vector=True,
        is_hybrid=False,
    )

    # --- Execute Candidate C: LanceDB ---
    lance_path = STORAGE_DIR / "oracle_lancedb"
    if lance_path.exists():
        shutil.rmtree(lance_path)
    cand_c_retriever = LanceDBRetriever(db_dir=lance_path)
    res_c = run_candidate_benchmark(
        candidate_name="Candidate C: LanceDB Hybrid",
        retriever=cand_c_retriever,
        evidence_list=evidence_list,
        eval_test_cases=test_cases,
        embeddings_cache=embeddings_cache,
        storage_path=lance_path,
        is_vector=True,
        is_hybrid=True,
    )

    # Compile benchmark summary payload
    final_output = {
        "benchmark_metadata": {
            "title": "ORACLE Brick 2B Retrieval Benchmark",
            "eval_suite": "Initial Controlled Evaluation Suite v1",
            "total_queries": len(test_cases),
            "total_evidence_chunks": len(evidence_list),
            "embedding_model": embeddings_cache.get("embedding_model"),
            "mean_query_embedding_latency_ms": embeddings_cache.get("mean_query_embedding_ms"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "candidate_results": [res_a, res_b, res_c],
    }

    RESULTS_PATH.write_text(json.dumps(final_output, indent=2), encoding="utf-8")
    print(f"\n[+] Full machine-readable results written to: {RESULTS_PATH}")

    # Print Final Comparative Scorecard Table
    print("\n" + "=" * 105)
    print("                              ORACLE BRICK 2B RETRIEVAL COMPARATIVE SCORECARD")
    print("=" * 105)
    header = (
        f"{'Candidate Architecture':<30} | "
        f"{'Recall@5':<9} | "
        f"{'Compl@5':<8} | "
        f"{'MultiHop':<9} | "
        f"{'ContraRec':<10} | "
        f"{'Latency':<11} | "
        f"{'Disk':<9} | "
        f"{'Dependencies'}"
    )
    print(header)
    print("-" * 105)

    dep_map = {
        "Candidate A: SQLite FTS5": "stdlib (sqlite3)",
        "Candidate B: SQLite + Vector": "stdlib + numpy",
        "Candidate C: LanceDB Hybrid": "pyarrow, lancedb",
    }

    for r in [res_a, res_b, res_c]:
        contra_str = f"{r['contradiction_recall']:.1f}%" if r['contradiction_recall'] is not None else "N/A"
        row = (
            f"{r['candidate_name']:<30} | "
            f"{r['mean_recall_k5']:>7.1f}% | "
            f"{r['mean_completeness_k5']:>6.1f}% | "
            f"{r['multihop_completeness_k5']:>7.1f}% | "
            f"{contra_str:>10} | "
            f"{r['warm_mean_latency_ms']:>8.2f} ms | "
            f"{r['disk_kb']:>6.1f} KB | "
            f"{dep_map.get(r['candidate_name'], '')}"
        )
        print(row)

    print("=" * 105)
    print("Benchmark completed successfully.\n")


if __name__ == "__main__":
    main()
