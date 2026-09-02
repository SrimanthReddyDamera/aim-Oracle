"""
ORACLE Brick 3.2: Correctness-Enhanced Investigation Benchmark Runner
Executes the live InvestigationEngine with local OllamaProvider (qwen2.5:3b)
incorporating all four audited fixes:
  - P1: Dependency-directed investigation prompting
  - P2: Jaccard semantic similarity duplicate query rejection
  - P3: Zero-yield query tracking and feedback
  - P4: Proposal vs authoritative resolution distinction
  - First-class InvestigationGap lifecycle tracking
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
from backend.investigation.models import InvestigationBudget
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever

CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
STORAGE_DB = project_root / "storage" / "oracle_investigation_fts.db"
RESULTS_PATH = project_root / "experiments" / "investigation_benchmark_results_brick32.json"

SCENARIOS = [
    {
        "id": "INV-01",
        "question_id": "Q-13",
        "objective": "Can Project Phoenix safely launch this Friday, October 24 at 09:00 UTC?",
        "required_chunks": [
            "DOC-NOVA-OVERVIEW#c003",
            "DOC-NOVA-INC-402#c004",
            "DOC-NOVA-PAYMENT#c003",
            "DOC-NOVA-CAB#c003",
        ],
        "contradictory_chunks": ["DOC-NOVA-ARCH-OLD#c003"],
    },
    {
        "id": "INV-02",
        "question_id": "Q-15",
        "objective": "How does the rollback of INC-402 create an immediate risk of a Tier-1 regulatory license suspension under Project Phoenix?",
        "required_chunks": [
            "DOC-NOVA-INC-402#c004",
            "DOC-NOVA-PAYMENT#c002",
            "DOC-NOVA-COMPLIANCE#c002",
            "DOC-NOVA-COMPLIANCE#c003",
        ],
        "contradictory_chunks": ["DOC-NOVA-ARCH-OLD#c003"],
    },
    {
        "id": "INV-03",
        "question_id": "Q-16",
        "objective": "What sequence of events and approvals is required before Project Phoenix can achieve compliant production status?",
        "required_chunks": [
            "DOC-NOVA-CAB#c004",
            "DOC-NOVA-CAB#c005",
            "DOC-NOVA-PAYMENT#c002",
        ],
        "contradictory_chunks": ["DOC-NOVA-CAB#c002"],
    },
]


def run_benchmark():
    print("=" * 95, flush=True)
    print("      ORACLE BRICK 3.2: CORRECTNESS-ENHANCED INVESTIGATION BENCHMARK", flush=True)
    print("      Invariants: P1 Directed Queries | P2 Jaccard Deduplication | P3 Zero-Yield | P4 Resolutions", flush=True)
    print("=" * 95, flush=True)

    # 1. Index Corpus into FTS5
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    all_chunks = []
    for doc in manifest["documents"]:
        all_chunks.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))

    if STORAGE_DB.exists():
        STORAGE_DB.unlink()
    retriever = SQLiteFTS5Retriever(db_path=STORAGE_DB)
    retriever.index_evidence(all_chunks)
    print(f"[+] Initialized SQLite FTS5 index with {len(all_chunks)} chunks.", flush=True)

    # 2. Initialize Provider & Engine
    provider = OllamaProvider()
    assert provider.health_check(), "Ollama is not running!"
    print(f"[+] Connected to local LLM: {provider.default_model}", flush=True)

    # STRICT TIMEOUT: 30.0s (Not increased!)
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

    benchmark_records = []
    process = psutil.Process(os.getpid())

    for sc in SCENARIOS:
        print(f"\n[{sc['id']}] Running Investigation: '{sc['objective'][:60]}...'", flush=True)
        t0 = time.perf_counter()
        mem_start_mb = process.memory_info().rss / (1024 * 1024)

        package = engine.investigate(sc["objective"])
        elapsed_s = time.perf_counter() - t0
        mem_end_mb = process.memory_info().rss / (1024 * 1024)

        retrieved_ids = set(e.evidence_id for e in package.evidence_items)
        req_set = set(sc["required_chunks"])
        found_req = req_set.intersection(retrieved_ids)

        completeness_pct = (len(found_req) / len(req_set)) * 100.0 if req_set else 100.0

        contra_set = set(sc.get("contradictory_chunks", []))
        found_contra = contra_set.intersection(retrieved_ids)
        contra_recall_pct = (len(found_contra) / len(contra_set)) * 100.0 if contra_set else None

        # Verify byte-level provenance
        provenance_verified = True
        for ev in package.evidence_items:
            fpath = CORPUS_DIR / f"{ev.source_id}.md"
            if not fpath.exists():
                provenance_verified = False
                break
            raw_bytes = fpath.read_bytes()
            if raw_bytes[ev.start_offset:ev.end_offset].decode("utf-8") != ev.content:
                provenance_verified = False
                break

        print(f"    - Controller Verdict:  {package.termination_reason}", flush=True)
        print(f"    - Controller Verified: {package.controller_verified}", flush=True)
        print(f"    - Hops Used:           {package.budget_summary['hops_used']}", flush=True)
        print(f"    - LLM Calls:           {package.budget_summary['llm_calls_used']}", flush=True)
        print(f"    - Zero-Yield Queries:  {package.budget_summary.get('zero_yield_queries_count', 0)}", flush=True)
        print(f"    - Elapsed Time:        {elapsed_s:.2f}s", flush=True)
        print(f"    - Chunks Collected:    {len(package.evidence_items)}", flush=True)
        print(f"    - Completeness:        {completeness_pct:.1f}% ({len(found_req)}/{len(req_set)})", flush=True)
        if contra_recall_pct is not None:
            print(f"    - Contradiction Disc:  {contra_recall_pct:.1f}% ({len(found_contra)}/{len(contra_set)})", flush=True)
        print(f"    - Provenance Verified: {provenance_verified}", flush=True)
        print(f"    - RAM Delta:           {mem_end_mb - mem_start_mb:+.2f} MB (Total RSS: {mem_end_mb:.1f} MB)", flush=True)

        benchmark_records.append({
            "scenario_id": sc["id"],
            "question_id": sc["question_id"],
            "objective": sc["objective"],
            "termination_reason": package.termination_reason,
            "controller_verified": package.controller_verified,
            "hops_used": package.budget_summary["hops_used"],
            "llm_calls_used": package.budget_summary["llm_calls_used"],
            "queries_executed": package.budget_summary["queries_executed"],
            "zero_yield_queries_count": package.budget_summary.get("zero_yield_queries_count", 0),
            "elapsed_seconds": round(elapsed_s, 2),
            "total_chunks": len(package.evidence_items),
            "completeness_pct": round(completeness_pct, 1),
            "contradiction_recall_pct": round(contra_recall_pct, 1) if contra_recall_pct is not None else None,
            "provenance_verified": provenance_verified,
            "ram_rss_mb": round(mem_end_mb, 1),
            "graph_edges_count": len(package.graph_edges),
            "investigation_trace_length": len(package.investigation_trace),
            "gaps_count": len(package.gaps),
            "package": package.model_dump(),
        })

    # Save Results
    RESULTS_PATH.write_text(json.dumps(benchmark_records, indent=2), encoding="utf-8")
    print(f"\n[+] Benchmark payload saved to: {RESULTS_PATH}", flush=True)

    # Print Summary Table
    print("\n" + "=" * 105, flush=True)
    print("                         BRICK 3.2 INVESTIGATION BENCHMARK SCORECARD", flush=True)
    print("=" * 105, flush=True)
    header = f"{'Scenario':<10} | {'Controller Decision':<25} | {'Verified':<8} | {'Hops':<5} | {'Completeness':<12} | {'Time (s)':<9} | {'RAM (MB)'}"
    print(header, flush=True)
    print("-" * 105, flush=True)
    for r in benchmark_records:
        row = (
            f"{r['scenario_id']:<10} | "
            f"{r['termination_reason'][:25]:<25} | "
            f"{str(r['controller_verified']):<8} | "
            f"{r['hops_used']:<5} | "
            f"{r['completeness_pct']:>10.1f}% | "
            f"{r['elapsed_seconds']:>7.2f}s | "
            f"{r['ram_rss_mb']:>7.1f} MB"
        )
        print(row, flush=True)
    print("=" * 105, flush=True)


if __name__ == "__main__":
    run_benchmark()
