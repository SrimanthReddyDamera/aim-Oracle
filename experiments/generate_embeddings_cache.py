"""
ORACLE Vector Embedding Cache Generator (Brick 2B)
Pre-computes and caches dense vectors for the 28 NOVA corpus chunks and 23 benchmark queries.
Uses the local 'nomic-embed-text:latest' model via OllamaProvider.
"""

import json
import sys
import time
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.inference.ollama_provider import OllamaProvider
from backend.evidence.parser import MarkdownEvidenceParser

CORPUS_DIR = project_root / "tests" / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
EVAL_SET_PATH = project_root / "tests" / "test_data" / "nova_eval_set_v1.json"
CACHE_PATH = project_root / "tests" / "test_data" / "nova_embeddings_cache.json"


def generate_cache():
    print("=" * 80)
    print("       PRE-COMPUTING DENSE VECTOR EMBEDDINGS CACHE (nomic-embed-text)")
    print("=" * 80)

    provider = OllamaProvider()
    assert provider.health_check(), "Ollama is not running!"

    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    # 1. Parse all 28 chunks
    all_chunks = []
    for doc in manifest["documents"]:
        fpath = CORPUS_DIR / doc["filename"]
        chunks = parser.parse_file(fpath)
        all_chunks.extend(chunks)

    print(f"[+] Parsed {len(all_chunks)} chunks from {len(manifest['documents'])} documents.")

    chunk_embeddings = {}
    print("\n[+] Generating embeddings for 28 Evidence chunks...")
    t0 = time.perf_counter()
    for i, c in enumerate(all_chunks):
        res = provider.embed(c.content)
        chunk_embeddings[c.evidence_id] = res.embedding
        print(f"    - [{i+1:02d}/{len(all_chunks):02d}] {c.evidence_id:<22} ({res.duration_ms:.1f} ms)")

    chunk_time = time.perf_counter() - t0
    print(f"[+] All chunk embeddings computed in {chunk_time:.2f}s.")

    # 2. Read evaluation queries
    eval_data = json.loads(EVAL_SET_PATH.read_text(encoding="utf-8"))
    queries = [tc["query"] for tc in eval_data["test_cases"]]
    print(f"\n[+] Generating embeddings for {len(queries)} benchmark queries...")

    query_embeddings = {}
    query_latencies_ms = []
    for i, q in enumerate(queries):
        res = provider.embed(q)
        query_embeddings[q] = res.embedding
        query_latencies_ms.append(res.duration_ms)
        print(f"    - [Q-{i+1:02d}] {res.duration_ms:.1f} ms | {q[:50]}...")

    avg_query_ms = sum(query_latencies_ms) / len(query_latencies_ms)
    print(f"[+] Query embedding baseline: Mean latency = {avg_query_ms:.2f} ms")

    # 3. Save cache
    cache_payload = {
        "embedding_model": "nomic-embed-text:latest",
        "dimensions": 768,
        "chunk_embeddings": chunk_embeddings,
        "query_embeddings": query_embeddings,
        "query_embedding_latencies_ms": query_latencies_ms,
        "mean_query_embedding_ms": round(avg_query_ms, 2),
    }

    CACHE_PATH.write_text(json.dumps(cache_payload, indent=2), encoding="utf-8")
    print(f"\n[+] Cache successfully written to: {CACHE_PATH}")
    print(f"    - Chunk vectors cached: {len(chunk_embeddings)}")
    print(f"    - Query vectors cached: {len(query_embeddings)}")
    print("=" * 80)


if __name__ == "__main__":
    generate_cache()
