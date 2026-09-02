"""
Unit Tests for ORACLE Brick 2B Retrieval Candidates
Verifies that all three candidate retrieval engines:
  - Candidate A: SQLiteFTS5Retriever
  - Candidate B: SQLiteVectorRetriever
  - Candidate C: LanceDBRetriever
function properly with deterministic indexing and querying.
"""

import json
from pathlib import Path
import pytest

from backend.evidence.parser import MarkdownEvidenceParser
from backend.retrieval.fts5_retriever import SQLiteFTS5Retriever
from backend.retrieval.sqlite_vector_retriever import SQLiteVectorRetriever
from backend.retrieval.lancedb_retriever import LanceDBRetriever

CORPUS_DIR = Path(__file__).resolve().parent.parent / "test_data" / "nova_corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
CACHE_PATH = Path(__file__).resolve().parent.parent / "test_data" / "nova_embeddings_cache.json"


@pytest.fixture(scope="module")
def corpus_evidence():
    parser = MarkdownEvidenceParser()
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    evidence_list = []
    for doc in manifest["documents"]:
        evidence_list.extend(parser.parse_file(CORPUS_DIR / doc["filename"]))
    return evidence_list


@pytest.fixture(scope="module")
def embeddings_cache():
    assert CACHE_PATH.exists(), f"Embedding cache missing: {CACHE_PATH}"
    return json.loads(CACHE_PATH.read_text(encoding="utf-8"))


def test_candidate_a_fts5_lifecycle(corpus_evidence, tmp_path):
    """Verify Candidate A indexes and searches using pure SQLite FTS5."""
    db_file = tmp_path / "test_fts.db"
    retriever = SQLiteFTS5Retriever(db_path=db_file)

    build_time = retriever.index_evidence(corpus_evidence)
    assert build_time > 0

    results, lat_ms = retriever.search("incident INC-402 Redis rollback", k=3)
    assert len(results) > 0
    assert lat_ms >= 0

    top_ids = [e.evidence_id for e, _ in results]
    assert any("DOC-NOVA-INC-402" in eid for eid in top_ids)
    retriever.close()


def test_candidate_b_sqlite_vector_lifecycle(corpus_evidence, embeddings_cache, tmp_path):
    """Verify Candidate B indexes and computes cosine similarity via NumPy."""
    db_file = tmp_path / "test_vec.db"
    retriever = SQLiteVectorRetriever(db_path=db_file)

    build_time = retriever.index_evidence(corpus_evidence, embeddings_cache["chunk_embeddings"])
    assert build_time > 0

    # Query using cached vector
    sample_q = "What was the incident identifier for the Redis production regression?"
    q_vec = embeddings_cache["query_embeddings"][sample_q]

    results, lat_ms = retriever.search(q_vec, k=3)
    assert len(results) == 3
    assert lat_ms >= 0

    top_ids = [e.evidence_id for e, _ in results]
    assert any("DOC-NOVA-INC-402" in eid for eid in top_ids)
    retriever.close()


def test_candidate_c_lancedb_lifecycle(corpus_evidence, embeddings_cache, tmp_path):
    """Verify Candidate C indexes and performs hybrid search in LanceDB."""
    db_dir = tmp_path / "test_lance"
    retriever = LanceDBRetriever(db_dir=db_dir)

    build_time = retriever.index_evidence(corpus_evidence, embeddings_cache["chunk_embeddings"])
    assert build_time > 0

    sample_q = "What was the incident identifier for the Redis production regression?"
    q_vec = embeddings_cache["query_embeddings"][sample_q]

    results, lat_ms = retriever.search(sample_q, q_vec, k=3)
    assert len(results) > 0
    assert lat_ms >= 0

    top_ids = [e.evidence_id for e, _ in results]
    assert any("DOC-NOVA-INC-402" in eid for eid in top_ids)
    retriever.close()
