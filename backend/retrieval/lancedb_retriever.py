"""
ORACLE Candidate C: LanceDB Columnar Hybrid Retriever
Uses file-backed Apache Arrow storage with native hybrid (Vector + FTS) search.
"""

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import lancedb

from backend.evidence.models import Evidence


class LanceDBRetriever:
    """
    Candidate C: Hybrid dense-lexical search using LanceDB.
    Combines dense vector similarity with Tantivy-backed FTS via Reciprocal Rank Fusion.
    """

    def __init__(self, db_dir: str | Path = "./storage/oracle_lancedb"):
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db = lancedb.connect(str(self.db_dir))
        self.table = None
        self._evidence_map: Dict[str, Evidence] = {}

    def index_evidence(
        self,
        evidence_list: List[Evidence],
        embeddings_dict: Dict[str, List[float]],
    ) -> float:
        """
        Ingest Evidence chunks and corresponding dense vectors into LanceDB.
        Creates columnar vector table and FTS index. Returns build time in ms.
        """
        t0 = time.perf_counter()

        records = []
        for e in evidence_list:
            vec = embeddings_dict.get(e.evidence_id)
            if vec is None:
                raise ValueError(f"Missing embedding for evidence_id: {e.evidence_id}")
            records.append({
                "evidence_id": e.evidence_id,
                "source_id": e.source_id,
                "content": e.content,
                "content_hash": e.content_hash,
                "source_path": e.source_path,
                "chunk_index": e.chunk_index,
                "start_offset": e.start_offset,
                "end_offset": e.end_offset,
                "metadata": json.dumps(e.metadata),
                "created_at": e.created_at,
                "vector": [float(x) for x in vec],
            })
            self._evidence_map[e.evidence_id] = e

        self.table = self.db.create_table("evidence", data=records, mode="overwrite")
        try:
            self.table.create_fts_index("content", replace=True)
        except Exception:
            pass

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return elapsed_ms

    def search(
        self,
        query_str: str,
        query_vector: List[float],
        k: int = 5,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """
        Execute native hybrid search combining query vector and query text.
        Returns (results_list, latency_ms).
        """
        t0 = time.perf_counter()
        if self.table is None:
            return [], (time.perf_counter() - t0) * 1000.0

        try:
            raw_results = (
                self.table.search(query_type="hybrid")
                .vector(query_vector)
                .text(query_str)
                .limit(k)
                .to_list()
            )
        except Exception:
            # Fallback to pure vector search if FTS query string parsing fails
            raw_results = (
                self.table.search(query_vector)
                .limit(k)
                .to_list()
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        results: List[Tuple[Evidence, float]] = []
        for i, row in enumerate(raw_results):
            eid = row.get("evidence_id")
            ev = self._evidence_map.get(eid)
            if not ev:
                ev = Evidence(
                    evidence_id=eid,
                    source_id=row.get("source_id"),
                    content=row.get("content"),
                    content_hash=row.get("content_hash"),
                    source_path=row.get("source_path"),
                    chunk_index=row.get("chunk_index"),
                    start_offset=row.get("start_offset"),
                    end_offset=row.get("end_offset"),
                    metadata=json.loads(row.get("metadata", "{}")),
                    created_at=row.get("created_at"),
                )
            # Use rank inverse score for standard sorting
            score = 1.0 / (1.0 + i)
            results.append((ev, score))

        return results, elapsed_ms

    def close(self):
        pass
