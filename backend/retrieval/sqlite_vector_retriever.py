"""
ORACLE Candidate B: SQLite + Local Dense Vector Retriever
Uses SQLite for persistent storage and in-process NumPy for BLAS-accelerated cosine similarity.
Zero external C-extension compilation required on Windows.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from backend.evidence.models import Evidence


class SQLiteVectorRetriever:
    """
    Candidate B: Dense semantic vector search over normalized Evidence chunks.
    Metadata stored in SQLite; vectors evaluated in-memory via NumPy dot products.
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self._init_schema()

        # In-memory matrix cache for zero-latency dot products
        self._evidence_map: Dict[str, Evidence] = {}
        self._matrix_norm: Optional[np.ndarray] = None
        self._id_list: List[str] = []

    def _init_schema(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_metadata (
                    evidence_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    start_offset INTEGER NOT NULL,
                    end_offset INTEGER NOT NULL,
                    metadata JSON NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_vectors (
                    evidence_id TEXT PRIMARY KEY,
                    vector BLOB NOT NULL,
                    FOREIGN KEY(evidence_id) REFERENCES evidence_metadata(evidence_id)
                );
            """)

    def index_evidence(
        self,
        evidence_list: List[Evidence],
        embeddings_dict: Dict[str, List[float]],
    ) -> float:
        """
        Ingest Evidence chunks and corresponding dense vectors.
        Builds normalized in-memory matrix cache. Returns index build time in ms.
        """
        t0 = time.perf_counter()
        with self.conn:
            self.conn.execute("DELETE FROM evidence_vectors;")
            self.conn.execute("DELETE FROM evidence_metadata;")

            meta_rows = [
                (
                    e.evidence_id,
                    e.source_id,
                    e.content,
                    e.content_hash,
                    e.source_path,
                    e.chunk_index,
                    e.start_offset,
                    e.end_offset,
                    json.dumps(e.metadata),
                    e.created_at,
                )
                for e in evidence_list
            ]
            self.conn.executemany(
                """
                INSERT INTO evidence_metadata (
                    evidence_id, source_id, content, content_hash, source_path,
                    chunk_index, start_offset, end_offset, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                meta_rows,
            )

            vec_rows = []
            ordered_ids = []
            raw_matrix = []

            for e in evidence_list:
                vec = embeddings_dict.get(e.evidence_id)
                if vec is None:
                    raise ValueError(f"Missing embedding for evidence_id: {e.evidence_id}")
                arr = np.array(vec, dtype=np.float32)
                vec_rows.append((e.evidence_id, arr.tobytes()))
                ordered_ids.append(e.evidence_id)
                raw_matrix.append(arr)
                self._evidence_map[e.evidence_id] = e

            self.conn.executemany(
                "INSERT INTO evidence_vectors (evidence_id, vector) VALUES (?, ?);",
                vec_rows,
            )

        # Build L2-normalized in-memory matrix for fast cosine similarity
        matrix = np.vstack(raw_matrix)
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1e-10
        self._matrix_norm = matrix / norms
        self._id_list = ordered_ids

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return elapsed_ms

    def search(
        self,
        query_vector: List[float],
        k: int = 5,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """
        Execute dense vector cosine similarity search. Returns (results_list, latency_ms).
        Results format: [(Evidence, cosine_similarity)] ordered by score descending.
        """
        t0 = time.perf_counter()
        if self._matrix_norm is None or len(self._id_list) == 0:
            return [], (time.perf_counter() - t0) * 1000.0

        q_arr = np.array(query_vector, dtype=np.float32)
        q_norm = np.linalg.norm(q_arr)
        if q_norm == 0:
            return [], (time.perf_counter() - t0) * 1000.0

        q_unit = q_arr / q_norm

        # Vector dot product: (N, D) @ (D,) -> (N,) cosine scores
        scores = np.dot(self._matrix_norm, q_unit)

        # Top-K sorting
        actual_k = min(k, len(scores))
        top_indices = np.argsort(scores)[::-1][:actual_k]

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        results: List[Tuple[Evidence, float]] = []
        for idx in top_indices:
            eid = self._id_list[idx]
            score = float(scores[idx])
            results.append((self._evidence_map[eid], score))

        return results, elapsed_ms

    def close(self):
        self.conn.close()
