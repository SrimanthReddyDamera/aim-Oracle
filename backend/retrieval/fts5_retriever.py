"""
ORACLE Candidate A: SQLite FTS5 Lexical Retriever
Pure standard library implementation of BM25 full-text search.
Zero external pip dependencies.
Implements the generic EvidenceProvider interface (Brick 3.4).
"""

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.db.migrator import run_migrations
from backend.evidence.models import Evidence
from backend.retrieval.provider import EvidenceProvider, ProviderCapability, ProviderSearchResult


class SQLiteFTS5Retriever(EvidenceProvider):
    """
    Candidate A: Pure lexical BM25 search over normalized Evidence chunks.
    Uses SQLite's built-in FTS5 engine with porter stemming.
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self._init_schema()

    @property
    def provider_id(self) -> str:
        return "sqlite_fts5"

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.LEXICAL_SEARCH, ProviderCapability.LOCAL_CACHE}

    def health_check(self) -> bool:
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT 1;")
            return cur.fetchone() is not None
        except Exception:
            return False

    def _init_schema(self):
        # Delegate table & FTS creation to idempotent migration runner
        run_migrations(target=self.conn)

    def index_evidence(self, evidence_list: List[Evidence]) -> float:
        """
        Populate tables with Evidence chunks. Returns index build time in ms.
        """
        t0 = time.perf_counter()
        with self.conn:
            self.conn.execute("DELETE FROM evidence_fts;")
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

            fts_rows = [(e.evidence_id, e.source_id, e.content) for e in evidence_list]
            self.conn.executemany(
                "INSERT INTO evidence_fts (evidence_id, source_id, content) VALUES (?, ?, ?);",
                fts_rows,
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return elapsed_ms

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        """
        Execute BM25 search. Returns (results_list, latency_ms).
        Results format: [(Evidence, score)] ordered by score descending.
        """
        t0 = time.perf_counter()
        sanitized = self._sanitize_query(query)
        if not sanitized:
            return [], (time.perf_counter() - t0) * 1000.0

        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                SELECT m.evidence_id, m.source_id, m.content, m.content_hash,
                       m.source_path, m.chunk_index, m.start_offset, m.end_offset,
                       m.metadata, m.created_at, bm25(evidence_fts) as rank
                FROM evidence_fts
                JOIN evidence_metadata m ON evidence_fts.evidence_id = m.evidence_id
                WHERE evidence_fts MATCH ?
                ORDER BY rank ASC
                LIMIT ?;
                """,
                (sanitized, k),
            )
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            fallback_query = " OR ".join(f'"{token}"' for token in sanitized.split() if token)
            try:
                cursor.execute(
                    """
                    SELECT m.evidence_id, m.source_id, m.content, m.content_hash,
                           m.source_path, m.chunk_index, m.start_offset, m.end_offset,
                           m.metadata, m.created_at, bm25(evidence_fts) as rank
                    FROM evidence_fts
                    JOIN evidence_metadata m ON evidence_fts.evidence_id = m.evidence_id
                    WHERE evidence_fts MATCH ?
                    ORDER BY rank ASC
                    LIMIT ?;
                    """,
                    (fallback_query, k),
                )
                rows = cursor.fetchall()
            except sqlite3.OperationalError:
                rows = []

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        results: List[Tuple[Evidence, float]] = []
        for r in rows:
            ev = Evidence(
                evidence_id=r[0],
                source_id=r[1],
                content=r[2],
                content_hash=r[3],
                source_path=r[4],
                chunk_index=r[5],
                start_offset=r[6],
                end_offset=r[7],
                metadata=json.loads(r[8]),
                created_at=r[9],
            )
            bm25_score = -float(r[10])
            results.append((ev, bm25_score))

        return results, elapsed_ms

    def search_provider(
        self,
        query: str,
        k: int = 4,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ProviderSearchResult]:
        """EvidenceProvider implementation returning normalized search results."""
        results, _ = self.search(query, k=k)
        return [
            ProviderSearchResult(
                evidence_id=ev.evidence_id,
                source_type="document",
                source_id=ev.source_id,
                content=ev.content,
                score=score,
                metadata=ev.metadata,
                evidence=ev,
            )
            for ev, score in results
        ]

    def _sanitize_query(self, query: str) -> str:
        """Sanitize query string to avoid FTS5 syntax errors while preserving keywords."""
        tokens = re.findall(r"[A-Za-z0-9_\.\-]+", query)
        if not tokens:
            return ""
        sanitized_tokens = [f'"{t}"' for t in tokens if len(t) > 1]
        return " OR ".join(sanitized_tokens)

    def close(self):
        self.conn.close()
