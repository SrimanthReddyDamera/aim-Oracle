-- 001_bootstrap_fts5_schema.sql
-- Baseline bootstrap migration for ORACLE core evidence storage & FTS5 index

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

CREATE INDEX IF NOT EXISTS idx_evidence_source_id ON evidence_metadata(source_id);
CREATE INDEX IF NOT EXISTS idx_evidence_content_hash ON evidence_metadata(content_hash);

CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(
    evidence_id UNINDEXED,
    source_id UNINDEXED,
    content,
    tokenize = 'porter unicode61'
);
