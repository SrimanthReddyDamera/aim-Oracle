"""
Unit Tests for ORACLE Database Migrator (Bootstrap & Idempotency)
"""

import sqlite3
import tempfile
from pathlib import Path
import pytest

from backend.db.migrator import run_migrations, get_default_migrations_dir


def test_migrations_directory_exists():
    migrations_dir = get_default_migrations_dir()
    assert migrations_dir.exists(), f"Migrations directory should exist at {migrations_dir}"
    sql_files = list(migrations_dir.glob("*.sql"))
    assert len(sql_files) >= 1, "At least one bootstrap migration must be present"


def test_run_migrations_bootstrap_and_idempotency_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test_oracle.db")
        migrations_dir = get_default_migrations_dir()

        # 1. First run: should apply the bootstrap migration
        applied_1 = run_migrations(target=db_path, migrations_dir=migrations_dir)
        assert len(applied_1) >= 1
        assert "001_bootstrap_fts5_schema.sql" in applied_1

        # Verify tables actually exist in SQLite
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "evidence_metadata" in tables
        assert "evidence_fts" in tables
        assert "schema_migrations" in tables

        # 2. Second run: should be completely idempotent (0 newly applied)
        applied_2 = run_migrations(target=db_path, migrations_dir=migrations_dir)
        assert len(applied_2) == 0, "Second migration run should apply 0 migrations (idempotent)"


def test_run_migrations_connection_object():
    conn = sqlite3.connect(":memory:")
    migrations_dir = get_default_migrations_dir()

    applied = run_migrations(target=conn, migrations_dir=migrations_dir)
    assert len(applied) >= 1

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cursor.fetchall()}

    assert "evidence_metadata" in tables
    assert "evidence_fts" in tables
    assert "schema_migrations" in tables

    # Re-run on same connection: 0 applied
    applied_again = run_migrations(target=conn, migrations_dir=migrations_dir)
    assert len(applied_again) == 0
    conn.close()
