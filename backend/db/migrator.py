"""
ORACLE Database Migration Runner (Bootstrap & Evolution)
Ensures database tables, full-text indexes, and schemas are initialized idempotently on application startup.
"""

import datetime
import logging
import sqlite3
from pathlib import Path
from typing import List, Optional, Union

logger = logging.getLogger("oracle.migrator")


def get_default_migrations_dir() -> Path:
    """Find the root migrations directory relative to this file."""
    current = Path(__file__).resolve().parent
    project_root = current.parent.parent
    return project_root / "migrations"


def run_migrations(
    target: Union[str, Path, sqlite3.Connection],
    migrations_dir: Optional[Path] = None,
) -> List[str]:
    """
    Execute pending migrations against the target SQLite database.
    Supports either a database file path (str/Path) or an existing sqlite3.Connection (e.g. in-memory).
    Idempotent:
      - Skips already-applied migrations instantly.
      - Executes new migrations inside an atomic transaction.
      - Creates 'schema_migrations' tracking table if missing.

    Returns:
      List of newly applied migration names.
    """
    if migrations_dir is None:
        migrations_dir = get_default_migrations_dir()

    if not migrations_dir.exists():
        raise FileNotFoundError(f"Migrations directory not found at: {migrations_dir}")

    is_conn_passed = isinstance(target, sqlite3.Connection)
    if is_conn_passed:
        conn = target
    else:
        db_path = str(target)
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)

    applied_now: List[str] = []

    try:
        cursor = conn.cursor()

        # 1. Ensure schema_migrations table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
        """)
        conn.commit()

        # 2. Get list of already applied versions
        cursor.execute("SELECT version FROM schema_migrations;")
        applied_versions = {row[0] for row in cursor.fetchall()}

        # 3. Read and sort all .sql migration files
        sql_files = sorted(migrations_dir.glob("*.sql"))

        for sql_file in sql_files:
            version = sql_file.name.split("_")[0]
            if version in applied_versions:
                continue

            sql_content = sql_file.read_text(encoding="utf-8")

            # Execute migration script in transaction
            cursor.executescript(sql_content)

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?);",
                (version, sql_file.name, now_iso),
            )
            conn.commit()
            applied_now.append(sql_file.name)
            logger.info(f"Applied database migration: {sql_file.name}")

    finally:
        if not is_conn_passed:
            conn.close()

    return applied_now
