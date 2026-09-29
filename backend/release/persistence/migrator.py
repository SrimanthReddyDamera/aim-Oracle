"""
Versioned Database Migrator for ORACLE (Brick 4.4)

Applies schema migrations idempotently for SQLite and PostgreSQL.
Preserves auditability of database migrations.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from typing import Any, List, Optional, Tuple

from backend.release.persistence.schema import (
    POSTGRES_SCHEMA_V1,
    POSTGRES_SCHEMA_V2,
    SQLITE_SCHEMA_V1,
    SQLITE_SCHEMA_V2,
)

logger = logging.getLogger("oracle.persistence.migrator")


class DatabaseMigrator:
    """Manages schema migrations and version tracking for relational storage."""

    MIGRATIONS: List[Tuple[int, str, List[str], List[str]]] = [
        (1, "v1_control_plane_core", SQLITE_SCHEMA_V1, POSTGRES_SCHEMA_V1),
        (2, "v2_operational_distributed", SQLITE_SCHEMA_V2, POSTGRES_SCHEMA_V2),
    ]

    def __init__(self, is_postgres: bool = False):
        self.is_postgres = is_postgres

    def apply_sqlite_migrations(self, conn: sqlite3.Connection) -> List[int]:
        """Apply all pending migrations to an SQLite connection."""
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            """
        )
        conn.commit()

        cursor.execute("SELECT version FROM schema_migrations;")
        applied_versions = {row[0] for row in cursor.fetchall()}

        newly_applied = []
        for version, name, sqlite_ddl, _ in self.MIGRATIONS:
            if version not in applied_versions:
                logger.info(f"Applying SQLite migration {version}: {name}")
                for statement in sqlite_ddl:
                    stmt = statement.strip()
                    if stmt:
                        try:
                            cursor.execute(stmt)
                        except sqlite3.OperationalError as e:
                            # Ignore duplicate column name when re-adding or testing against migrated DBs
                            if "duplicate column name" in str(e).lower():
                                pass
                            else:
                                raise
                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                cursor.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?);",
                    (version, name, now_iso),
                )
                conn.commit()
                newly_applied.append(version)

        return newly_applied

    def apply_postgres_migrations(self, conn: Any) -> List[int]:
        """Apply all pending migrations to a PostgreSQL connection."""
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name VARCHAR(128) NOT NULL,
                    applied_at VARCHAR(64) NOT NULL
                );
                """
            )
            conn.commit()

            cursor.execute("SELECT version FROM schema_migrations;")
            applied_versions = {row[0] for row in cursor.fetchall()}

            newly_applied = []
            for version, name, _, pg_ddl in self.MIGRATIONS:
                if version not in applied_versions:
                    logger.info(f"Applying PostgreSQL migration {version}: {name}")
                    for statement in pg_ddl:
                        stmt = statement.strip()
                        if stmt:
                            cursor.execute(stmt)
                    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    cursor.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (%s, %s, %s);",
                        (version, name, now_iso),
                    )
                    conn.commit()
                    newly_applied.append(version)

            return newly_applied

    def apply_migrations(self, conn: Any) -> List[int]:
        """Convenience dispatcher to apply pending migrations based on backend type."""
        if self.is_postgres:
            return self.apply_postgres_migrations(conn)
        return self.apply_sqlite_migrations(conn)

    def get_status(self, conn: Any) -> Dict[str, Any]:
        """Inspect and return schema version status and applied/pending migrations."""
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC;")
            applied_rows = cursor.fetchall()
            applied_map = {row[0]: {"version": row[0], "name": row[1], "applied_at": row[2]} for row in applied_rows}
        except Exception:
            applied_map = {}

        max_available = max(m[0] for m in self.MIGRATIONS) if self.MIGRATIONS else 0
        current_version = max(applied_map.keys()) if applied_map else 0

        pending = []
        for v, name, _, _ in self.MIGRATIONS:
            if v not in applied_map:
                pending.append({"version": v, "name": name})

        return {
            "backend": "PostgreSQL" if self.is_postgres else "SQLite",
            "current_version": current_version,
            "target_version": max_available,
            "is_up_to_date": current_version >= max_available,
            "applied_count": len(applied_map),
            "pending_count": len(pending),
            "applied_migrations": list(applied_map.values()),
            "pending_migrations": pending,
        }

