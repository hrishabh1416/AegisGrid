"""AegisGrid Asynchronous Database Manager.

Provides non-blocking persistence for telemetry logs using ``aiosqlite``
for the local SQLite fallback and ``asyncio.to_thread`` for the synchronous
Supabase Python SDK.

Architecture
------------
- **Primary**: Supabase cloud (when ``SUPABASE_URL`` + ``SUPABASE_KEY`` are set).
- **Fallback**: Local SQLite via ``aiosqlite`` (always initialised so the
  system degrades gracefully if Supabase is unreachable).

Exports
-------
- :class:`DatabaseManager` — async CRUD façade.
- ``db_manager`` — module-level singleton ready for import.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import aiosqlite

from app.core.config import settings

logger = logging.getLogger("aegisgrid.database")


class DatabaseManager:
    """Async-first database façade with Supabase-primary / SQLite-fallback.

    All public methods are coroutines so the FastAPI event loop is never
    blocked by I/O.
    """

    def __init__(self) -> None:
        self.use_sqlite: bool = True
        self.supabase_client: Optional[Any] = None
        self._sqlite_path: str = settings.local_sqlite_path

        # ── Attempt Supabase connection ─────────────────────────────────
        if settings.supabase_url and settings.supabase_key:
            try:
                from supabase import create_client  # type: ignore[import-untyped]

                self.supabase_client = create_client(
                    settings.supabase_url, settings.supabase_key
                )
                self.use_sqlite = False
                logger.info("Connected to Supabase Cloud Database.")
            except Exception:
                logger.exception(
                    "Failed to connect to Supabase — falling back to SQLite."
                )
        else:
            logger.info(
                "Supabase credentials not configured. Using local SQLite at '%s'.",
                self._sqlite_path,
            )

    # ── Bootstrap ───────────────────────────────────────────────────────

    async def init_sqlite(self) -> None:
        """Create the telemetry_logs table and index if they don't exist.

        Called once during application startup (``lifespan`` context).
        """
        async with aiosqlite.connect(self._sqlite_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_logs (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL,
                    source_asset    TEXT    NOT NULL,
                    user_principal  TEXT    NOT NULL,
                    bytes_transferred INTEGER NOT NULL,
                    anomaly_score   REAL    NOT NULL,
                    status          TEXT    NOT NULL
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_telemetry_source_timestamp
                ON telemetry_logs (source_asset, timestamp);
                """
            )
            await db.commit()
        logger.info("SQLite schema verified at '%s'.", self._sqlite_path)

    # ── Write ───────────────────────────────────────────────────────────

    async def insert_log(
        self, parsed_log: dict, score: float, status: str
    ) -> None:
        """Persist a single telemetry record.

        Attempts Supabase first; on failure, falls back to local SQLite.
        """
        record = {
            "timestamp": parsed_log["timestamp"].isoformat(),
            "source_asset": parsed_log["source_asset"],
            "user_principal": parsed_log["user_principal"],
            "bytes_transferred": parsed_log["bytes_transferred"],
            "anomaly_score": score,
            "status": status,
        }

        if not self.use_sqlite and self.supabase_client:
            try:
                await asyncio.to_thread(
                    lambda: self.supabase_client.table("telemetry_logs")
                    .insert(record)
                    .execute()
                )
                logger.debug("Log inserted into Supabase.")
                return
            except Exception:
                logger.exception(
                    "Supabase insert failed — falling back to SQLite."
                )

        async with aiosqlite.connect(self._sqlite_path) as db:
            await db.execute(
                """
                INSERT INTO telemetry_logs
                    (timestamp, source_asset, user_principal,
                     bytes_transferred, anomaly_score, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record["timestamp"],
                    record["source_asset"],
                    record["user_principal"],
                    record["bytes_transferred"],
                    record["anomaly_score"],
                    record["status"],
                ),
            )
            await db.commit()
        logger.debug("Log inserted into SQLite.")

    # ── Delete ──────────────────────────────────────────────────────────

    async def clear_logs(self) -> None:
        """Truncate all telemetry log records from both backends."""
        if not self.use_sqlite and self.supabase_client:
            try:
                await asyncio.to_thread(
                    lambda: self.supabase_client.table("telemetry_logs")
                    .delete()
                    .neq("id", -1)
                    .execute()
                )
                logger.info("Supabase telemetry_logs cleared.")
            except Exception:
                logger.exception("Supabase delete failed.")

        async with aiosqlite.connect(self._sqlite_path) as db:
            await db.execute("DELETE FROM telemetry_logs;")
            await db.commit()
        logger.info("SQLite telemetry_logs cleared.")

    # ── Read ────────────────────────────────────────────────────────────

    async def get_total_logs_count(self) -> int:
        """Return the total number of stored telemetry records."""
        if not self.use_sqlite and self.supabase_client:
            try:
                res = await asyncio.to_thread(
                    lambda: self.supabase_client.table("telemetry_logs")
                    .select("id", count="exact")
                    .execute()
                )
                return res.count if res.count is not None else 0
            except Exception:
                logger.exception("Supabase count query failed.")

        async with aiosqlite.connect(self._sqlite_path) as db:
            async with db.execute(
                "SELECT COUNT(*) FROM telemetry_logs;"
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0

    async def get_recent_anomalies(
        self, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Fetch the most recent critical-anomaly records.

        Parameters
        ----------
        limit:
            Maximum number of rows to return (default 10).
        """
        if not self.use_sqlite and self.supabase_client:
            try:
                res = await asyncio.to_thread(
                    lambda: self.supabase_client.table("telemetry_logs")
                    .select("*")
                    .eq("status", "CRITICAL_ANOMALY")
                    .order("timestamp", desc=True)
                    .limit(limit)
                    .execute()
                )
                return res.data
            except Exception:
                logger.exception("Supabase anomaly query failed.")

        async with aiosqlite.connect(self._sqlite_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT * FROM telemetry_logs
                WHERE status = 'CRITICAL_ANOMALY'
                ORDER BY timestamp DESC
                LIMIT ?;
                """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]


# ── Module-level singleton ──────────────────────────────────────────────────
db_manager = DatabaseManager()
