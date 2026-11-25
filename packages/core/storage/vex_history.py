"""SQLite-backed historical tracking for emitted OpenVEX documents and statement versions."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packages.core.models.openvex import OpenVEXDocument
from packages.core.utils.safe_path import calculate_file_sha256


class SQLiteVEXStore:
    """Persists and increments historical OpenVEX document versions in SQLite."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vex_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_path TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    status_counts_json TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vex_history_target ON vex_history(target_path, version)"
            )

    def next_version_for_target(self, target_path: str) -> int:
        """Return next monotonic OpenVEX document version number for `target_path`."""
        norm = str(Path(target_path).resolve()) if Path(target_path).exists() else target_path
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(version) AS max_ver FROM vex_history WHERE target_path = ?",
                (norm,),
            ).fetchone()
        max_ver = row["max_ver"] if row and row["max_ver"] is not None else 0
        return int(max_ver) + 1

    def record_document(
        self,
        *,
        target_path: str,
        assessment_id: str,
        document: OpenVEXDocument,
        status_counts: dict[str, int],
        document_file_path: Path | None = None,
    ) -> str:
        """Insert a validated OpenVEX document revision and return its SHA-256 hash."""
        norm = str(Path(target_path).resolve()) if Path(target_path).exists() else target_path
        raw_json = document.to_openvex_json()
        if document_file_path is not None and document_file_path.is_file():
            sha256 = calculate_file_sha256(document_file_path)
        else:
            import hashlib

            sha256 = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vex_history (
                    target_path, assessment_id, document_id, version,
                    content_sha256, status_counts_json, document_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    norm,
                    assessment_id,
                    document.id,
                    document.version,
                    sha256,
                    json.dumps(status_counts, sort_keys=True),
                    raw_json,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return sha256

    def list_history(self, target_path: str) -> list[dict[str, Any]]:
        """List stored OpenVEX document revisions for `target_path` ordered newest first."""
        norm = str(Path(target_path).resolve()) if Path(target_path).exists() else target_path
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT assessment_id, document_id, version, content_sha256, status_counts_json, created_at
                FROM vex_history
                WHERE target_path = ?
                ORDER BY version DESC, id DESC
                """,
                (norm,),
            ).fetchall()
        return [
            {
                "assessment_id": row["assessment_id"],
                "document_id": row["document_id"],
                "version": row["version"],
                "content_sha256": row["content_sha256"],
                "status_counts": json.loads(row["status_counts_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
