"""SQLite-backed local cache for OSV advisories and package query stubs."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from packages.core.integrations.osv.schemas import OSVVulnerability, OSVVulnerabilityStub
from packages.core.utils.logging import get_logger

logger = get_logger("storage.advisory_cache")


def _sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _parse_utc(raw: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


class SQLiteAdvisoryCache:
    """Thread-safe, integrity-checked SQLite cache for OSV responses."""

    def __init__(self, db_path: Path, ttl_seconds: int = 86400) -> None:
        self.db_path = db_path
        self.ttl_seconds = max(0, ttl_seconds)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS osv_advisories (
                    advisory_id TEXT PRIMARY KEY,
                    modified_at TEXT,
                    retrieved_at TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    sha256 TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS osv_package_queries (
                    query_key TEXT PRIMARY KEY,
                    retrieved_at TEXT NOT NULL,
                    stubs_json TEXT NOT NULL,
                    sha256 TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def get_advisory(
        self,
        advisory_id: str,
        expected_modified: str | None = None,
        force_refresh: bool = False,
        now: datetime | None = None,
    ) -> tuple[OSVVulnerability, dict[str, Any], datetime] | None:
        """Retrieve a cached OSV advisory if valid, unexpired, untampered, and matching modified_at."""
        if force_refresh or self.ttl_seconds == 0:
            return None

        current_time = now or datetime.now(timezone.utc)
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT advisory_id, modified_at, retrieved_at, raw_json, sha256 "
                "FROM osv_advisories WHERE advisory_id = ?",
                (advisory_id,),
            ).fetchone()

            if row is None:
                return None

            raw_json = str(row["raw_json"])
            stored_hash = str(row["sha256"])
            if _sha256_text(raw_json) != stored_hash:
                logger.warning("Corrupted/tampered cache entry for '%s'; evicting.", advisory_id)
                conn.execute("DELETE FROM osv_advisories WHERE advisory_id = ?", (advisory_id,))
                conn.commit()
                return None

            retrieved_dt = _parse_utc(str(row["retrieved_at"]))
            if retrieved_dt is None:
                conn.execute("DELETE FROM osv_advisories WHERE advisory_id = ?", (advisory_id,))
                conn.commit()
                return None

            age_seconds = (current_time - retrieved_dt).total_seconds()
            if age_seconds > self.ttl_seconds:
                return None

            if expected_modified is not None and row["modified_at"] != expected_modified:
                return None

            try:
                raw_dict = json.loads(raw_json)
                parsed = OSVVulnerability.model_validate(raw_dict)
            except (json.JSONDecodeError, ValidationError):
                conn.execute("DELETE FROM osv_advisories WHERE advisory_id = ?", (advisory_id,))
                conn.commit()
                return None

            return parsed, raw_dict, retrieved_dt

    def put_advisory(
        self,
        advisory_id: str,
        modified_at: str | None,
        raw_payload: dict[str, Any],
        retrieved_at: datetime | None = None,
    ) -> None:
        """Persist raw OSV advisory JSON and integrity hash into SQLite cache."""
        ts = retrieved_at or datetime.now(timezone.utc)
        serialized = json.dumps(raw_payload, separators=(",", ":"), sort_keys=True)
        digest = _sha256_text(serialized)

        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO osv_advisories
                    (advisory_id, modified_at, retrieved_at, raw_json, sha256)
                VALUES (?, ?, ?, ?, ?)
                """,
                (advisory_id, modified_at, ts.isoformat(), serialized, digest),
            )
            conn.commit()

    def get_package_stubs(
        self,
        query_key: str,
        force_refresh: bool = False,
        now: datetime | None = None,
    ) -> list[OSVVulnerabilityStub] | None:
        """Retrieve cached OSV querybatch stubs for a package query key if fresh."""
        if force_refresh or self.ttl_seconds == 0:
            return None

        current_time = now or datetime.now(timezone.utc)
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT retrieved_at, stubs_json, sha256 FROM osv_package_queries WHERE query_key = ?",
                (query_key,),
            ).fetchone()

            if row is None:
                return None

            stubs_json = str(row["stubs_json"])
            if _sha256_text(stubs_json) != str(row["sha256"]):
                conn.execute("DELETE FROM osv_package_queries WHERE query_key = ?", (query_key,))
                conn.commit()
                return None

            retrieved_dt = _parse_utc(str(row["retrieved_at"]))
            if retrieved_dt is None or (current_time - retrieved_dt).total_seconds() > self.ttl_seconds:
                return None

            try:
                raw_list = json.loads(stubs_json)
                if not isinstance(raw_list, list):
                    return None
                return [OSVVulnerabilityStub.model_validate(item) for item in raw_list]
            except (json.JSONDecodeError, ValidationError):
                conn.execute("DELETE FROM osv_package_queries WHERE query_key = ?", (query_key,))
                conn.commit()
                return None

    def put_package_stubs(
        self,
        query_key: str,
        stubs: list[OSVVulnerabilityStub],
        retrieved_at: datetime | None = None,
    ) -> None:
        """Store package query stubs in SQLite cache with integrity digest."""
        ts = retrieved_at or datetime.now(timezone.utc)
        serialized = json.dumps(
            [s.model_dump() for s in stubs],
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = _sha256_text(serialized)
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO osv_package_queries
                    (query_key, retrieved_at, stubs_json, sha256)
                VALUES (?, ?, ?, ?)
                """,
                (query_key, ts.isoformat(), serialized, digest),
            )
            conn.commit()

    def invalidate_advisory(self, advisory_id: str) -> None:
        """Remove a specific advisory from the cache."""
        with closing(self._connect()) as conn:
            conn.execute("DELETE FROM osv_advisories WHERE advisory_id = ?", (advisory_id,))
            conn.commit()

    def clear(self) -> None:
        """Remove all cached advisories and package query entries."""
        with closing(self._connect()) as conn:
            conn.execute("DELETE FROM osv_advisories")
            conn.execute("DELETE FROM osv_package_queries")
            conn.commit()
