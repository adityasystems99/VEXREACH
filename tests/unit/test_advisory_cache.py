"""Unit tests for SQLiteAdvisoryCache TTL, modified_at invalidation, and tamper detection."""

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from packages.core.integrations.osv.schemas import OSVVulnerabilityStub
from packages.core.storage.advisory_cache import SQLiteAdvisoryCache


@pytest.mark.unit
def test_cache_hit_modified_invalidation_and_ttl_expiry(tmp_path: Path) -> None:
    """Cache serves valid entries, invalidates on modified mismatch, and expires after TTL."""
    db_path = tmp_path / "cache.db"
    cache = SQLiteAdvisoryCache(db_path=db_path, ttl_seconds=60)
    t0 = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
    payload = {"id": "GHSA-test-1234", "modified": "2026-10-01T00:00:00Z", "summary": "Test"}

    cache.put_advisory("GHSA-test-1234", "2026-10-01T00:00:00Z", payload, retrieved_at=t0)

    # Fresh hit matching modified_at
    hit = cache.get_advisory(
        "GHSA-test-1234",
        expected_modified="2026-10-01T00:00:00Z",
        now=t0 + timedelta(seconds=30),
    )
    assert hit is not None
    assert hit[0].id == "GHSA-test-1234"

    # Upstream modified timestamp changed -> cache miss
    stale_mod = cache.get_advisory(
        "GHSA-test-1234",
        expected_modified="2026-11-01T00:00:00Z",
        now=t0 + timedelta(seconds=30),
    )
    assert stale_mod is None

    # Expired TTL -> cache miss (never treats stale expired entry as current)
    expired = cache.get_advisory(
        "GHSA-test-1234",
        expected_modified="2026-10-01T00:00:00Z",
        now=t0 + timedelta(seconds=61),
    )
    assert expired is None

    # Force refresh -> bypasses cache
    refreshed = cache.get_advisory(
        "GHSA-test-1234",
        expected_modified="2026-10-01T00:00:00Z",
        force_refresh=True,
        now=t0 + timedelta(seconds=5),
    )
    assert refreshed is None


@pytest.mark.unit
def test_cache_detects_tampering_and_evicts_corrupted_entry(tmp_path: Path) -> None:
    """Tampered raw_json failing SHA-256 verification is evicted cleanly."""
    db_path = tmp_path / "cache.db"
    cache = SQLiteAdvisoryCache(db_path=db_path, ttl_seconds=3600)
    payload = {"id": "CVE-2023-9999", "modified": "2026-01-01T00:00:00Z", "summary": "Original"}
    cache.put_advisory("CVE-2023-9999", "2026-01-01T00:00:00Z", payload)

    # Simulate database tampering without updating sha256
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "UPDATE osv_advisories SET raw_json = ? WHERE advisory_id = ?",
            ('{"id":"CVE-2023-9999","summary":"Tampered"}', "CVE-2023-9999"),
        )
        conn.commit()

    assert cache.get_advisory("CVE-2023-9999") is None


@pytest.mark.unit
def test_package_stubs_cache_and_invalidation(tmp_path: Path) -> None:
    """Package query stubs cache round-trip and clear cleanly."""
    cache = SQLiteAdvisoryCache(db_path=tmp_path / "cache.db", ttl_seconds=300)
    stubs = [OSVVulnerabilityStub(id="GHSA-1", modified="2026-01-01T00:00:00Z")]
    cache.put_package_stubs("purl:pkg:pypi/requests@2.28.1", stubs)

    loaded = cache.get_package_stubs("purl:pkg:pypi/requests@2.28.1")
    assert loaded is not None
    assert loaded[0].id == "GHSA-1"

    cache.clear()
    assert cache.get_package_stubs("purl:pkg:pypi/requests@2.28.1") is None
