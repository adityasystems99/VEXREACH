"""Bounded, optional EPSS and CISA KEV threat-feed adapters for Risk Intelligence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from packages.core.config.settings import Settings, get_settings


@dataclass(frozen=True)
class EPSSRecord:
    """EPSS probability & percentile returned by FIRST.org."""

    cve_id: str
    epss: float
    percentile: float


@dataclass(frozen=True)
class KEVEntry:
    """Entry parsed from the official CISA Known Exploited Vulnerabilities catalog."""

    cve_id: str
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware_use: str | None = None


@dataclass
class ThreatFeedSnapshot:
    """Normalized EPSS & CISA KEV lookup tables plus non-fatal retrieval warnings."""

    epss_by_cve: dict[str, EPSSRecord] = field(default_factory=dict)
    kev_by_cve: dict[str, KEVEntry] = field(default_factory=dict)
    kev_loaded: bool = False
    warnings: list[str] = field(default_factory=list)


class ThreatFeedClient:
    """Fetches EPSS scores and CISA KEV entries safely with local file or HTTP transport support."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(self._settings.threat_feed_timeout_seconds),
            headers={"User-Agent": self._settings.osv_user_agent, "Accept": "application/json"},
            follow_redirects=False,
        )

    def __enter__(self) -> "ThreatFeedClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def load_snapshot(
        self,
        cve_ids: list[str],
        *,
        epss_file: Path | None = None,
        kev_file: Path | None = None,
        fetch_remote: bool = False,
    ) -> ThreatFeedSnapshot:
        """Load EPSS and CISA KEV records from local snapshots and/or remote feeds cleanly."""
        snap = ThreatFeedSnapshot()
        norm_cves = sorted({c.strip().upper() for c in cve_ids if c.strip().upper().startswith("CVE-")})

        if kev_file is not None:
            self._load_kev_from_file(kev_file, snap)
        elif fetch_remote:
            self._fetch_kev_remote(snap)

        if epss_file is not None:
            self._load_epss_from_file(epss_file, snap)
        elif fetch_remote and norm_cves:
            self._fetch_epss_remote(norm_cves, snap)

        return snap

    def _load_kev_from_file(self, path: Path, snap: ThreatFeedSnapshot) -> None:
        if not path.is_file():
            snap.warnings.append(f"KEV catalog file not found: {path}")
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            self._parse_kev_payload(payload, snap)
        except (OSError, ValueError, KeyError) as exc:
            snap.warnings.append(f"Failed parsing local KEV catalog '{path}': {exc}")

    def _fetch_kev_remote(self, snap: ThreatFeedSnapshot) -> None:
        try:
            resp = self._client.get(self._settings.kev_catalog_url)
            if len(resp.content) > self._settings.threat_feed_max_bytes:
                snap.warnings.append("KEV response exceeded configured size bound.")
                return
            if resp.status_code >= 400:
                snap.warnings.append(f"CISA KEV HTTP {resp.status_code}")
                return
            self._parse_kev_payload(resp.json(), snap)
        except (httpx.HTTPError, ValueError) as exc:
            snap.warnings.append(f"Unable to reach CISA KEV catalog cleanly: {exc}")

    @staticmethod
    def _parse_kev_payload(payload: Any, snap: ThreatFeedSnapshot) -> None:
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            snap.warnings.append("KEV catalog JSON missing 'vulnerabilities' array.")
            return
        for row in payload["vulnerabilities"]:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cveID", "")).strip().upper()
            if not cve:
                continue
            snap.kev_by_cve[cve] = KEVEntry(
                cve_id=cve,
                date_added=row.get("dateAdded"),
                due_date=row.get("dueDate"),
                known_ransomware_use=row.get("knownRansomwareCampaignUse"),
            )
        snap.kev_loaded = True

    def _load_epss_from_file(self, path: Path, snap: ThreatFeedSnapshot) -> None:
        if not path.is_file():
            snap.warnings.append(f"EPSS snapshot file not found: {path}")
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            self._parse_epss_payload(payload, snap)
        except (OSError, ValueError) as exc:
            snap.warnings.append(f"Failed parsing local EPSS JSON '{path}': {exc}")

    def _fetch_epss_remote(self, cve_ids: list[str], snap: ThreatFeedSnapshot) -> None:
        for idx in range(0, len(cve_ids), 50):
            chunk = cve_ids[idx : idx + 50]
            try:
                resp = self._client.get(
                    self._settings.epss_api_url,
                    params={"cve": ",".join(chunk)},
                )
                if len(resp.content) > self._settings.threat_feed_max_bytes:
                    snap.warnings.append("EPSS response exceeded configured size bound.")
                    return
                if resp.status_code >= 400:
                    snap.warnings.append(f"EPSS API HTTP {resp.status_code}")
                    return
                self._parse_epss_payload(resp.json(), snap)
            except (httpx.HTTPError, ValueError) as exc:
                snap.warnings.append(f"Unable to reach EPSS API cleanly: {exc}")
                return

    @staticmethod
    def _parse_epss_payload(payload: Any, snap: ThreatFeedSnapshot) -> None:
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            snap.warnings.append("EPSS response JSON missing 'data' list.")
            return
        for row in payload["data"]:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).strip().upper()
            if not cve:
                continue
            try:
                epss_val = min(1.0, max(0.0, float(row.get("epss", 0.0))))
                pct_val = min(1.0, max(0.0, float(row.get("percentile", 0.0))))
            except (TypeError, ValueError):
                continue
            snap.epss_by_cve[cve] = EPSSRecord(
                cve_id=cve, epss=epss_val, percentile=pct_val
            )
