"""Bidirectional mapping between VEXReach canonical models and OSV.dev v1 API schemas."""

from datetime import datetime, timezone
from typing import Any

from packages.core.engines.discovery.normalizer import parse_purl
from packages.core.integrations.osv.schemas import OSVAffected, OSVVulnerability
from packages.core.models.intelligence import (
    AdvisoryRecord,
    AdvisoryReference,
    AffectedPackageRange,
    OSVRangeType,
    RangeEvent,
    SeverityInfo,
)

# Official OSV schema ecosystem identifiers (case-sensitive on api.osv.dev)
_TO_OSV_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "golang": "Go",
    "npm": "npm",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "apk": "Alpine",
    "deb": "Debian",
    "rpm": "Red Hat",
}

_FROM_OSV_ECOSYSTEM: dict[str, str] = {
    "pypi": "pypi",
    "go": "golang",
    "npm": "npm",
    "crates.io": "cargo",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "gem",
    "packagist": "composer",
    "alpine": "apk",
    "debian": "deb",
    "ubuntu": "deb",
    "red hat": "rpm",
    "rocky linux": "rpm",
    "almalinux": "rpm",
}


def to_osv_ecosystem(canonical_ecosystem: str, purl: str | None = None) -> str | None:
    """Convert VEXReach canonical ecosystem identifier to OSV's exact ecosystem name."""
    cleaned = canonical_ecosystem.strip().lower()
    if not cleaned or cleaned == "unknown":
        return None

    parsed = parse_purl(purl)
    if cleaned == "deb" and parsed and parsed.namespace:
        ns = parsed.namespace.lower()
        if "ubuntu" in ns:
            return "Ubuntu"
        if "debian" in ns:
            return "Debian"
    if cleaned == "rpm" and parsed and parsed.namespace:
        ns = parsed.namespace.lower()
        if "rocky" in ns:
            return "Rocky Linux"
        if "alma" in ns:
            return "AlmaLinux"

    return _TO_OSV_ECOSYSTEM.get(cleaned)


def from_osv_ecosystem(osv_ecosystem: str | None) -> str:
    """Normalize an OSV ecosystem string into VEXReach's canonical ecosystem identifier."""
    if not osv_ecosystem or not osv_ecosystem.strip():
        return "unknown"
    raw = osv_ecosystem.strip()
    # OSV Debian/Alpine entries can include release suffixes like "Debian:12" or "Alpine:v3.19"
    base = raw.split(":", 1)[0].strip().lower()
    return _FROM_OSV_ECOSYSTEM.get(base, raw.lower())


def _parse_osv_timestamp(raw_ts: str | None) -> datetime | None:
    """Parse RFC3339 OSV timestamp into timezone-aware UTC datetime, or None if invalid."""
    if not raw_ts:
        return None
    normalized = raw_ts.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _map_range_type(raw_type: str) -> OSVRangeType:
    upper = raw_type.strip().upper()
    if upper == "SEMVER":
        return OSVRangeType.SEMVER
    if upper == "ECOSYSTEM":
        return OSVRangeType.ECOSYSTEM
    if upper == "GIT":
        return OSVRangeType.GIT
    return OSVRangeType.UNKNOWN


def _map_affected_entry(entry: OSVAffected) -> list[AffectedPackageRange]:
    """Convert an OSV affected item into one AffectedPackageRange per range (preserving events)."""
    raw_eco = entry.package.ecosystem if entry.package and entry.package.ecosystem else "unknown"
    eco = from_osv_ecosystem(raw_eco)
    pkg_name = entry.package.name if entry.package and entry.package.name else "unknown"
    purl = entry.package.purl if entry.package else None

    if not entry.ranges:
        # Preserve explicit affected[].versions even when no ranges array is present
        return [
            AffectedPackageRange(
                ecosystem=eco,
                package_name=pkg_name,
                purl=purl,
                affected_versions=list(entry.versions),
                range_type=OSVRangeType.UNKNOWN,
                ecosystem_specific=dict(entry.ecosystem_specific),
                database_specific=dict(entry.database_specific),
            )
        ]

    mapped_ranges: list[AffectedPackageRange] = []
    for osv_range in entry.ranges:
        events: list[RangeEvent] = []
        introduced: list[str] = []
        fixed: list[str] = []
        last_affected: list[str] = []
        limits: list[str] = []

        for ev in osv_range.events:
            if ev.introduced is not None:
                events.append(RangeEvent(event_type="introduced", value=ev.introduced))
                introduced.append(ev.introduced)
            elif ev.fixed is not None:
                events.append(RangeEvent(event_type="fixed", value=ev.fixed))
                fixed.append(ev.fixed)
            elif ev.last_affected is not None:
                events.append(RangeEvent(event_type="last_affected", value=ev.last_affected))
                last_affected.append(ev.last_affected)
            elif ev.limit is not None:
                events.append(RangeEvent(event_type="limit", value=ev.limit))
                limits.append(ev.limit)

        db_specific = dict(entry.database_specific)
        if osv_range.database_specific:
            db_specific["range_database_specific"] = dict(osv_range.database_specific)

        mapped_ranges.append(
            AffectedPackageRange(
                ecosystem=eco,
                package_name=pkg_name,
                purl=purl,
                affected_versions=list(entry.versions),
                introduced_versions=introduced,
                fixed_versions=fixed,
                last_affected_versions=last_affected,
                limit_versions=limits,
                events=events,
                range_type=_map_range_type(osv_range.type),
                repo=osv_range.repo,
                ecosystem_specific=dict(entry.ecosystem_specific),
                database_specific=db_specific,
            )
        )

    return mapped_ranges


def map_osv_to_advisory(
    osv_vuln: OSVVulnerability,
    retrieved_at: datetime,
    from_cache: bool = False,
) -> AdvisoryRecord:
    """Normalize an OSVVulnerability response schema into a canonical AdvisoryRecord."""
    withdrawn_dt = _parse_osv_timestamp(osv_vuln.withdrawn)
    is_withdrawn = bool(osv_vuln.withdrawn and osv_vuln.withdrawn.strip())

    affected_ranges: list[AffectedPackageRange] = []
    for affected_item in osv_vuln.affected:
        affected_ranges.extend(_map_affected_entry(affected_item))

    references = [
        AdvisoryReference(ref_type=ref.type or "WEB", url=ref.url)
        for ref in osv_vuln.references
    ]

    severities = [
        SeverityInfo(
            scheme=sev.type,
            score=sev.score,
            base_score=None,
            source=sev.source,
        )
        for sev in osv_vuln.severity
    ]

    # Also capture ecosystem-level severity string if present in database_specific without guessing CVSS
    db_severity = osv_vuln.database_specific.get("severity")
    if isinstance(db_severity, str) and db_severity.strip():
        severities.append(
            SeverityInfo(
                scheme="ECOSYSTEM",
                score=db_severity.strip(),
                base_score=None,
                source="osv_database_specific",
            )
        )

    raw_meta: dict[str, Any] = {}
    if osv_vuln.schema_version:
        raw_meta["schema_version"] = osv_vuln.schema_version
    if osv_vuln.related:
        raw_meta["related"] = list(osv_vuln.related)
    if osv_vuln.database_specific:
        raw_meta["database_specific"] = dict(osv_vuln.database_specific)
    if osv_vuln.credits:
        raw_meta["credits"] = list(osv_vuln.credits)
    if osv_vuln.withdrawn and withdrawn_dt is None:
        raw_meta["unparsed_withdrawn"] = osv_vuln.withdrawn

    return AdvisoryRecord(
        advisory_id=osv_vuln.id,
        aliases=list(dict.fromkeys(osv_vuln.aliases)),
        summary=osv_vuln.summary or "",
        details=osv_vuln.details or "",
        published_at=_parse_osv_timestamp(osv_vuln.published),
        modified_at=_parse_osv_timestamp(osv_vuln.modified),
        withdrawn_at=withdrawn_dt,
        is_withdrawn=is_withdrawn,
        references=references,
        severity_information=severities,
        affected_ranges=affected_ranges,
        source="osv",
        source_url=f"https://osv.dev/vulnerability/{osv_vuln.id}",
        retrieved_at=retrieved_at,
        from_cache=from_cache,
        raw_source_metadata=raw_meta,
    )
