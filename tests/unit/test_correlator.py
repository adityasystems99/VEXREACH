"""Unit tests for conservative VulnerabilityCorrelator outcomes and conflict preservation."""

from datetime import datetime, timezone

import pytest

from packages.core.engines.intelligence.correlator import VulnerabilityCorrelator
from packages.core.models.discovery import PackageRecord, SeverityLevel, VulnerabilityRecord
from packages.core.models.intelligence import (
    AdvisoryRecord,
    AffectedPackageRange,
    CorrelationOutcome,
    OSVRangeType,
    RangeEvent,
    VersionMatchStatus,
)


def _pkg(name: str = "requests", version: str = "2.28.1", eco: str = "pypi") -> PackageRecord:
    return PackageRecord(
        package_id=f"pkg:{eco}/{name}@{version}",
        name=name,
        version=version,
        ecosystem=eco,
        purl=f"pkg:{eco}/{name}@{version}",
    )


def _finding(vuln_id: str, pkg_id: str, fixed_ver: str | None = None) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        vulnerability_id=vuln_id,
        package_id=pkg_id,
        installed_version="2.28.1",
        fixed_version=fixed_ver,
        severity=SeverityLevel.MEDIUM,
        detection_timestamp=datetime.now(timezone.utc),
    )


def _advisory(
    adv_id: str,
    aliases: list[str] | None = None,
    pkg_name: str = "requests",
    eco: str = "pypi",
    introduced: str = "2.0.0",
    fixed: str | None = "2.31.0",
    withdrawn: bool = False,
    include_ranges: bool = True,
) -> AdvisoryRecord:
    events = [RangeEvent(event_type="introduced", value=introduced)]
    if fixed:
        events.append(RangeEvent(event_type="fixed", value=fixed))
    ranges = (
        [
            AffectedPackageRange(
                ecosystem=eco,
                package_name=pkg_name,
                introduced_versions=[introduced],
                fixed_versions=[fixed] if fixed else [],
                events=events,
                range_type=OSVRangeType.ECOSYSTEM,
            )
        ]
        if include_ranges
        else []
    )
    return AdvisoryRecord(
        advisory_id=adv_id,
        aliases=aliases or [],
        is_withdrawn=withdrawn,
        withdrawn_at=datetime.now(timezone.utc) if withdrawn else None,
        affected_ranges=ranges,
        retrieved_at=datetime.now(timezone.utc),
    )


@pytest.mark.unit
def test_correlate_exact_and_alias_matches() -> None:
    """Exact ID and authoritative alias matches link advisories cleanly."""
    pkg = _pkg("PyYAML", "5.3.0")
    finding = _finding("CVE-2020-14343", pkg.package_id)

    exact_adv = _advisory("CVE-2020-14343", pkg_name="pyyaml", introduced="5.1", fixed="5.4")
    _, _, _, _, outcome1, status1, _ = VulnerabilityCorrelator().correlate_finding(
        finding, pkg, [exact_adv]
    )
    assert outcome1 == CorrelationOutcome.EXACT_IDENTIFIER_MATCH
    assert status1 == VersionMatchStatus.AFFECTED

    alias_adv = _advisory(
        "PYSEC-2021-142",
        aliases=["CVE-2020-14343"],
        pkg_name="pyyaml",
        introduced="5.1",
        fixed="5.4",
    )
    _, _, _, _, outcome2, status2, _ = VulnerabilityCorrelator().correlate_finding(
        finding, pkg, [alias_adv]
    )
    assert outcome2 == CorrelationOutcome.AUTHORITATIVE_ALIAS_MATCH
    assert status2 == VersionMatchStatus.AFFECTED


@pytest.mark.unit
def test_correlate_preserves_conflicts_and_never_merges_unrelated_ids() -> None:
    """Withdrawn advisories, range disagreements, and package mismatches produce CONFLICTING_EVIDENCE."""
    pkg = _pkg("PyYAML", "5.4.1")
    finding = _finding("CVE-2020-14343", pkg.package_id)

    # Disagreement: Trivy flagged 5.4.1, OSV says fixed in 5.4 -> NOT_AFFECTED -> CONFLICTING_EVIDENCE
    adv_fixed_earlier = _advisory(
        "PYSEC-2021-142",
        aliases=["CVE-2020-14343"],
        pkg_name="pyyaml",
        introduced="5.1",
        fixed="5.4",
    )
    _, _, _, _, outcome, ver_status, warnings = VulnerabilityCorrelator().correlate_finding(
        finding, pkg, [adv_fixed_earlier]
    )
    assert outcome == CorrelationOutcome.CONFLICTING_EVIDENCE
    assert ver_status == VersionMatchStatus.NOT_AFFECTED
    assert any("conflicting with scanner finding" in w for w in warnings)

    # Unrelated CVE on the exact same package MUST NOT be merged -> NO_MATCH
    unrelated = _advisory("GHSA-other-9999", aliases=["CVE-2024-9999"], pkg_name="pyyaml")
    matched, _, _, _, outcome_unrelated, _, _ = VulnerabilityCorrelator().correlate_finding(
        finding, pkg, [unrelated]
    )
    assert matched == []
    assert outcome_unrelated == CorrelationOutcome.NO_MATCH

    # Withdrawn advisory -> CONFLICTING_EVIDENCE
    withdrawn_adv = _advisory(
        "CVE-2020-14343",
        pkg_name="pyyaml",
        introduced="5.1",
        fixed="5.5",
        withdrawn=True,
    )
    _, _, _, _, outcome_w, _, _ = VulnerabilityCorrelator().correlate_finding(
        finding, pkg, [withdrawn_adv]
    )
    assert outcome_w == CorrelationOutcome.CONFLICTING_EVIDENCE


@pytest.mark.unit
def test_correlate_partial_match_when_ranges_missing() -> None:
    """ID match without affected_ranges yields PARTIAL_MATCH instead of claiming full validation."""
    pkg = _pkg()
    finding = _finding("CVE-2023-32681", pkg.package_id)
    empty_adv = _advisory("CVE-2023-32681", include_ranges=False)
    _, _, _, _, outcome, ver_status, _ = VulnerabilityCorrelator().correlate_finding(
        finding, pkg, [empty_adv]
    )
    assert outcome == CorrelationOutcome.PARTIAL_MATCH
    assert ver_status == VersionMatchStatus.UNKNOWN
