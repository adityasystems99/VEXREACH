"""Unit tests for canonical Discovery Engine Pydantic models."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from packages.core.models.discovery import (
    AssessmentTarget,
    CVSSMetric,
    DependencyScope,
    DiscoveryResult,
    PackageRecord,
    SBOMCompletenessStatus,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
    SeverityLevel,
    TargetType,
    VulnerabilityRecord,
)


@pytest.mark.unit
def test_discovery_result_round_trip_and_counts() -> None:
    """Verify full DiscoveryResult creation, JSON serialization, and round-trip validation."""
    now = datetime.now(timezone.utc)
    target = AssessmentTarget(
        target_id="target-abc",
        target_path=Path("/tmp/sample-app"),
        target_type=TargetType.FILESYSTEM,
        created_at=now,
        detected_ecosystems=["pypi"],
        detected_manifests=["requirements.txt"],
    )
    pkg = PackageRecord(
        package_id="pkg:pypi/requests@2.28.1",
        name="requests",
        version="2.28.1",
        ecosystem="pypi",
        purl="pkg:pypi/requests@2.28.1",
        dependency_scope=DependencyScope.DIRECT,
    )
    vuln = VulnerabilityRecord(
        vulnerability_id="CVE-2023-32681",
        package_id=pkg.package_id,
        installed_version="2.28.1",
        fixed_version="2.31.0",
        severity=SeverityLevel.MEDIUM,
        cvss=[CVSSMetric(source="nvd", version="3.1", base_score=5.3)],
        description="Header leak",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
        source="trivy",
        detection_timestamp=now,
    )
    sbom = SBOMRecord(
        format="cyclonedx",
        format_version="1.5",
        packages=[pkg.package_id],
        generation_timestamp=now,
        completeness_status=SBOMCompletenessStatus.COMPLETE,
    )
    meta = ScanMetadata(
        scanner_name="trivy",
        scanner_version="0.58.1",
        scan_started_at=now,
        scan_completed_at=now,
        scan_status=ScanStatus.COMPLETED,
    )
    result = DiscoveryResult(
        target=target,
        scan_metadata=meta,
        sbom=sbom,
        packages=[pkg],
        vulnerabilities=[vuln],
    )

    counts = result.severity_counts()
    assert counts["MEDIUM"] == 1
    assert counts["CRITICAL"] == 0

    raw_json = result.model_dump_json()
    rehydrated = DiscoveryResult.model_validate_json(raw_json)
    assert rehydrated.assessment_id == result.assessment_id
    assert rehydrated.packages[0].package_id == pkg.package_id
    assert rehydrated.vulnerabilities[0].fixed_version == "2.31.0"


@pytest.mark.unit
def test_discovery_result_rejects_orphan_vulnerability_reference() -> None:
    """Verify referential integrity rejects vulnerabilities pointing to unknown package_id."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="unknown package_id"):
        DiscoveryResult(
            target=AssessmentTarget(target_id="t1", target_path="/tmp/app", created_at=now),
            scan_metadata=ScanMetadata(scan_started_at=now, scan_status=ScanStatus.COMPLETED),
            sbom=SBOMRecord(completeness_status=SBOMCompletenessStatus.COMPLETE),
            packages=[],
            vulnerabilities=[
                VulnerabilityRecord(
                    vulnerability_id="CVE-2024-0001",
                    package_id="nonexistent-pkg",
                    detection_timestamp=now,
                )
            ],
        )


@pytest.mark.unit
def test_discovery_result_rejects_orphan_sbom_package_reference() -> None:
    """Verify referential integrity rejects SBOM package references absent from packages list."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="SBOMRecord.packages references unknown"):
        DiscoveryResult(
            target=AssessmentTarget(target_id="t1", target_path="/tmp/app", created_at=now),
            scan_metadata=ScanMetadata(scan_started_at=now, scan_status=ScanStatus.COMPLETED),
            sbom=SBOMRecord(
                packages=["missing-id"],
                completeness_status=SBOMCompletenessStatus.COMPLETE,
            ),
            packages=[],
        )


@pytest.mark.unit
def test_discovery_result_rejects_duplicate_package_ids() -> None:
    """Verify duplicate package_ids are rejected."""
    now = datetime.now(timezone.utc)
    pkg1 = PackageRecord(package_id="dup", name="a")
    pkg2 = PackageRecord(package_id="dup", name="b")
    with pytest.raises(ValidationError, match="Duplicate package_id"):
        DiscoveryResult(
            target=AssessmentTarget(target_id="t1", target_path="/tmp/app", created_at=now),
            scan_metadata=ScanMetadata(scan_started_at=now, scan_status=ScanStatus.COMPLETED),
            sbom=SBOMRecord(completeness_status=SBOMCompletenessStatus.COMPLETE),
            packages=[pkg1, pkg2],
        )
