"""Unit tests for PURL parsing, severity normalization, and DiscoveryNormalizer edge cases."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from packages.core.engines.discovery.normalizer import (
    DiscoveryNormalizer,
    normalize_ecosystem,
    normalize_severity,
    parse_purl,
)
from packages.core.integrations.cyclonedx.parser import CycloneDXParser
from packages.core.integrations.trivy.parser import TrivyReportParser
from packages.core.models.discovery import DependencyScope, SeverityLevel

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw_purl", "expected_eco", "expected_ns", "expected_name", "expected_ver"),
    [
        ("pkg:pypi/requests@2.28.1", "pypi", None, "requests", "2.28.1"),
        ("pkg:npm/%40babel/core@7.20.0", "npm", "@babel", "core", "7.20.0"),
        ("pkg:golang/github.com/gin-gonic/gin@v1.9.1#sub", "golang", "github.com/gin-gonic", "gin", "v1.9.1"),
        ("pkg:deb/debian/openssl@3.0.11?arch=amd64", "deb", "debian", "openssl", "3.0.11"),
    ],
)
def test_parse_purl_variants(
    raw_purl: str,
    expected_eco: str,
    expected_ns: str | None,
    expected_name: str,
    expected_ver: str | None,
) -> None:
    """Verify PURL coordinate extraction across ecosystems."""
    parsed = parse_purl(raw_purl)
    assert parsed is not None
    assert parsed.ecosystem == expected_eco
    assert parsed.namespace == expected_ns
    assert parsed.name == expected_name
    assert parsed.version == expected_ver


@pytest.mark.unit
def test_parse_purl_invalid_and_missing() -> None:
    """Missing or malformed PURLs return None without crashing."""
    assert parse_purl(None) is None
    assert parse_purl("") is None
    assert parse_purl("not-a-purl") is None
    assert parse_purl("pkg:pypi/") is None


@pytest.mark.unit
def test_severity_and_ecosystem_normalization() -> None:
    """Verify severity and ecosystem mapping including unknown values."""
    assert normalize_severity("critical") == SeverityLevel.CRITICAL
    assert normalize_severity("HIGH") == SeverityLevel.HIGH
    assert normalize_severity("negligible") == SeverityLevel.NEGLIGIBLE
    assert normalize_severity("UNKNOWN") == SeverityLevel.UNKNOWN
    assert normalize_severity("UNRECOGNIZED") == SeverityLevel.UNKNOWN
    assert normalize_severity(None) == SeverityLevel.UNKNOWN

    assert normalize_ecosystem("pip") == "pypi"
    assert normalize_ecosystem("gomod") == "golang"
    assert normalize_ecosystem(None) == "unknown"


@pytest.mark.unit
def test_normalizer_correlates_sbom_and_trivy_edge_cases() -> None:
    """Verify normalization across multiple CVEs per pkg, missing PURL, missing fixed version, unknown severity."""
    cdx_raw = json.loads((FIXTURES_DIR / "sbom_cyclonedx_sample.json").read_text(encoding="utf-8"))
    trivy_raw = json.loads((FIXTURES_DIR / "trivy_vuln_sample.json").read_text(encoding="utf-8"))

    cdx_res = CycloneDXParser().parse(cdx_raw)
    trivy_res = TrivyReportParser().parse(trivy_raw)
    now = datetime.now(timezone.utc)

    packages, vulns, sbom_ids, warnings = DiscoveryNormalizer().normalize(
        cyclonedx_result=cdx_res,
        trivy_report=trivy_res,
        detection_timestamp=now,
    )

    assert len(packages) == 4
    assert len(sbom_ids) == 4
    assert len(vulns) == 5
    assert warnings == []

    pkg_by_name = {p.name: p for p in packages}
    assert pkg_by_name["requests"].dependency_scope == DependencyScope.DIRECT
    assert pkg_by_name["urllib3"].dependency_scope == DependencyScope.TRANSITIVE
    assert pkg_by_name["internal-helper"].purl is None

    # Multiple vulnerabilities in one package ('requests') share the exact same package_id
    req_vulns = [v for v in vulns if v.package_id == pkg_by_name["requests"].package_id]
    assert {v.vulnerability_id for v in req_vulns} == {"CVE-2023-32681", "CVE-2024-35195"}

    # Missing fixed version stays None (never invented)
    pyyaml_vuln = next(v for v in vulns if v.vulnerability_id == "CVE-2020-14343")
    assert pyyaml_vuln.fixed_version is None
    assert pyyaml_vuln.severity == SeverityLevel.CRITICAL
    assert pyyaml_vuln.cvss[0].base_score == 9.8

    # Unknown severity + missing CVSS + missing PURL handled gracefully
    custom_vuln = next(v for v in vulns if v.vulnerability_id == "VEXREACH-CUSTOM-0001")
    assert custom_vuln.severity == SeverityLevel.UNKNOWN
    assert custom_vuln.fixed_version is None
    assert custom_vuln.cvss == []


@pytest.mark.unit
def test_normalizer_synthesizes_missing_sbom_package_and_avoids_cross_ecosystem_match() -> None:
    """When SBOM is unavailable or lacks a package, normalizer synthesizes PackageRecord with warning."""
    trivy_raw = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-9999",
                        "PkgName": "requests",
                        "PkgIdentifier": {"PURL": "pkg:npm/requests@1.0.0"},
                        "InstalledVersion": "1.0.0",
                        "Severity": "HIGH",
                    }
                ],
            }
        ],
    }
    # SBOM only has pypi requests@1.0.0, NOT npm requests@1.0.0
    cdx_raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "bom-ref": "pkg:pypi/requests@1.0.0",
                "type": "library",
                "name": "requests",
                "version": "1.0.0",
                "purl": "pkg:pypi/requests@1.0.0",
            }
        ],
    }

    cdx_res = CycloneDXParser().parse(cdx_raw)
    trivy_res = TrivyReportParser().parse(trivy_raw)
    packages, vulns, _, warnings = DiscoveryNormalizer().normalize(
        cyclonedx_result=cdx_res,
        trivy_report=trivy_res,
        detection_timestamp=datetime.now(timezone.utc),
    )

    assert len(packages) == 2
    assert len(vulns) == 1
    assert vulns[0].package_id == "pkg:npm/requests@1.0.0"
    assert any("missing from SBOM" in w for w in warnings)
