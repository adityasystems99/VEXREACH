"""Unit tests for TrivyReportParser boundary validation and edge cases."""

import json
from pathlib import Path

import pytest

from packages.core.integrations.trivy.parser import TrivyParseError, TrivyReportParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"


@pytest.mark.unit
def test_parse_valid_trivy_sample() -> None:
    """Valid Trivy sample JSON parses packages, vulnerabilities, CVSS, and missing fields."""
    payload = json.loads((FIXTURES_DIR / "trivy_vuln_sample.json").read_text(encoding="utf-8"))
    report = TrivyReportParser().parse(payload)

    assert report.schema_version == 2
    assert len(report.results) == 1
    assert len(report.results[0].vulnerabilities) == 5
    # Verify extra undocumented fields do not crash parser
    assert report.results[0].vulnerabilities[3].fixed_version is None


@pytest.mark.unit
def test_parse_clean_trivy_report_with_null_vulnerabilities() -> None:
    """Clean scan with Vulnerabilities: null yields empty vulnerabilities list."""
    payload = json.loads((FIXTURES_DIR / "trivy_vuln_clean.json").read_text(encoding="utf-8"))
    report = TrivyReportParser().parse(payload)
    assert len(report.results) == 1
    assert report.results[0].vulnerabilities == []


@pytest.mark.unit
def test_parse_arbitrary_json_rejected_as_invalid_scanner_output() -> None:
    """Unrelated JSON dict must not be silently interpreted as a clean 0-CVE scan."""
    with pytest.raises(TrivyParseError, match="expected Trivy report keys"):
        TrivyReportParser().parse({"status": "ok", "unrelated": 123})


@pytest.mark.unit
def test_parse_malformed_vulnerability_entry_raises() -> None:
    """Missing required VulnerabilityID inside Trivy report raises TrivyParseError."""
    bad_payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [{"PkgName": "requests"}],  # missing VulnerabilityID
            }
        ],
    }
    with pytest.raises(TrivyParseError, match="Invalid Trivy JSON structure"):
        TrivyReportParser().parse(bad_payload)
