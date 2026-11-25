"""Unit tests for CycloneDXParser schema validation, dependency scope, and completeness."""

import json
from pathlib import Path

import pytest

from packages.core.integrations.cyclonedx.parser import CycloneDXParseError, CycloneDXParser
from packages.core.models.discovery import DependencyScope, SBOMCompletenessStatus

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"


@pytest.mark.unit
def test_parse_cyclonedx_sample_resolves_scopes_and_incomplete_flag() -> None:
    """CycloneDX parser resolves direct/transitive scopes and flags missing PURLs cleanly."""
    payload = json.loads((FIXTURES_DIR / "sbom_cyclonedx_sample.json").read_text(encoding="utf-8"))
    result = CycloneDXParser().parse(payload, detected_manifests=["requirements.txt"])

    assert result.bom.spec_version == "1.5"
    assert result.scanner_version == "0.58.1"
    assert result.generation_timestamp is not None
    assert result.scope_by_ref["pkg:pypi/requests@2.28.1"] == DependencyScope.DIRECT
    assert result.scope_by_ref["pkg:pypi/urllib3@1.26.15"] == DependencyScope.TRANSITIVE
    # Sample intentionally includes internal-helper without PURL -> INCOMPLETE with warning
    assert result.completeness_status == SBOMCompletenessStatus.INCOMPLETE
    assert any("lack Package URL" in w for w in result.warnings)


@pytest.mark.unit
def test_parse_complete_cyclonedx_14_sbom() -> None:
    """Complete CycloneDX 1.4 SBOM with full versions, PURLs, and graph marks COMPLETE."""
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "timestamp": "2026-11-25T10:00:00Z",
            "tools": [{"name": "trivy", "version": "0.58.1"}],
            "component": {"bom-ref": "root", "type": "application", "name": "app"},
        },
        "components": [
            {
                "bom-ref": "pkg:pypi/flask@3.0.0",
                "type": "library",
                "name": "flask",
                "version": "3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
            }
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["pkg:pypi/flask@3.0.0"]},
            {"ref": "pkg:pypi/flask@3.0.0", "dependsOn": []},
        ],
    }

    result = CycloneDXParser().parse(payload)
    assert result.completeness_status == SBOMCompletenessStatus.COMPLETE
    assert result.scanner_version == "0.58.1"
    assert result.scope_by_ref["pkg:pypi/flask@3.0.0"] == DependencyScope.DIRECT
    assert result.warnings == []


@pytest.mark.unit
def test_empty_components_with_manifests_marks_incomplete() -> None:
    """Empty SBOM when dependency manifests exist must be marked INCOMPLETE, never COMPLETE."""
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [],
        "dependencies": [],
    }
    result = CycloneDXParser().parse(payload, detected_manifests=["requirements.txt"])
    assert result.completeness_status == SBOMCompletenessStatus.INCOMPLETE
    assert any("0 packages despite detected manifest" in w for w in result.warnings)


@pytest.mark.unit
def test_invalid_bom_format_rejected() -> None:
    """Non-CycloneDX JSON raises CycloneDXParseError."""
    with pytest.raises(CycloneDXParseError, match="Invalid CycloneDX SBOM"):
        CycloneDXParser().parse({"bomFormat": "SPDX", "specVersion": "2.3"})
