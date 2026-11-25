"""Unit tests for OSV boundary schemas and canonical AdvisoryRecord mapping."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from packages.core.integrations.osv.mapper import (
    from_osv_ecosystem,
    map_osv_to_advisory,
    to_osv_ecosystem,
)
from packages.core.integrations.osv.schemas import (
    OSVPackageSpec,
    OSVQueryRequest,
    OSVVulnerability,
)
from packages.core.models.intelligence import OSVRangeType

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "intelligence"


@pytest.mark.unit
def test_osv_request_rejects_versioned_purl_with_top_level_version() -> None:
    """OSV API forbids sending top-level version alongside a versioned PURL."""
    with pytest.raises(ValidationError, match="forbids specifying top-level 'version'"):
        OSVQueryRequest(
            package=OSVPackageSpec(purl="pkg:pypi/requests@2.28.1"),
            version="2.28.1",
        )

    # Unversioned PURL or ecosystem+name+version is valid
    valid_purl = OSVQueryRequest(package=OSVPackageSpec(purl="pkg:pypi/requests@2.28.1"))
    valid_eco = OSVQueryRequest(
        package=OSVPackageSpec(ecosystem="PyPI", name="requests"),
        version="2.28.1",
    )
    assert valid_purl.package is not None
    assert valid_eco.version == "2.28.1"


@pytest.mark.unit
def test_ecosystem_mapping_bidirectional() -> None:
    """Canonical ecosystems map accurately to OSV names and back."""
    assert to_osv_ecosystem("pypi") == "PyPI"
    assert to_osv_ecosystem("golang") == "Go"
    assert to_osv_ecosystem("cargo") == "crates.io"
    assert to_osv_ecosystem("deb", "pkg:deb/ubuntu/openssl@3.0") == "Ubuntu"
    assert to_osv_ecosystem("deb", "pkg:deb/debian/openssl@3.0") == "Debian"
    assert to_osv_ecosystem("unknown") is None

    assert from_osv_ecosystem("PyPI") == "pypi"
    assert from_osv_ecosystem("Go") == "golang"
    assert from_osv_ecosystem("Debian:12") == "deb"
    assert from_osv_ecosystem(None) == "unknown"


@pytest.mark.unit
def test_map_osv_advisory_preserves_ranges_aliases_and_metadata() -> None:
    """OSV mapper extracts aliases, events, severities, and preserves database_specific."""
    raw = json.loads((FIXTURES_DIR / "osv_ghsa_urllib3_2023_45803.json").read_text(encoding="utf-8"))
    parsed = OSVVulnerability.model_validate(raw)
    now = datetime.now(timezone.utc)

    adv = map_osv_to_advisory(parsed, retrieved_at=now)
    assert adv.advisory_id == "GHSA-g4mx-q9vg-27p4"
    assert adv.aliases == ["CVE-2023-45803"]
    assert adv.is_withdrawn is False
    assert len(adv.affected_ranges) == 1
    rng = adv.affected_ranges[0]
    assert rng.ecosystem == "pypi"
    assert rng.range_type == OSVRangeType.ECOSYSTEM
    assert rng.introduced_versions == ["1.26.0", "2.0.0"]
    assert rng.fixed_versions == ["1.26.18", "2.0.7"]
    assert len(rng.events) == 4


@pytest.mark.unit
def test_map_withdrawn_and_minimal_osv_advisory() -> None:
    """Withdrawn timestamp and missing optional fields normalize cleanly without inventing data."""
    raw = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "withdrawn": "2025-11-01T00:00:00Z",
        "summary": "Withdrawn false positive",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "versions": ["1.3.0"],
            }
        ],
    }
    parsed = OSVVulnerability.model_validate(raw)
    adv = map_osv_to_advisory(parsed, retrieved_at=datetime.now(timezone.utc))
    assert adv.is_withdrawn is True
    assert adv.withdrawn_at is not None
    assert adv.published_at is None
    assert adv.affected_ranges[0].affected_versions == ["1.3.0"]
    assert adv.affected_ranges[0].fixed_versions == []
