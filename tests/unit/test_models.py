"""Unit tests for core Pydantic domain models."""

import pytest
from pydantic import ValidationError
from packages.core.models.openvex import (
    OpenVEXDocument,
    VEXJustification,
    VEXStatement,
    VEXStatus,
)
from packages.core.models.reachability import (
    ReachabilityEvidence,
    ReachabilityStatus,
)
from packages.core.models.vulnerability import (
    NormalizedDependency,
    VulnerabilityRecord,
    VulnerableSymbolSignature,
)


@pytest.mark.unit
def test_normalized_dependency() -> None:
    """Test NormalizedDependency creation and validation."""
    dep = NormalizedDependency(
        purl="pkg:pypi/requests@2.28.1",
        name="requests",
        version="2.28.1",
        ecosystem="pypi",
        direct=True,
    )
    assert dep.purl == "pkg:pypi/requests@2.28.1"
    assert dep.direct is True


@pytest.mark.unit
def test_vulnerability_record() -> None:
    """Test VulnerabilityRecord creation."""
    vuln = VulnerabilityRecord(
        cve_id="CVE-2023-32681",
        purl="pkg:pypi/requests@2.28.1",
        summary="Unintended leak of Proxy-Authorization header",
        details="Requests library leaked headers during redirect",
        fixed_version="2.31.0",
    )
    assert vuln.cve_id == "CVE-2023-32681"
    assert vuln.fixed_version == "2.31.0"


@pytest.mark.unit
def test_reachability_evidence() -> None:
    """Test ReachabilityEvidence creation and validation."""
    evidence = ReachabilityEvidence(
        status=ReachabilityStatus.REACHABLE,
        target_symbol="requests.sessions.Session.send",
        call_paths=[["main", "fetch_url", "requests.sessions.Session.send"]],
        entry_points_evaluated=["main"],
    )
    assert evidence.status == ReachabilityStatus.REACHABLE
    assert len(evidence.call_paths) == 1


@pytest.mark.unit
def test_openvex_document_serialization() -> None:
    """Test OpenVEX document construction matching OpenVEX 0.2.0."""
    statement = VEXStatement(
        vulnerability={"name": "CVE-2023-32681"},
        products=["pkg:pypi/requests@2.28.1"],
        status=VEXStatus.NOT_AFFECTED,
        justification=VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        impact_statement="Call graph analysis confirms requests.sessions.Session.send is never invoked.",
    )

    doc = OpenVEXDocument(
        author="VEXReach Test Suite",
        statements=[statement],
    )

    data = doc.model_dump(by_alias=True)
    assert data["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert "@id" in data
    assert len(data["statements"]) == 1
    assert data["statements"][0]["status"] == "not_affected"
    assert (
        data["statements"][0]["justification"]
        == "vulnerable_code_not_in_execute_path"
    )


@pytest.mark.unit
def test_strict_model_rejection() -> None:
    """Verify that extra unknown fields are rejected under strict base model."""
    with pytest.raises(ValidationError):
        NormalizedDependency(
            purl="pkg:pypi/test@1.0",
            name="test",
            version="1.0",
            ecosystem="pypi",
            unknown_arbitrary_field="malicious_payload",  # type: ignore
        )
