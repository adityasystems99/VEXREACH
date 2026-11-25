"""Unit tests for Risk Intelligence EPSS/KEV threat feeds and explainable deterministic scoring."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from packages.core.engines.risk import RiskIntelligenceOrchestrator
from packages.core.integrations.threat_feeds import ThreatFeedClient
from packages.core.models.attack_path import (
    AttackPathRecord,
    AttackPathReport,
    ExposureSurface,
    TaintFlowStatus,
)
from packages.core.models.discovery import (
    AssessmentTarget,
    CVSSMetric,
    DiscoveryResult,
    PackageRecord,
    SBOMCompletenessStatus,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
    SeverityLevel,
    VulnerabilityRecord,
)
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    EntryPoint,
    ReachabilityResult,
    ReachabilityState,
    StaticReachabilityReport,
    SymbolConfidence,
    SymbolSource,
)
from packages.core.models.risk import RiskPriorityTier, WorkloadContext


@pytest.mark.unit
def test_threat_feed_client_handles_kev_epss_and_network_gracefully(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "epss" in str(request.url):
            return httpx.Response(
                200,
                json={"data": [{"cve": "CVE-2023-32681", "epss": "0.8421", "percentile": "0.97"}]},
            )
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2023-32681",
                        "dateAdded": "2024-01-10",
                        "dueDate": "2024-01-31",
                        "knownRansomwareCampaignUse": "Unknown",
                    }
                ]
            },
        )

    client = ThreatFeedClient(http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    snap = client.load_snapshot(["CVE-2023-32681"], fetch_remote=True)
    assert snap.kev_loaded is True
    assert "CVE-2023-32681" in snap.kev_by_cve
    assert snap.epss_by_cve["CVE-2023-32681"].epss == pytest.approx(0.8421)

    # Local JSON snapshots also work cleanly offline
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2020-14343"}]}), encoding="utf-8")
    snap_local = client.load_snapshot(["CVE-2020-14343"], kev_file=kev_file, fetch_remote=False)
    assert "CVE-2020-14343" in snap_local.kev_by_cve


@pytest.mark.unit
def test_deterministic_risk_scorer_ranks_kev_reachable_above_verified_no_path() -> None:
    pkg_req = PackageRecord(
        package_id="pkg:pypi/requests@2.28.1",
        name="requests",
        version="2.28.1",
        ecosystem="pypi",
    )
    pkg_yaml = PackageRecord(
        package_id="pkg:pypi/PyYAML@5.4.1",
        name="PyYAML",
        version="5.4.1",
        ecosystem="pypi",
    )
    vuln_req = VulnerabilityRecord(
        vulnerability_id="CVE-2023-32681",
        package_id=pkg_req.package_id,
        severity=SeverityLevel.HIGH,
        cvss=[CVSSMetric(source="nvd", base_score=7.5)],
        source="trivy",
    )
    vuln_yaml = VulnerabilityRecord(
        vulnerability_id="CVE-2020-14343",
        package_id=pkg_yaml.package_id,
        severity=SeverityLevel.CRITICAL,
        cvss=[CVSSMetric(source="nvd", base_score=9.8)],
        source="trivy",
    )

    cand_req = CandidateVulnerableSymbol(
        module="requests",
        qualified_name="requests.get",
        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
        confidence=SymbolConfidence.VERIFIED,
    )
    cand_yaml = CandidateVulnerableSymbol(
        module="yaml",
        qualified_name="yaml.load",
        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
        confidence=SymbolConfidence.VERIFIED,
    )
    reach = StaticReachabilityReport(
        files_discovered=2,
        files_parsed=2,
        entry_points=[EntryPoint(qualified_name="routes.fetch", module="routes", source="fastapi_route")],
        results=[
            ReachabilityResult(
                vulnerability_id="CVE-2023-32681",
                package_id=pkg_req.package_id,
                package_name="requests",
                ecosystem="pypi",
                candidate_symbol=cand_req,
                dependency_symbol_status=DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE,
                reachable=True,
                state=ReachabilityState.REACHABLE,
                path=["routes.fetch", "requests.get"],
                path_length=1,
            ),
            ReachabilityResult(
                vulnerability_id="CVE-2020-14343",
                package_id=pkg_yaml.package_id,
                package_name="PyYAML",
                ecosystem="pypi",
                candidate_symbol=cand_yaml,
                dependency_symbol_status=DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE,
                reachable=False,
                state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            ),
        ],
    )
    attack_paths = AttackPathReport(
        paths_evaluated=1,
        network_exposed_paths=1,
        taint_observed_paths=1,
        paths=[
            AttackPathRecord(
                vulnerability_id="CVE-2023-32681",
                package_name="requests",
                target_symbol="requests.get",
                entry_point="routes.fetch",
                exposure_surface=ExposureSurface.NETWORK_HTTP_PUBLIC,
                is_network_exposed=True,
                data_flow_status=TaintFlowStatus.TAINTED_FLOW_OBSERVED,
                explanation="Public endpoint forwards payload into requests.get",
            )
        ],
    )
    disc = DiscoveryResult(
        target=AssessmentTarget(target_path="."),
        scan_metadata=ScanMetadata(scan_status=ScanStatus.COMPLETED),
        sbom=SBOMRecord(completeness_status=SBOMCompletenessStatus.COMPLETE, packages=[pkg_req.package_id, pkg_yaml.package_id]),
        packages=[pkg_req, pkg_yaml],
        vulnerabilities=[vuln_req, vuln_yaml],
        reachability=reach,
        attack_paths=attack_paths,
    )

    from packages.core.integrations.threat_feeds.client import EPSSRecord, KEVEntry, ThreatFeedSnapshot

    snap = ThreatFeedSnapshot(
        epss_by_cve={"CVE-2023-32681": EPSSRecord("CVE-2023-32681", 0.90, 0.99)},
        kev_by_cve={"CVE-2023-32681": KEVEntry("CVE-2023-32681", "2024-01-01")},
        kev_loaded=True,
    )
    _, risk_report = RiskIntelligenceOrchestrator().evaluate(
        disc,
        threat_snapshot=snap,
        workload_context=WorkloadContext(workload_name="checkout-api", internet_facing=True, criticality="critical"),
    )

    by_vid = {a.vulnerability_id: a for a in risk_report.assessments}
    assert by_vid["CVE-2023-32681"].priority_tier == RiskPriorityTier.P0_CRITICAL
    assert by_vid["CVE-2023-32681"].contextual_score > by_vid["CVE-2020-14343"].contextual_score
    assert by_vid["CVE-2023-32681"].exploitability_established is False
    assert by_vid["CVE-2020-14343"].static_path_identified is False
    assert by_vid["CVE-2020-14343"].runtime_execution_observed is None
    assert len(by_vid["CVE-2023-32681"].score_breakdown) >= 4
