"""Unit tests for RuntimeEvidenceCorrelator, ContinuousEvidenceTracker, and WhatIfSimulator."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.core.analysis.python.discovery import PythonSourceDiscovery
from packages.core.config.settings import Settings
from packages.core.engines.continuous import ContinuousEvidenceTracker
from packages.core.engines.openvex import OpenVEXOrchestrator
from packages.core.engines.risk import RiskIntelligenceOrchestrator
from packages.core.engines.runtime import RuntimeEvidenceCorrelator
from packages.core.engines.simulator import WhatIfSimulator
from packages.core.models.discovery import (
    AssessmentTarget,
    DiscoveryResult,
    PackageRecord,
    SBOMCompletenessStatus,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
    SeverityLevel,
    VulnerabilityRecord,
)
from packages.core.models.extensions import (
    PackageUpgradeProposal,
    ReassessmentTriggerType,
    RuntimeObservationRecord,
)
from packages.core.models.intelligence import (
    AffectedPackageRange,
    CorrelationOutcome,
    IntelligenceStatus,
    OSVRangeType,
    RangeEvent,
    VersionMatchStatus,
    VulnerabilityIntelligence,
    VulnerabilityIntelligenceReport,
)
from packages.core.models.openvex import VEXStatus
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
from packages.core.storage.vex_history import SQLiteVEXStore


def _build_fixture_result(target_path: Path, source_hash: str) -> DiscoveryResult:
    pkg = PackageRecord(
        package_id="pkg:pypi/requests@2.28.1",
        name="requests",
        version="2.28.1",
        ecosystem="pypi",
    )
    vuln = VulnerabilityRecord(
        vulnerability_id="CVE-2023-32681",
        package_id=pkg.package_id,
        installed_version="2.28.1",
        fixed_version="2.31.0",
        severity=SeverityLevel.HIGH,
        source="trivy",
    )
    affected_range = AffectedPackageRange(
        ecosystem="PyPI",
        package_name="requests",
        range_type=OSVRangeType.ECOSYSTEM,
        introduced_versions=["2.3.0"],
        fixed_versions=["2.31.0"],
        events=[
            RangeEvent(event_type="introduced", value="2.3.0"),
            RangeEvent(event_type="fixed", value="2.31.0"),
        ],
    )
    intel = VulnerabilityIntelligenceReport(
        assessment_id="assess-ext-1",
        intelligence_status=IntelligenceStatus.ENRICHED,
        findings_discovered=1,
        advisories_retrieved=1,
        vulnerabilities=[
            VulnerabilityIntelligence(
                vulnerability_id="CVE-2023-32681",
                canonical_id="GHSA-j8r2-6x86-q33q",
                aliases=["CVE-2023-32681"],
                package_id=pkg.package_id,
                affected_ranges=[affected_range],
                fixed_versions=["2.31.0"],
                overall_correlation=CorrelationOutcome.EXACT_IDENTIFIER_MATCH,
                overall_version_status=VersionMatchStatus.AFFECTED,
                intelligence_status=IntelligenceStatus.ENRICHED,
            )
        ],
    )
    cand = CandidateVulnerableSymbol(
        module="requests",
        qualified_name="requests.get",
        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
        confidence=SymbolConfidence.VERIFIED,
    )
    reach = StaticReachabilityReport(
        files_discovered=1,
        files_parsed=1,
        source_snapshot_hash=source_hash,
        entry_points=[
            EntryPoint(qualified_name="app.handler", module="app", source="manual")
        ],
        results=[
            ReachabilityResult(
                vulnerability_id="CVE-2023-32681",
                package_id=pkg.package_id,
                package_name="requests",
                ecosystem="pypi",
                candidate_symbol=cand,
                dependency_symbol_status=DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE,
                state=ReachabilityState.REACHABLE,
                reachable=True,
                entry_point="app.handler",
                path=["app.handler", "requests.get"],
            )
        ],
    )
    return DiscoveryResult(
        assessment_id="assess-ext-1",
        target=AssessmentTarget(target_path=str(target_path)),
        scan_metadata=ScanMetadata(scan_status=ScanStatus.COMPLETED, scanner_name="trivy"),
        sbom=SBOMRecord(completeness_status=SBOMCompletenessStatus.COMPLETE, packages=[pkg.package_id]),
        packages=[pkg],
        vulnerabilities=[vuln],
        intelligence=intel,
        reachability=reach,
    )


@pytest.mark.unit
def test_runtime_correlator_and_non_observation_never_triggers_not_affected(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "app.py").write_text("import requests\ndef handler(): return requests.get('https://x')\n", encoding="utf-8")
    src_hash = PythonSourceDiscovery().discover(app_dir).source_snapshot_hash
    res = _build_fixture_result(app_dir, src_hash)

    correlator = RuntimeEvidenceCorrelator()
    settings = Settings(storage_path=tmp_path / "vex.db", default_output_dir=tmp_path / "out")

    # 1. Unmatched observation (other symbol traced, requests.get NOT seen, low coverage)
    res_unmatched, rt_unmatched, map_unmatched = correlator.ingest_observations(
        res,
        [
            RuntimeObservationRecord(
                qualified_symbol="app.healthcheck",
                instrumentation_source="ebpf_uprobe",
            )
        ],
        coverage_percent=35.0,
    )
    assert rt_unmatched.matched_vulnerability_ids == []
    assert map_unmatched == {}
    assert any("NEVER proves unreachability" in item for item in rt_unmatched.instrumentation_limitations)

    _, vex_unmatched = OpenVEXOrchestrator(
        settings=settings, vex_history_store=SQLiteVEXStore(settings.storage_path)
    ).generate(res_unmatched, runtime_observations=map_unmatched)
    assert vex_unmatched.decisions[0].decided_status == VEXStatus.AFFECTED

    # 2. Matched observation (requests.get traced at runtime) -> boosts risk & keeps exploitability_established=False
    res_matched, rt_matched, map_matched = correlator.ingest_observations(
        res,
        [
            RuntimeObservationRecord(
                qualified_symbol="requests.get",
                workload_name="payments-api",
                instrumentation_source="python_sys_monitoring",
                call_count=12,
            )
        ],
        coverage_percent=88.5,
    )
    assert rt_matched.matched_vulnerability_ids == ["CVE-2023-32681"]
    assert map_matched == {"CVE-2023-32681": ["requests.get"]}

    _, risk_report = RiskIntelligenceOrchestrator().evaluate(
        res_matched, runtime_observations=map_matched
    )
    assessment = risk_report.assessments[0]
    assert assessment.runtime_execution_observed is True
    assert assessment.exploitability_established is False
    assert any(f.factor_name == "runtime_execution_observed" for f in assessment.score_breakdown)


@pytest.mark.unit
def test_continuous_tracker_detects_source_sbom_and_advisory_drift(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    app_file = app_dir / "app.py"
    app_file.write_text("def handler():\n    return 1\n", encoding="utf-8")
    initial_hash = PythonSourceDiscovery().discover(app_dir).source_snapshot_hash
    res = _build_fixture_result(app_dir, initial_hash)

    tracker = ContinuousEvidenceTracker()
    no_drift = tracker.compute_reassessment_plan(
        res,
        current_target_path=app_dir,
        updated_sbom_package_versions={"requests": "2.28.1"},
    )
    assert no_drift.reassessment_required is False
    assert no_drift.triggers == []

    # Introduce source drift, SBOM drift, and new advisory drift simultaneously
    app_file.write_text("def handler():\n    return 2\n", encoding="utf-8")
    with_drift = tracker.compute_reassessment_plan(
        res,
        current_target_path=app_dir,
        updated_sbom_package_versions={"requests": "2.31.0"},
        new_advisory_vulns=["CVE-2026-9999"],
    )
    assert with_drift.reassessment_required is True
    assert ReassessmentTriggerType.SOURCE_SNAPSHOT_DRIFT in with_drift.triggers
    assert ReassessmentTriggerType.SBOM_DEPENDENCY_DRIFT in with_drift.triggers
    assert ReassessmentTriggerType.ADVISORY_DRIFT in with_drift.triggers
    assert "requests" in with_drift.affected_packages
    assert "CVE-2023-32681" in with_drift.affected_vulnerabilities
    assert "CVE-2026-9999" in with_drift.affected_vulnerabilities


@pytest.mark.unit
def test_what_if_simulator_evaluates_osv_ranges_and_requires_isolated_tests(tmp_path: Path) -> None:
    res = _build_fixture_result(tmp_path, "deadbeef")
    sim = WhatIfSimulator()

    resolved_report = sim.simulate_upgrades(
        res,
        [PackageUpgradeProposal(package_name="requests", target_version="2.31.0")],
    )
    assert resolved_report.validation_status == "pending_isolated_test_verification"
    assert len(resolved_report.vulnerability_deltas) == 1
    delta = resolved_report.vulnerability_deltas[0]
    assert delta.projected_version_affected == "not_affected"
    assert delta.projected_status_change == "resolved_in_advisory_ranges"
    assert any("requests.get" in site for site in resolved_report.potentially_impacted_call_sites)

    still_vuln_report = sim.simulate_upgrades(
        res,
        [PackageUpgradeProposal(package_name="requests", target_version="2.30.0")],
    )
    assert still_vuln_report.vulnerability_deltas[0].projected_version_affected == "affected"
    assert still_vuln_report.vulnerability_deltas[0].projected_status_change == "remains_affected"
