"""End-to-end integration tests for Go AST static reachability, Attack Path, Risk, OpenVEX, CLI, and REST API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from apps.api.main import create_app
from apps.cli.main import app as cli_app
from packages.core.analysis import (
    GoReachabilityAnalyzer,
    run_hybrid_reachability_repository,
)
from packages.core.analysis.go.reachability import GoToolchainNotFoundError
from packages.core.analysis.python import load_symbol_manifest
from packages.core.config.settings import Settings
from packages.core.engines.attack_path import AttackPathOrchestrator
from packages.core.engines.openvex import OpenVEXOrchestrator, validate_openvex_json_payload
from packages.core.engines.risk import RiskIntelligenceOrchestrator
from packages.core.integrations.registry import IntegrationRegistry
from packages.core.models.attack_path import ExposureSurface, TaintFlowStatus
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
from packages.core.models.openvex import VEXStatus
from packages.core.models.reachability import (
    DependencySymbolResolutionStatus,
    ReachabilityState,
)
from packages.core.models.risk import WorkloadContext
from packages.core.storage.evidence_store import EvidenceStore
from packages.core.storage.vex_history import SQLiteVEXStore
from tests.integration.test_discovery_pipeline import _FakeTrivyClient

GO_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "go_reachability"
GO_SAMPLE_APP = GO_FIXTURES / "sample_web_app"
GO_FAKE_DEPS = GO_FIXTURES / "fake_dep_sources"
runner = CliRunner()


@pytest.mark.integration
def test_go_reachability_end_to_end_attack_path_risk_and_openvex(tmp_path: Path) -> None:
    manifest, sha = load_symbol_manifest(GO_SAMPLE_APP / "symbols.json")
    settings = Settings(
        storage_path=tmp_path / "vex.db",
        default_output_dir=tmp_path / "out",
    )

    bundle = run_hybrid_reachability_repository(
        GO_SAMPLE_APP,
        language="auto",
        settings=settings,
        manifest=manifest,
        manifest_sha256=sha,
        dependency_source_dirs=[GO_FAKE_DEPS],
    )
    assert bundle.report.language == "go"
    assert bundle.report.analyzer_name == "vexreach-go-ast"
    assert len(bundle.report.results) == 1
    r_res = bundle.report.results[0]
    assert r_res.state == ReachabilityState.REACHABLE
    assert r_res.reachable is True
    assert r_res.dependency_symbol_status == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE
    assert r_res.path[-1] == "gopkg.in/yaml.v2.Unmarshal"

    pkg = PackageRecord(
        package_id="pkg:golang/gopkg.in/yaml.v2@v2.2.8",
        name="gopkg.in/yaml.v2",
        version="v2.2.8",
        ecosystem="golang",
        purl="pkg:golang/gopkg.in/yaml.v2@v2.2.8",
    )
    vuln = VulnerabilityRecord(
        vulnerability_id="CVE-2022-28948",
        package_id=pkg.package_id,
        installed_version="v2.2.8",
        fixed_version="v2.4.0",
        severity=SeverityLevel.HIGH,
        source="trivy",
    )
    disc = DiscoveryResult(
        target=AssessmentTarget(target_path=str(GO_SAMPLE_APP)),
        scan_metadata=ScanMetadata(scan_status=ScanStatus.COMPLETED, scanner_name="trivy"),
        sbom=SBOMRecord(completeness_status=SBOMCompletenessStatus.COMPLETE, packages=[pkg.package_id]),
        packages=[pkg],
        vulnerabilities=[vuln],
        reachability=bundle.report,
    )

    disc, ap_report = AttackPathOrchestrator(settings=settings).analyze_discovery_result(disc)
    assert ap_report.paths_evaluated >= 1
    assert any(p.exposure_surface == ExposureSurface.NETWORK_HTTP_PUBLIC for p in ap_report.paths)
    assert all(p.data_flow_status == TaintFlowStatus.CALL_PATH_ONLY_TAINT_NOT_PROVEN for p in ap_report.paths)

    disc, risk_report = RiskIntelligenceOrchestrator().evaluate(
        disc,
        workload_context=WorkloadContext(workload_name="go-web", internet_facing=True, criticality="high"),
    )
    assert risk_report.assessments[0].static_path_identified is True
    assert risk_report.assessments[0].exploitability_established is False

    store = EvidenceStore(settings.default_output_dir)
    artifacts = store._build_artifacts(settings.default_output_dir / disc.assessment_id)
    disc, policy_report = OpenVEXOrchestrator(
        settings=settings,
        vex_history_store=SQLiteVEXStore(settings.storage_path),
        evidence_store=store,
    ).generate(disc, artifacts=artifacts)

    assert policy_report.schema_valid is True
    assert policy_report.decisions[0].decided_status == VEXStatus.AFFECTED
    ok, errs = validate_openvex_json_payload(
        json.loads(artifacts.openvex_path.read_text(encoding="utf-8"))
    )
    assert ok, errs


@pytest.mark.integration
def test_cli_analyze_go_and_api_assessment_for_go_repository(tmp_path: Path) -> None:
    cli_res = runner.invoke(
        cli_app,
        [
            "analyze",
            str(GO_SAMPLE_APP),
            "--symbols",
            str(GO_SAMPLE_APP / "symbols.json"),
            "--dependency-source",
            str(GO_FAKE_DEPS),
            "--language",
            "go",
            "--format",
            "json",
        ],
    )
    assert cli_res.exit_code == 0, cli_res.stdout
    parsed = json.loads(cli_res.stdout)
    assert parsed["language"] == "go"
    assert parsed["results"][0]["state"] == "reachable"

    # IntegrationRegistry sees Go static analyzer configured cleanly
    descriptors = {d.integration_id: d for d in IntegrationRegistry().inspect_all(Settings())}
    assert descriptors["go_static_analyzer"].configured is True

    # Missing explicit Go binary raises clean GoToolchainNotFoundError when PATH has no go
    with pytest.raises(GoToolchainNotFoundError):
        bad = Settings(go_analyzer_binary_path=str(tmp_path / "missing-go-bin"))
        GoReachabilityAnalyzer(settings=bad).analyze_repository(GO_SAMPLE_APP)

    # End-to-end FastAPI assessment run on Go repository using mocked Trivy coordinates
    trivy_sbom = tmp_path / "go_sbom.json"
    trivy_sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "bom-ref": "yaml-v2",
                        "type": "library",
                        "name": "gopkg.in/yaml.v2",
                        "version": "v2.2.8",
                        "purl": "pkg:golang/gopkg.in/yaml.v2@v2.2.8",
                    }
                ],
                "dependencies": [{"ref": "app", "dependsOn": ["yaml-v2"]}],
            }
        ),
        encoding="utf-8",
    )
    trivy_vuln = tmp_path / "go_trivy.json"
    trivy_vuln.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Metadata": {},
                "Results": [
                    {
                        "Target": "go.mod",
                        "Class": "lang-pkgs",
                        "Type": "gomod",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2022-28948",
                                "PkgID": "gopkg.in/yaml.v2@v2.2.8",
                                "PkgName": "gopkg.in/yaml.v2",
                                "PkgIdentifier": {"PURL": "pkg:golang/gopkg.in/yaml.v2@v2.2.8"},
                                "InstalledVersion": "v2.2.8",
                                "FixedVersion": "v2.4.0",
                                "Severity": "HIGH",
                                "Title": "yaml.Unmarshal DoS",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    api_settings = Settings(
        storage_path=tmp_path / "api.db",
        default_output_dir=tmp_path / "api_out",
        api_auth_enabled=False,
    )
    app = create_app(
        api_settings,
        trivy_client_factory=lambda: _FakeTrivyClient(
            sbom_fixture=trivy_sbom, vuln_fixture=trivy_vuln
        ),
    )
    client = TestClient(app)
    resp = client.post(
        "/api/v1/assessments",
        json={
            "target_path": str(GO_SAMPLE_APP),
            "symbols_file": str(GO_SAMPLE_APP / "symbols.json"),
            "dependency_source_dirs": [str(GO_FAKE_DEPS)],
            "analyze_python": False,
            "analyze_go": True,
            "attack_paths": True,
            "compute_risk": True,
            "emit_vex": True,
            "async_execution": False,
        },
    )
    assert resp.status_code == 202, resp.text
    job = resp.json()
    assert job["status"] == "completed", job.get("error")
    aid = job["assessment_id"]
    vulns = client.get(f"/api/v1/assessments/{aid}/vulnerabilities").json()["items"]
    assert vulns[0]["static_path_identified"] is True
    assert vulns[0]["attack_surface"] == "network_http_public"
    assert vulns[0]["openvex_status"] == "affected"
