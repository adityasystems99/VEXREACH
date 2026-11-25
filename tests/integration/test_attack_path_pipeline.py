"""Integration tests for Milestone 4 Attack Path Intelligence + storage + CLI."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from apps.cli.main import app
from packages.core.analysis.python import PythonReachabilityAnalyzer, load_entry_point_config
from packages.core.config.settings import Settings
from packages.core.engines.attack_path import AttackPathOrchestrator
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.integrations.osv.client import OSVClient
from packages.core.models.attack_path import ExposureSurface, TaintFlowStatus
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    SymbolConfidence,
    SymbolPackageTarget,
    SymbolSource,
    VulnerabilitySymbolEntry,
    VulnerabilitySymbolManifest,
)
from packages.core.storage.advisory_cache import SQLiteAdvisoryCache
from packages.core.storage.evidence_store import EvidenceStore
from tests.integration.test_discovery_pipeline import _FakeTrivyClient
from tests.integration.test_intelligence_pipeline import (
    DISCOVERY_FIXTURES,
    SAMPLE_APP_DIR,
    _build_mock_osv_transport,
)

runner = CliRunner()


@pytest.mark.integration
def test_attack_path_full_persistence_and_cli_command(tmp_path: Path) -> None:
    """Verify Discovery -> OSV -> Reachability -> Attack Paths -> EvidenceStore -> CLI attack-paths."""
    settings = Settings(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "out",
    )
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )
    store = EvidenceStore(settings.default_output_dir)
    disc_res, artifacts = DiscoveryOrchestrator(
        trivy_client=fake_trivy,
        evidence_store=store,
        settings=settings,
    ).run_discovery(SAMPLE_APP_DIR, output_dir=settings.default_output_dir)
    assert artifacts is not None

    osv_transport, _ = _build_mock_osv_transport()
    osv_client = OSVClient(http_client=httpx.Client(transport=osv_transport))
    cache = SQLiteAdvisoryCache(db_path=settings.storage_path, ttl_seconds=3600)
    try:
        disc_res = IntelligenceOrchestrator(
            osv_client=osv_client,
            advisory_cache=cache,
            evidence_store=store,
            settings=settings,
        ).enrich(discovery_result=disc_res, artifacts=artifacts)
    finally:
        osv_client.close()

    manifest = VulnerabilitySymbolManifest(
        entries=[
            VulnerabilitySymbolEntry(
                vulnerability_id="CVE-2023-32681",
                package=SymbolPackageTarget(ecosystem="pypi", name="requests", import_names=["requests"]),
                symbols=[
                    CandidateVulnerableSymbol(
                        module="requests",
                        qualified_name="requests.get",
                        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
                        confidence=SymbolConfidence.VERIFIED,
                    )
                ],
            )
        ]
    )
    ep_file = tmp_path / "ep.json"
    ep_file.write_text(
        json.dumps({"entry_points": [{"module": "app", "qualified_name": "fetch_status"}]}),
        encoding="utf-8",
    )
    disc_res, bundle = PythonReachabilityAnalyzer(settings=settings).analyze_discovery_result(
        disc_res,
        manifest=manifest,
        entry_point_config=load_entry_point_config(ep_file),
    )
    store.persist_reachability_artifacts(
        artifacts, bundle.report, call_graph_artifact=bundle.call_graph_artifact, manifest=bundle.manifest
    )

    disc_res, ap_report = AttackPathOrchestrator(settings=settings).analyze_discovery_result(disc_res)
    assert ap_report.paths_evaluated == 1
    ap = ap_report.paths[0]
    assert ap.exposure_surface == ExposureSurface.INTERNAL_FUNCTION
    assert ap.data_flow_status == TaintFlowStatus.TAINTED_FLOW_OBSERVED

    store.persist_attack_path_artifacts(artifacts, ap_report)
    store.persist_assessment(artifacts=artifacts, result=disc_res)

    reloaded, _ = store.load_assessment(artifacts.assessment_dir)
    assert reloaded.attack_paths is not None
    assert "attack-paths.json" in reloaded.scan_metadata.evidence_hashes

    # Exercise CLI `attack-paths` subcommand directly on persisted assessment dir
    cli_out = runner.invoke(
        app,
        ["attack-paths", str(artifacts.assessment_dir), "--format", "json"],
    )
    assert cli_out.exit_code == 0, cli_out.stdout
    parsed_json = json.loads(cli_out.stdout)
    assert parsed_json["taint_observed_paths"] == 1
