"""Integration tests for Python AST static call-graph reachability and full pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from apps.cli.main import app
from packages.core.analysis.python import (
    PythonReachabilityAnalyzer,
    load_entry_point_config,
    load_symbol_manifest,
)
from packages.core.config.settings import Settings
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.integrations.osv.client import OSVClient
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    ReachabilityState,
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

REACH_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "reachability"
FAKE_DEP_SOURCES = REACH_FIXTURES / "fake_dep_sources"
runner = CliRunner()


def _analyze_fixture(
    fixture_name: str,
    *,
    manifest_name: str = "symbols.json",
    entry_points_name: str | None = None,
    dependency_source_dirs: list[Path] | None = None,
    max_depth: int | None = None,
    max_paths: int | None = None,
):
    repo_dir = REACH_FIXTURES / fixture_name
    manifest, sha = load_symbol_manifest(repo_dir / manifest_name)
    ep_config = (
        load_entry_point_config(repo_dir / entry_points_name)
        if entry_points_name
        else None
    )
    analyzer = PythonReachabilityAnalyzer()
    return analyzer.analyze_repository(
        repo_dir,
        manifest=manifest,
        manifest_sha256=sha,
        entry_point_config=ep_config,
        dependency_source_dirs=dependency_source_dirs,
        max_depth=max_depth,
        max_paths=max_paths,
    )


@pytest.mark.integration
def test_fixture_a_direct_call() -> None:
    bundle = _analyze_fixture("fixture_a_direct")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.reachable is True
    assert res.dependency_symbol_status == DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE
    assert res.path == ["main.__main__", "yaml.load"]
    assert res.path_length == 1
    assert res.supporting_edges[0].source_locations[0].file == "main.py"
    assert "\\" not in res.supporting_edges[0].source_locations[0].file


@pytest.mark.integration
def test_fixture_b_multilevel_fastapi_chain() -> None:
    bundle = _analyze_fixture("fixture_b_multilevel")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.reachable is True
    assert res.entry_point == "app.routes.parse_endpoint"
    assert res.path == [
        "app.routes.parse_endpoint",
        "app.service.handle_payload",
        "app.parser.parse_xml",
        "xml.etree.ElementTree.fromstring",
    ]
    assert res.path_length == 3
    assert any(ep.source == "fastapi_route" for ep in bundle.report.entry_points)


@pytest.mark.integration
def test_fixture_c_aliased_module_import_typer() -> None:
    bundle = _analyze_fixture("fixture_c_aliased_module")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.path == ["cli.parse_cmd", "xml.etree.ElementTree.fromstring"]
    assert any(ep.source == "typer_command" for ep in bundle.report.entry_points)


@pytest.mark.integration
def test_fixture_d_aliased_function_import_and_src_layout() -> None:
    bundle = _analyze_fixture("fixture_d_aliased_function")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.path == ["fetcher.client.__main__", "urllib.request.urlopen"]


@pytest.mark.integration
def test_fixture_e_no_path_within_supported_subset_never_claims_unreachable() -> None:
    bundle = _analyze_fixture("fixture_e_no_path")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET
    assert res.reachable is False
    assert res.path == []
    assert any(ep.source == "flask_route" for ep in bundle.report.entry_points)
    # Dead helper exists in call graph but has no path from entry points
    assert "unused.dead_legacy_loader" in bundle.call_graph_artifact["nodes"] or any(
        n["node_id"] == "unused.dead_legacy_loader"
        for n in bundle.call_graph_artifact["nodes"]
    )


@pytest.mark.integration
def test_fixture_f_dynamic_getattr_reports_unresolved() -> None:
    bundle = _analyze_fixture("fixture_f_dynamic_getattr")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.UNRESOLVED
    assert res.reachable is None
    assert len(res.unresolved_calls) >= 1
    assert any(u.category == "dynamic_attribute_lookup" for u in res.unresolved_calls)
    assert any(ep.source == "click_command" for ep in bundle.report.entry_points)


@pytest.mark.integration
def test_fixture_g_mutual_recursion_terminates_cleanly() -> None:
    bundle = _analyze_fixture("fixture_g_recursive")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.reachable is True
    assert res.path == ["rec.__main__", "rec.step_a", "rec.step_b", "yaml.load"]


@pytest.mark.integration
def test_fixture_h_cyclic_imports_and_user_entry_points() -> None:
    bundle = _analyze_fixture(
        "fixture_h_cyclic_imports", entry_points_name="entry_points.json"
    )
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.reachable is True
    assert res.path == [
        "pkg.a.start",
        "pkg.b.middle",
        "pkg.a.finalize",
        "yaml.load",
    ]


@pytest.mark.integration
def test_fixture_i_nested_functions_and_class_methods() -> None:
    bundle = _analyze_fixture("fixture_i_nested_and_methods")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.REACHABLE
    assert res.path == [
        "service.outer",
        "service.outer.<locals>.inner",
        "service.Runner.execute",
        "service.Runner._dispatch",
        "yaml.load",
    ]


@pytest.mark.integration
def test_fixture_j_dependency_source_verified_vs_missing_vs_absent_symbol() -> None:
    # 1. Dependency source present and defines yaml.load -> VERIFIED_IN_DEPENDENCY_SOURCE + REACHABLE
    verified = _analyze_fixture(
        "fixture_a_direct",
        manifest_name="symbols.json",
        dependency_source_dirs=[FAKE_DEP_SOURCES],
    )
    v_res = verified.report.results[0]
    assert v_res.dependency_symbol_status == DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE
    assert v_res.state == ReachabilityState.REACHABLE

    # 2. Dependency source present and does NOT define yaml.nonexistent_api -> TARGET_SYMBOL_NOT_FOUND
    absent = _analyze_fixture(
        "fixture_a_direct",
        manifest_name="symbols_absent.json",
        dependency_source_dirs=[FAKE_DEP_SOURCES],
    )
    a_res = absent.report.results[0]
    assert a_res.dependency_symbol_status == DependencySymbolResolutionStatus.NOT_FOUND_IN_DEPENDENCY_SOURCE
    assert a_res.state == ReachabilityState.TARGET_SYMBOL_NOT_FOUND
    assert a_res.reachable is None


@pytest.mark.integration
def test_fixture_k_missing_candidate_symbols() -> None:
    bundle = _analyze_fixture("fixture_k_missing_manifest", manifest_name="empty_symbols.json")
    res = bundle.report.results[0]
    assert res.state == ReachabilityState.MISSING_CANDIDATE_SYMBOLS
    assert res.reachable is None

    # Also test running without any manifest at all on standalone repository
    no_manifest = PythonReachabilityAnalyzer().analyze_repository(
        REACH_FIXTURES / "fixture_k_missing_manifest",
        manifest=None,
    )
    assert no_manifest.report.results == []
    assert any(d.code == "NO_SYMBOL_MANIFEST" for d in no_manifest.report.diagnostics)


@pytest.mark.integration
def test_fixture_l_multiple_candidate_symbols_for_one_vulnerability() -> None:
    bundle = _analyze_fixture("fixture_l_multiple_symbols")
    assert bundle.report.vulnerabilities_analyzed == 1
    assert bundle.report.candidate_symbols_evaluated == 2
    by_sym = {
        r.candidate_symbol.qualified_name: r for r in bundle.report.results if r.candidate_symbol
    }
    assert by_sym["dep.safe_unused"].state == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET
    assert by_sym["dep.safe_unused"].reachable is False
    assert by_sym["dep.dangerous_call"].state == ReachabilityState.REACHABLE
    assert by_sym["dep.dangerous_call"].reachable is True


@pytest.mark.integration
def test_fixture_m_depth_limit_exceeded_reports_analysis_incomplete() -> None:
    shallow = _analyze_fixture("fixture_m_deep_chain", max_depth=3)
    s_res = shallow.report.results[0]
    assert s_res.state == ReachabilityState.ANALYSIS_INCOMPLETE
    assert s_res.reachable is None
    assert any(d.code == "DEPTH_LIMIT_EXCEEDED" for d in s_res.diagnostics)

    deep = _analyze_fixture("fixture_m_deep_chain", max_depth=10)
    d_res = deep.report.results[0]
    assert d_res.state == ReachabilityState.REACHABLE
    assert d_res.path_length == 7


@pytest.mark.integration
def test_cli_analyze_command_outputs_and_persistence(tmp_path: Path) -> None:
    help_scan = runner.invoke(app, ["scan", "--help"])
    assert help_scan.exit_code == 0
    assert "--analyze" in help_scan.stdout
    assert "--symbols" in help_scan.stdout

    help_analyze = runner.invoke(app, ["analyze", "--help"])
    assert help_analyze.exit_code == 0

    out_dir = tmp_path / "reach_out"
    res_json = runner.invoke(
        app,
        [
            "analyze",
            str(REACH_FIXTURES / "fixture_b_multilevel"),
            "--symbols",
            str(REACH_FIXTURES / "fixture_b_multilevel" / "symbols.json"),
            "--output",
            str(out_dir),
            "--format",
            "json",
        ],
    )
    assert res_json.exit_code == 0, res_json.stdout
    payload = json.loads(res_json.stdout)
    assert payload["results"][0]["state"] == "reachable"

    assert (out_dir / "reachability-analysis.json").is_file()
    assert (out_dir / "call-graph.json").is_file()
    assert (out_dir / "candidate-symbols.json").is_file()
    assert (out_dir / "provenance.json").is_file()

    # Verify table output never labels NO_PATH_WITHIN_SUPPORTED_SUBSET as "unreachable"
    res_table = runner.invoke(
        app,
        [
            "analyze",
            str(REACH_FIXTURES / "fixture_e_no_path"),
            "--symbols",
            str(REACH_FIXTURES / "fixture_e_no_path" / "symbols.json"),
            "--format",
            "table",
        ],
    )
    assert res_table.exit_code == 0, res_table.stdout
    assert "no_path_within_supported_subset" in res_table.stdout
    lower_without_phrase = res_table.stdout.lower().replace("unreachability", "")
    assert "unreachable" not in lower_without_phrase


@pytest.mark.integration
def test_discovery_osv_and_python_reachability_full_pipeline(tmp_path: Path) -> None:
    """End-to-end integration: Discovery -> OSV Intelligence -> Python Static Reachability."""
    settings = Settings(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "out",
    )
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )
    store = EvidenceStore(settings.default_output_dir)
    disc_orch = DiscoveryOrchestrator(
        trivy_client=fake_trivy,
        evidence_store=store,
        settings=settings,
    )
    discovery_result, artifacts = disc_orch.run_discovery(
        SAMPLE_APP_DIR, output_dir=settings.default_output_dir
    )
    assert artifacts is not None

    transport, _ = _build_mock_osv_transport()
    osv_client = OSVClient(http_client=httpx.Client(transport=transport))
    cache = SQLiteAdvisoryCache(db_path=settings.storage_path, ttl_seconds=3600)
    try:
        intel_orch = IntelligenceOrchestrator(
            osv_client=osv_client,
            advisory_cache=cache,
            evidence_store=store,
            settings=settings,
        )
        discovery_result = intel_orch.enrich(discovery_result=discovery_result, artifacts=artifacts)
    finally:
        osv_client.close()

    # Manifest keyed by CVE-2023-32681 targets requests.get called in sample_app/app.py
    manifest = VulnerabilitySymbolManifest(
        entries=[
            VulnerabilitySymbolEntry(
                vulnerability_id="CVE-2023-32681",
                package=SymbolPackageTarget(ecosystem="pypi", name="requests", import_names=["requests"]),
                symbols=[
                    CandidateVulnerableSymbol(
                        module="requests",
                        qualified_name="requests.get",
                        symbol_type="function",
                        source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
                        confidence=SymbolConfidence.VERIFIED,
                    )
                ],
            )
        ]
    )
    tmp_path_ep = tmp_path / "sample_entry_points.json"
    tmp_path_ep.write_text(
        json.dumps({"entry_points": [{"module": "app", "qualified_name": "fetch_status"}]}),
        encoding="utf-8",
    )
    ep_config = load_entry_point_config(tmp_path_ep)

    reach_analyzer = PythonReachabilityAnalyzer(settings=settings)
    enriched, bundle = reach_analyzer.analyze_discovery_result(
        discovery_result,
        manifest=manifest,
        entry_point_config=ep_config,
    )
    store.persist_reachability_artifacts(
        artifacts,
        bundle.report,
        call_graph_artifact=bundle.call_graph_artifact,
        manifest=bundle.manifest,
    )
    store.persist_assessment(artifacts=artifacts, result=enriched)

    assert enriched.reachability is not None
    by_vid = {r.vulnerability_id: r for r in enriched.reachability.results}
    assert by_vid["CVE-2023-32681"].state == ReachabilityState.REACHABLE
    assert by_vid["CVE-2023-32681"].path == ["app.fetch_status", "requests.get"]

    # Check persisted evidence artifacts and SHA-256 hashes
    reloaded, _ = store.load_assessment(artifacts.assessment_dir)
    assert reloaded.reachability is not None
    assert "reachability-analysis.json" in reloaded.scan_metadata.evidence_hashes
    assert "call-graph.json" in reloaded.scan_metadata.evidence_hashes
    assert "candidate-symbols.json" in reloaded.scan_metadata.evidence_hashes
    provenance_data = json.loads(artifacts.provenance_path.read_text(encoding="utf-8"))
    assert provenance_data["reachability_analyzer"] == "vexreach-python-ast"
