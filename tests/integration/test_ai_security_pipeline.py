"""Integration tests for Milestone 3 AI Security Intelligence pipeline & CLI."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from apps.cli.main import app
from packages.core.analysis.python import PythonReachabilityAnalyzer, load_entry_point_config
from packages.core.config.settings import Settings
from packages.core.engines.ai_intelligence import (
    AISecurityIntelligenceOrchestrator,
    OpenAICompatibleLLMProvider,
)
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.integrations.osv.client import OSVClient
from packages.core.models.reachability import ReachabilityState
from packages.core.storage.advisory_cache import SQLiteAdvisoryCache
from packages.core.storage.evidence_store import EvidenceStore
from tests.integration.test_discovery_pipeline import _FakeTrivyClient
from tests.integration.test_intelligence_pipeline import (
    DISCOVERY_FIXTURES,
    SAMPLE_APP_DIR,
    _build_mock_osv_transport,
)

AI_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "ai_intelligence"
FAKE_REQUESTS_DEP = AI_FIXTURES / "fake_requests_dep"
runner = CliRunner()


@pytest.mark.integration
def test_ai_intelligence_patch_prompt_injection_to_reachability_pipeline(
    tmp_path: Path,
) -> None:
    """Verify Discovery -> OSV -> AI/Patch (with poisoned patch) -> Static Reachability -> Storage."""
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
    disc_res, artifacts = disc_orch.run_discovery(
        SAMPLE_APP_DIR, output_dir=settings.default_output_dir
    )
    assert artifacts is not None

    osv_transport, _ = _build_mock_osv_transport()
    osv_client = OSVClient(http_client=httpx.Client(transport=osv_transport))
    cache = SQLiteAdvisoryCache(db_path=settings.storage_path, ttl_seconds=3600)
    try:
        intel_orch = IntelligenceOrchestrator(
            osv_client=osv_client,
            advisory_cache=cache,
            evidence_store=store,
            settings=settings,
        )
        disc_res = intel_orch.enrich(discovery_result=disc_res, artifacts=artifacts)
    finally:
        osv_client.close()

    # Adversarial mocked LLM returns both valid symbol, hallucinated symbol, AND attempts a fake VEX verdict
    def mock_llm_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "mechanism_summary": "Leak of Proxy-Authorization header on redirect",
                                    "affected_component_hint": "requests.get",
                                    "vex_status": "not_affected",
                                    "reachable": False,
                                    "candidate_symbols": [
                                        {
                                            "module": "requests",
                                            "qualified_name": "requests.get",
                                            "symbol_type": "function",
                                            "rationale": "Entry point wrapper",
                                        },
                                        {
                                            "module": "requests",
                                            "qualified_name": "requests.hallucinated_sink",
                                            "symbol_type": "function",
                                        },
                                    ],
                                }
                            )
                        }
                    }
                ]
            },
        )

    llm = OpenAICompatibleLLMProvider(
        base_url="http://127.0.0.1:11434/v1",
        model="local-test",
        http_client=httpx.Client(transport=httpx.MockTransport(mock_llm_handler)),
    )

    patch_dir = tmp_path / "patches"
    patch_dir.mkdir()
    # Copy poisoned patch under CVE-2023-32681.diff (contains injection targeting requests.get!)
    (patch_dir / "CVE-2023-32681.diff").write_text(
        (AI_FIXTURES / "poisoned_patch.diff").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    with AISecurityIntelligenceOrchestrator(
        settings=settings,
        llm_provider=llm,
        dependency_source_dirs=[FAKE_REQUESTS_DEP],
    ) as ai_orch:
        disc_res, ai_report, raw_patch_payloads = ai_orch.analyze_discovery_result(
            disc_res, patch_dir=patch_dir
        )

    assert disc_res.ai_intelligence is not None
    assert ai_report.prompt_injections_detected >= 3
    by_vid_ai = {a.vulnerability_id: a for a in ai_report.analyses}
    cve_ai = by_vid_ai["CVE-2023-32681"]
    # LLM verdict attempt stripped cleanly; hallucinated sink rejected; real requests.get accepted & deterministically verified
    assert any("LLM_UNAUTHORIZED_VERDICT_IGNORED" in w for w in cve_ai.warnings)
    assert any(r.qualified_name == "requests.hallucinated_sink" for r in cve_ai.rejected_symbols)
    assert any(s.qualified_name == "requests.get" for s in cve_ai.accepted_symbols)

    store.persist_ai_intelligence_artifacts(
        artifacts, ai_report, raw_patch_payloads=raw_patch_payloads
    )

    # Feed generated_manifest automatically into Python Static Reachability
    ep_path = tmp_path / "ep.json"
    ep_path.write_text(
        json.dumps({"entry_points": [{"module": "app", "qualified_name": "fetch_status"}]}),
        encoding="utf-8",
    )
    ep_config = load_entry_point_config(ep_path)

    disc_res, reach_bundle = PythonReachabilityAnalyzer(
        settings=settings
    ).analyze_discovery_result(
        disc_res,
        manifest=ai_report.generated_manifest,
        entry_point_config=ep_config,
        dependency_source_dirs=[FAKE_REQUESTS_DEP],
    )
    store.persist_reachability_artifacts(
        artifacts,
        reach_bundle.report,
        call_graph_artifact=reach_bundle.call_graph_artifact,
        manifest=reach_bundle.manifest,
    )
    store.persist_assessment(artifacts=artifacts, result=disc_res)

    assert disc_res.reachability is not None
    cve_reach = [
        r for r in disc_res.reachability.results if r.vulnerability_id == "CVE-2023-32681"
    ]
    assert any(r.state == ReachabilityState.REACHABLE for r in cve_reach)

    reloaded, _ = store.load_assessment(artifacts.assessment_dir)
    assert reloaded.ai_intelligence is not None
    assert "ai-intelligence.json" in reloaded.scan_metadata.evidence_hashes
    assert "raw-patch-evidence.json" in reloaded.scan_metadata.evidence_hashes

    # Exercise CLI extract-symbols against persisted assessment cleanly (offline heuristic mode)
    cli_res = runner.invoke(
        app,
        [
            "extract-symbols",
            str(artifacts.assessment_dir),
            "--patch-dir",
            str(patch_dir),
            "--dependency-source",
            str(FAKE_REQUESTS_DEP),
            "--format",
            "json",
        ],
    )
    assert cli_res.exit_code == 0, cli_res.stdout
    cli_payload = json.loads(cli_res.stdout)
    assert cli_payload["prompt_injections_detected"] >= 3
