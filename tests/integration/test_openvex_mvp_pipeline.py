"""End-to-end Python MVP integration test: Discovery -> OSV -> AI/Patch -> Reachability -> Attack Path -> OpenVEX."""

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
from packages.core.engines.attack_path import AttackPathOrchestrator
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.engines.openvex import (
    OpenVEXOrchestrator,
    validate_openvex_json_payload,
)
from packages.core.integrations.osv.client import OSVClient
from packages.core.models.openvex import VEXStatus
from packages.core.storage.advisory_cache import SQLiteAdvisoryCache
from packages.core.storage.evidence_store import EvidenceStore
from packages.core.storage.vex_history import SQLiteVEXStore
from tests.integration.test_ai_security_pipeline import AI_FIXTURES, FAKE_REQUESTS_DEP
from tests.integration.test_discovery_pipeline import _FakeTrivyClient
from tests.integration.test_intelligence_pipeline import (
    DISCOVERY_FIXTURES,
    SAMPLE_APP_DIR,
    _build_mock_osv_transport,
)

runner = CliRunner()


@pytest.mark.integration
def test_end_to_end_python_mvp_to_validated_openvex_and_history(tmp_path: Path) -> None:
    """Verify full Python MVP evidence pipeline and OpenVEX 0.2.0 statement history."""
    settings = Settings(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "out",
    )
    store = EvidenceStore(settings.default_output_dir)
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )
    disc_res, artifacts = DiscoveryOrchestrator(
        trivy_client=fake_trivy, evidence_store=store, settings=settings
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

    # Patch fixture for CVE-2023-32681 + adversarial mocked LLM proposing requests.get + fake not_affected claim
    patch_dir = tmp_path / "patches"
    patch_dir.mkdir()
    (patch_dir / "CVE-2023-32681.diff").write_text(
        (AI_FIXTURES / "poisoned_patch.diff").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    def _llm_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "mechanism_summary": "Proxy-Authorization leaked via requests.get -> Session.request",
                                    "vex_status": "not_affected",
                                    "candidate_symbols": [
                                        {
                                            "module": "requests",
                                            "qualified_name": "requests.get",
                                            "symbol_type": "function",
                                            "rationale": "Public entry calling Session.request",
                                        }
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
        model="mvp-test-model",
        http_client=httpx.Client(transport=httpx.MockTransport(_llm_handler)),
    )
    with AISecurityIntelligenceOrchestrator(
        settings=settings, llm_provider=llm, dependency_source_dirs=[FAKE_REQUESTS_DEP]
    ) as ai_orch:
        disc_res, ai_report, raw_patch_payloads = ai_orch.analyze_discovery_result(
            disc_res, patch_dir=patch_dir
        )
    store.persist_ai_intelligence_artifacts(
        artifacts, ai_report, raw_patch_payloads=raw_patch_payloads
    )

    ep_file = tmp_path / "ep.json"
    ep_file.write_text(
        json.dumps({"entry_points": [{"module": "app", "qualified_name": "fetch_status"}]}),
        encoding="utf-8",
    )
    disc_res, reach_bundle = PythonReachabilityAnalyzer(settings=settings).analyze_discovery_result(
        disc_res,
        manifest=ai_report.generated_manifest,
        entry_point_config=load_entry_point_config(ep_file),
        dependency_source_dirs=[FAKE_REQUESTS_DEP],
    )
    store.persist_reachability_artifacts(
        artifacts,
        reach_bundle.report,
        call_graph_artifact=reach_bundle.call_graph_artifact,
        manifest=reach_bundle.manifest,
    )

    disc_res, ap_report = AttackPathOrchestrator(settings=settings).analyze_discovery_result(disc_res)
    store.persist_attack_path_artifacts(artifacts, ap_report)

    vex_history = SQLiteVEXStore(settings.storage_path)
    disc_res, policy_report = OpenVEXOrchestrator(
        settings=settings, vex_history_store=vex_history, evidence_store=store
    ).generate(disc_res, artifacts=artifacts)

    assert policy_report.schema_valid is True
    assert policy_report.openvex_document.version == 1
    assert artifacts.openvex_path is not None and artifacts.openvex_path.is_file()
    assert artifacts.policy_evaluation_path is not None and artifacts.policy_evaluation_path.is_file()

    # Validate emitted OpenVEX JSON-LD directly
    emitted_json = json.loads(artifacts.openvex_path.read_text(encoding="utf-8"))
    ok, errs = validate_openvex_json_payload(emitted_json)
    assert ok, errs
    assert emitted_json["@context"] == "https://openvex.dev/ns/v0.2.0"

    by_vid = {d.vulnerability_id: d for d in policy_report.decisions}
    # CVE-2023-32681 (requests.get reached by sample_app/app.py) -> AFFECTED
    assert by_vid["CVE-2023-32681"].decided_status == VEXStatus.AFFECTED
    # Conflicting PyYAML finding MUST stay UNDER_INVESTIGATION
    assert by_vid["CVE-2020-14343"].decided_status == VEXStatus.UNDER_INVESTIGATION

    reloaded, _ = store.load_assessment(artifacts.assessment_dir)
    assert reloaded.policy_evaluation is not None
    assert "openvex.vex.json" in reloaded.scan_metadata.evidence_hashes
    assert "policy-evaluation.json" in reloaded.scan_metadata.evidence_hashes

    # Exercise CLI `vex` command -> creates monotonic v2 and validates JSON output
    cli_vex = runner.invoke(
        app,
        ["vex", str(artifacts.assessment_dir), "--format", "json"],
        env={"VEXREACH_STORAGE_PATH": str(settings.storage_path)},
    )
    assert cli_vex.exit_code == 0, cli_vex.stdout
    v2_doc = json.loads(cli_vex.stdout)
    assert v2_doc["version"] == 2
    assert len(vex_history.list_history(str(SAMPLE_APP_DIR))) == 2
