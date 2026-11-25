"""Integration and regression tests for the VEXReach Vulnerability Intelligence Engine."""

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from apps.cli.main import app
from packages.core.config.settings import Settings
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.integrations.osv.client import OSVClient
from packages.core.models.discovery import DiscoveryResult, ScanStatus
from packages.core.models.intelligence import (
    CorrelationOutcome,
    IntelligenceStatus,
    VersionMatchStatus,
)
from packages.core.storage.advisory_cache import SQLiteAdvisoryCache
from packages.core.storage.evidence_store import EvidenceStore
from tests.integration.test_discovery_pipeline import _FakeTrivyClient

DISCOVERY_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"
INTEL_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "intelligence"
SAMPLE_APP_DIR = DISCOVERY_FIXTURES / "sample_app"
runner = CliRunner()


def _load_intel_fixture(name: str) -> dict[str, object]:
    return json.loads((INTEL_FIXTURES / name).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _build_mock_osv_transport(
    advisories_by_id: dict[str, dict[str, object]] | None = None,
    extra_requests_stub: bool = False,
) -> tuple[httpx.MockTransport, dict[str, int]]:
    """Build deterministic OSV.dev MockTransport tracking HTTP call counts."""
    vulns_db = advisories_by_id or {
        "GHSA-j8r2-6x86-q33q": _load_intel_fixture("osv_ghsa_requests_2023_32681.json"),
        "GHSA-9wx4-h78v-vm56": _load_intel_fixture("osv_ghsa_requests_2024_35195.json"),
        "GHSA-g4mx-q9vg-27p4": _load_intel_fixture("osv_ghsa_urllib3_2023_45803.json"),
        "PYSEC-2021-142": _load_intel_fixture("osv_pysec_pyyaml_2020_14343.json"),
        "PYSEC-2023-74": _load_intel_fixture("osv_pysec_requests_extra.json"),
    }
    counters = {"querybatch": 0, "vulns": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/querybatch"):
            counters["querybatch"] += 1
            body = json.loads(request.content.decode("utf-8"))
            results = []
            for q in body["queries"]:
                pkg = q.get("package", {})
                purl = pkg.get("purl", "")
                name = pkg.get("name", "")
                if "requests" in purl or name == "requests":
                    stubs = [
                        {"id": "GHSA-j8r2-6x86-q33q", "modified": "2026-10-01T12:00:00Z"},
                        {"id": "GHSA-9wx4-h78v-vm56", "modified": "2026-10-02T09:00:00Z"},
                    ]
                    if extra_requests_stub:
                        stubs.append({"id": "PYSEC-2023-74", "modified": "2026-10-05T08:00:00Z"})
                    results.append({"vulns": stubs})
                elif "urllib3" in purl or name == "urllib3":
                    results.append(
                        {"vulns": [{"id": "GHSA-g4mx-q9vg-27p4", "modified": "2026-10-03T10:00:00Z"}]}
                    )
                elif "pyyaml" in purl.lower() or name.lower() == "pyyaml":
                    results.append(
                        {"vulns": [{"id": "PYSEC-2021-142", "modified": "2026-09-01T00:00:00Z"}]}
                    )
                else:
                    results.append({"vulns": []})
            return httpx.Response(200, json={"results": results})

        if "/vulns/" in path:
            counters["vulns"] += 1
            vuln_id = path.rsplit("/vulns/", 1)[1]
            if vuln_id in vulns_db:
                return httpx.Response(200, json=vulns_db[vuln_id])
            return httpx.Response(404, json={"message": "Not found"})

        return httpx.Response(400, json={"message": f"Unexpected path {path}"})

    return httpx.MockTransport(_handler), counters


@pytest.mark.integration
def test_discovery_to_intelligence_enrichment_and_caching(tmp_path: Path) -> None:
    """Verify full enrichment pipeline, conflict preservation, raw OSV storage, and SQLite caching."""
    settings = Settings(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "assessments",
    )
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )
    store = EvidenceStore(settings.default_output_dir)
    disc_orch = DiscoveryOrchestrator(
        settings=settings,
        trivy_client=fake_trivy,
        evidence_store=store,
    )
    disc_res, artifacts = disc_orch.run_discovery(SAMPLE_APP_DIR, output_dir=tmp_path / "out1")
    assert artifacts is not None

    transport, counters = _build_mock_osv_transport(extra_requests_stub=True)
    osv_client = OSVClient(http_client=httpx.Client(transport=transport))
    cache = SQLiteAdvisoryCache(db_path=settings.storage_path, ttl_seconds=3600)

    intel_orch = IntelligenceOrchestrator(
        settings=settings,
        osv_client=osv_client,
        advisory_cache=cache,
        evidence_store=store,
    )
    enriched = intel_orch.enrich(disc_res, artifacts=artifacts)

    assert enriched.intelligence is not None
    intel = enriched.intelligence

    # Original Trivy & SBOM records remain completely preserved
    assert len(enriched.packages) == 4
    assert len(enriched.vulnerabilities) == 5
    assert enriched.scan_metadata.scan_status == ScanStatus.COMPLETED
    assert "raw-trivy-vuln.json" in enriched.scan_metadata.evidence_hashes
    assert "sbom-cyclonedx.json" in enriched.scan_metadata.evidence_hashes
    assert "raw-osv-responses.json" in enriched.scan_metadata.evidence_hashes
    assert artifacts.raw_osv_responses_path.is_file()

    # Check intelligence metrics derived from real fixture scenarios:
    assert intel.findings_discovered == 5
    assert intel.advisories_retrieved == 5
    assert intel.conflicting_records == 1  # PyYAML 5.4.1 vs OSV fixed 5.4
    assert intel.incomplete_intelligence_records == 2  # PyYAML conflict + internal-helper 404
    assert intel.intelligence_status == IntelligenceStatus.PARTIALLY_ENRICHED
    assert counters["querybatch"] == 1

    by_vid = {v.vulnerability_id: v for v in intel.vulnerabilities}
    assert by_vid["CVE-2023-32681"].overall_correlation == CorrelationOutcome.AUTHORITATIVE_ALIAS_MATCH
    assert by_vid["CVE-2023-32681"].overall_version_status == VersionMatchStatus.AFFECTED
    assert "GHSA-j8r2-6x86-q33q" in by_vid["CVE-2023-32681"].source_records or len(by_vid["CVE-2023-32681"].advisories) == 2

    # Multi-branch fixed versions preserved (not flattened!)
    assert by_vid["CVE-2023-45803"].fixed_versions == ["1.26.18", "2.0.7"]
    assert by_vid["CVE-2023-45803"].overall_version_status == VersionMatchStatus.AFFECTED

    # Conflict preserved on PyYAML without erasing Trivy finding
    assert by_vid["CVE-2020-14343"].overall_correlation == CorrelationOutcome.CONFLICTING_EVIDENCE
    assert by_vid["CVE-2020-14343"].overall_version_status == VersionMatchStatus.NOT_AFFECTED

    # 404 preserved cleanly without declaring unaffected
    assert by_vid["VEXREACH-CUSTOM-0001"].overall_correlation == CorrelationOutcome.NO_MATCH
    assert by_vid["VEXREACH-CUSTOM-0001"].overall_version_status == VersionMatchStatus.UNKNOWN

    # Second enrichment run should hit SQLite cache and avoid redundant network requests
    disc_res2, artifacts2 = disc_orch.run_discovery(SAMPLE_APP_DIR, output_dir=tmp_path / "out2")
    counters_before = dict(counters)
    enriched2 = intel_orch.enrich(disc_res2, artifacts=artifacts2, refresh_cache=False)
    assert enriched2.intelligence is not None
    assert enriched2.intelligence.cache_hits > 0
    assert counters["querybatch"] == counters_before["querybatch"]
    # Only VEXREACH-CUSTOM-0001 (which was 404 and not cached as advisory) may be retried
    assert counters["vulns"] <= counters_before["vulns"] + 1

    # refresh_cache=True forces fresh network queries
    enriched3 = intel_orch.enrich(disc_res2, artifacts=artifacts2, refresh_cache=True)
    assert enriched3.intelligence is not None
    assert enriched3.intelligence.cache_hits == 0
    assert counters["querybatch"] == counters_before["querybatch"] + 1


@pytest.mark.integration
def test_osv_package_version_discovery_when_trivy_found_zero_vulns(tmp_path: Path) -> None:
    """When Trivy reports 0 vulns but OSV batch returns an affected advisory, surface PACKAGE_VERSION_MATCH."""
    settings = Settings(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "assessments",
    )
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_clean.json",
    )
    disc_res, artifacts = DiscoveryOrchestrator(
        settings=settings,
        trivy_client=fake_trivy,
    ).run_discovery(SAMPLE_APP_DIR, output_dir=tmp_path / "clean_plus_osv")

    transport, _ = _build_mock_osv_transport()
    osv_client = OSVClient(http_client=httpx.Client(transport=transport))
    enriched = IntelligenceOrchestrator(
        settings=settings,
        osv_client=osv_client,
        advisory_cache=SQLiteAdvisoryCache(db_path=settings.storage_path),
    ).enrich(disc_res, artifacts=artifacts)

    assert enriched.intelligence is not None
    # Trivy reported 0 findings, OSV discovered requests (2 CVEs) + urllib3 (1 CVE); PyYAML 5.4.1 is NOT_AFFECTED so filtered out
    assert enriched.intelligence.findings_discovered == 0
    assert len(enriched.intelligence.vulnerabilities) == 3
    assert all(
        v.overall_correlation == CorrelationOutcome.PACKAGE_VERSION_MATCH
        for v in enriched.intelligence.vulnerabilities
    )
    assert all(v.source_records == ["osv"] for v in enriched.intelligence.vulnerabilities)


@pytest.mark.integration
def test_regression_osv_network_failure_does_not_corrupt_discovery(tmp_path: Path) -> None:
    """Failed OSV queries preserve original Discovery packages/vulnerabilities and mark FAILED."""
    settings = Settings(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "assessments",
        osv_max_retries=0,
    )
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )
    store = EvidenceStore(settings.default_output_dir)
    disc_res, artifacts = DiscoveryOrchestrator(
        settings=settings,
        trivy_client=fake_trivy,
        evidence_store=store,
    ).run_discovery(SAMPLE_APP_DIR, output_dir=tmp_path / "net_fail")

    def _failing_handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Network unreachable")

    osv_client = OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_failing_handler)),
        max_retries=0,
    )
    enriched = IntelligenceOrchestrator(
        settings=settings,
        osv_client=osv_client,
        advisory_cache=SQLiteAdvisoryCache(db_path=settings.storage_path),
        evidence_store=store,
    ).enrich(disc_res, artifacts=artifacts)

    # Original Discovery data untouched
    assert enriched.scan_metadata.scan_status == ScanStatus.COMPLETED
    assert len(enriched.packages) == 4
    assert len(enriched.vulnerabilities) == 5

    assert enriched.intelligence is not None
    assert enriched.intelligence.intelligence_status == IntelligenceStatus.FAILED
    assert enriched.intelligence.advisories_retrieved == 0
    assert len(enriched.intelligence.errors) > 0


@pytest.mark.integration
def test_cli_scan_enrich_and_intelligence_lookup_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `vexreach scan --enrich` and `vexreach intelligence <assessment-id>` end-to-end."""
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )
    transport, _ = _build_mock_osv_transport()
    mock_osv = OSVClient(http_client=httpx.Client(transport=transport))

    monkeypatch.setenv("VEXREACH_STORAGE_PATH", str(tmp_path / "cli_cache.db"))
    monkeypatch.setenv("VEXREACH_DEFAULT_OUTPUT_DIR", str(tmp_path / "assessments"))

    from packages.core.config.settings import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr(
        "packages.core.engines.discovery.orchestrator.TrivyClient",
        lambda **_kwargs: fake_trivy,
    )
    monkeypatch.setattr(
        "packages.core.engines.intelligence.orchestrator.OSVClient",
        lambda **_kwargs: mock_osv,
    )

    out_dir = tmp_path / "assessments" / "assess-cli-1"
    res = runner.invoke(
        app,
        ["scan", str(SAMPLE_APP_DIR), "--output", str(out_dir), "--enrich", "--format", "table"],
    )
    assert res.exit_code == 0
    assert "VEXReach Discovery Assessment" in res.output
    assert "VEXReach Vulnerability Intelligence" in res.output
    assert "Findings discovered: 5" in res.output
    assert "Advisories retrieved: 4" in res.output
    assert "Intelligence status: PARTIALLY_ENRICHED" in res.output
    assert (out_dir / "raw-osv-responses.json").is_file()

    # Verify JSON inspection via `vexreach intelligence <assessment-id>`
    res_lookup = runner.invoke(
        app,
        ["intelligence", str(out_dir), "--format", "json"],
    )
    assert res_lookup.exit_code == 0
    parsed = DiscoveryResult.model_validate_json(res_lookup.stdout)
    assert parsed.intelligence is not None
    assert parsed.intelligence.conflicting_records == 1

    # Verify missing assessment exits cleanly with code 1
    res_missing = runner.invoke(
        app,
        ["intelligence", "does-not-exist", "--assessments-dir", str(tmp_path / "assessments")],
    )
    assert res_missing.exit_code == 1
    get_settings.cache_clear()


@pytest.mark.integration
@pytest.mark.osv_live
def test_live_osv_api_query_if_network_available() -> None:
    """Verify real api.osv.dev/v1 contracts against requests@2.28.1; skips cleanly if offline/sandboxed."""
    from datetime import datetime, timezone

    from packages.core.engines.intelligence.version_ranges import VersionRangeEvaluator
    from packages.core.integrations.osv.mapper import map_osv_to_advisory
    from packages.core.integrations.osv.schemas import OSVPackageSpec, OSVQueryRequest

    with OSVClient(timeout_seconds=10.0, max_retries=0) as client:
        try:
            stubs_list, _, _ = client.query_batch(
                [OSVQueryRequest(package=OSVPackageSpec(purl="pkg:pypi/requests@2.28.1"))]
            )
            vuln, raw = client.get_vulnerability("GHSA-j8r2-6x86-q33q")
        except Exception as err:  # noqa: BLE001
            pytest.skip(f"Live api.osv.dev unreachable in current environment: {err}")

    assert len(stubs_list) == 1
    assert any(s.id == "GHSA-j8r2-6x86-q33q" for s in stubs_list[0])
    assert vuln.id == "GHSA-j8r2-6x86-q33q"
    assert "CVE-2023-32681" in vuln.aliases
    assert "affected" in raw

    advisory = map_osv_to_advisory(vuln, retrieved_at=datetime.now(timezone.utc))
    assert advisory.affected_ranges
    eval_res = VersionRangeEvaluator().evaluate_range(
        advisory_id=advisory.advisory_id,
        package_id="pkg:pypi/requests@2.28.1",
        installed_version="2.28.1",
        affected_range=advisory.affected_ranges[0],
    )
    assert eval_res.status == VersionMatchStatus.AFFECTED
