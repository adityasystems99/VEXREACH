"""Integration tests for DiscoveryOrchestrator and CLI `vexreach scan`.

Mocked/fixture-based pipeline tests are clearly separated from live Trivy tests
marked with `@pytest.mark.trivy`.
"""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apps.cli.main import app
from packages.core.config.settings import Settings
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.integrations.trivy.client import (
    TrivyClient,
    TrivyCommandResult,
    TrivyNotFoundError,
    TrivyTimeoutError,
    TrivyVersionInfo,
)
from packages.core.models.discovery import (
    DiscoveryResult,
    SBOMCompletenessStatus,
    ScanStatus,
)
from packages.core.storage.evidence_store import EvidenceStore

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "discovery"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"
runner = CliRunner()


class _FakeTrivyClient(TrivyClient):
    """Deterministic test double simulating Trivy CLI execution using fixture payloads."""

    def __init__(
        self,
        sbom_fixture: Path | None = None,
        vuln_fixture: Path | None = None,
        sbom_error: Exception | None = None,
        vuln_error: Exception | None = None,
        version_error: Exception | None = None,
        sbom_raw_override: str | None = None,
        vuln_raw_override: str | None = None,
    ) -> None:
        super().__init__(binary_path="fake-trivy")
        self.sbom_fixture = sbom_fixture
        self.vuln_fixture = vuln_fixture
        self.sbom_error = sbom_error
        self.vuln_error = vuln_error
        self.version_error = version_error
        self.sbom_raw_override = sbom_raw_override
        self.vuln_raw_override = vuln_raw_override

    def get_version(self, timeout: int = 15) -> TrivyVersionInfo:
        if self.version_error is not None:
            raise self.version_error
        return TrivyVersionInfo(version="0.58.1", raw_output="Version: 0.58.1")

    def generate_cyclonedx_sbom(
        self,
        target_dir: Path,
        output_file: Path,
        timeout: int = 300,
    ) -> TrivyCommandResult:
        if self.sbom_error is not None:
            raise self.sbom_error
        raw_text = (
            self.sbom_raw_override
            if self.sbom_raw_override is not None
            else self.sbom_fixture.read_text(encoding="utf-8")  # type: ignore[union-attr]
        )
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(raw_text, encoding="utf-8")
        return TrivyCommandResult(
            command=["trivy", "fs", "--format", "cyclonedx", str(target_dir)],
            returncode=0,
            stdout="",
            stderr="",
            output_path=output_file,
            raw_text=raw_text,
            parsed_json=json.loads(raw_text),
        )

    def scan_filesystem_vulnerabilities(
        self,
        target_dir: Path,
        output_file: Path,
        timeout: int = 300,
    ) -> TrivyCommandResult:
        if self.vuln_error is not None:
            raise self.vuln_error
        raw_text = (
            self.vuln_raw_override
            if self.vuln_raw_override is not None
            else self.vuln_fixture.read_text(encoding="utf-8")  # type: ignore[union-attr]
        )
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(raw_text, encoding="utf-8")
        return TrivyCommandResult(
            command=["trivy", "fs", "--format", "json", str(target_dir)],
            returncode=0,
            stdout="",
            stderr="",
            output_path=output_file,
            raw_text=raw_text,
            parsed_json=json.loads(raw_text),
        )


@pytest.mark.integration
def test_orchestrator_full_discovery_with_vulnerabilities_mocked_trivy(tmp_path: Path) -> None:
    """Mocked Trivy pipeline normalizes SBOM + vulnerabilities and persists all evidence files."""
    out_dir = tmp_path / "evidence"
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=FIXTURES_DIR / "sbom_cyclonedx_sample.json",
        vuln_fixture=FIXTURES_DIR / "trivy_vuln_sample.json",
    )
    settings = Settings(default_output_dir=tmp_path / "default_out")
    orchestrator = DiscoveryOrchestrator(
        settings=settings,
        trivy_client=fake_trivy,
        evidence_store=EvidenceStore(settings.default_output_dir),
    )

    result, artifacts = orchestrator.run_discovery(target_path=SAMPLE_APP_DIR, output_dir=out_dir)

    assert artifacts is not None
    assert artifacts.raw_trivy_vuln_path.is_file()
    assert artifacts.sbom_cyclonedx_path.is_file()
    assert artifacts.assessment_json_path.is_file()
    assert artifacts.provenance_path.is_file()

    assert result.scan_metadata.scan_status == ScanStatus.COMPLETED
    assert result.scan_metadata.scanner_version == "0.58.1"
    assert len(result.packages) == 4
    assert len(result.vulnerabilities) == 5
    counts = result.severity_counts()
    assert counts["CRITICAL"] == 1
    assert counts["MEDIUM"] == 2
    assert counts["LOW"] == 1
    assert counts["UNKNOWN"] == 1
    assert "raw-trivy-vuln.json" in result.scan_metadata.evidence_hashes
    assert "sbom-cyclonedx.json" in result.scan_metadata.evidence_hashes


@pytest.mark.integration
def test_orchestrator_clean_scan_mocked_trivy(tmp_path: Path) -> None:
    """Clean scan yields COMPLETED status with 0 vulnerabilities and preserves packages."""
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=FIXTURES_DIR / "sbom_cyclonedx_sample.json",
        vuln_fixture=FIXTURES_DIR / "trivy_vuln_clean.json",
    )
    orchestrator = DiscoveryOrchestrator(
        settings=Settings(default_output_dir=tmp_path),
        trivy_client=fake_trivy,
    )
    result, _ = orchestrator.run_discovery(target_path=SAMPLE_APP_DIR, output_dir=tmp_path / "clean")

    assert result.scan_metadata.scan_status == ScanStatus.COMPLETED
    assert len(result.packages) == 4
    assert len(result.vulnerabilities) == 0


@pytest.mark.integration
def test_orchestrator_partial_failure_preserves_available_evidence(tmp_path: Path) -> None:
    """If SBOM succeeds but vulnerability scan times out, status is PARTIAL (never clean)."""
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=FIXTURES_DIR / "sbom_cyclonedx_sample.json",
        vuln_error=TrivyTimeoutError("Trivy vulnerability scan timed out after 10s."),
    )
    orchestrator = DiscoveryOrchestrator(
        settings=Settings(default_output_dir=tmp_path),
        trivy_client=fake_trivy,
    )
    result, artifacts = orchestrator.run_discovery(
        target_path=SAMPLE_APP_DIR,
        output_dir=tmp_path / "partial",
    )

    assert artifacts is not None
    assert artifacts.sbom_cyclonedx_path.is_file()
    assert result.scan_metadata.scan_status == ScanStatus.PARTIAL
    assert len(result.packages) == 4
    assert len(result.vulnerabilities) == 0
    assert any("timed out" in err for err in result.errors)


@pytest.mark.integration
def test_orchestrator_partial_failure_sbom_failed_vuln_succeeded(tmp_path: Path) -> None:
    """If SBOM fails but vuln scan succeeds, status is PARTIAL with synthesized package records."""
    fake_trivy = _FakeTrivyClient(
        sbom_error=TrivyTimeoutError("SBOM timed out"),
        vuln_fixture=FIXTURES_DIR / "trivy_vuln_sample.json",
    )
    orchestrator = DiscoveryOrchestrator(
        settings=Settings(default_output_dir=tmp_path),
        trivy_client=fake_trivy,
    )
    result, _ = orchestrator.run_discovery(
        target_path=SAMPLE_APP_DIR,
        output_dir=tmp_path / "partial_vuln_only",
    )

    assert result.scan_metadata.scan_status == ScanStatus.PARTIAL
    assert result.sbom.completeness_status == SBOMCompletenessStatus.FAILED
    assert len(result.vulnerabilities) == 5
    assert len(result.packages) == 4
    assert any("SBOM generation/parsing failed" in err for err in result.errors)


@pytest.mark.integration
def test_orchestrator_trivy_unavailable_returns_failed(tmp_path: Path) -> None:
    """Missing Trivy binary records FAILED status and diagnostics instead of crashing."""
    fake_trivy = _FakeTrivyClient(
        version_error=TrivyNotFoundError("Trivy binary 'trivy' was not found on PATH.")
    )
    orchestrator = DiscoveryOrchestrator(
        settings=Settings(default_output_dir=tmp_path),
        trivy_client=fake_trivy,
    )
    result, artifacts = orchestrator.run_discovery(
        target_path=SAMPLE_APP_DIR,
        output_dir=tmp_path / "missing_trivy",
    )

    assert artifacts is not None
    assert artifacts.assessment_json_path.is_file()
    assert result.scan_metadata.scan_status == ScanStatus.FAILED
    assert result.sbom.completeness_status == SBOMCompletenessStatus.FAILED
    assert any("not found" in err for err in result.errors)


@pytest.mark.integration
def test_orchestrator_invalid_target_path_returns_failed(tmp_path: Path) -> None:
    """Invalid target path produces FAILED DiscoveryResult with error message."""
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=FIXTURES_DIR / "sbom_cyclonedx_sample.json",
        vuln_fixture=FIXTURES_DIR / "trivy_vuln_clean.json",
    )
    orchestrator = DiscoveryOrchestrator(
        settings=Settings(default_output_dir=tmp_path),
        trivy_client=fake_trivy,
    )
    result, _ = orchestrator.run_discovery(
        target_path=tmp_path / "nonexistent_dir",
        output_dir=tmp_path / "invalid_target",
    )

    assert result.scan_metadata.scan_status == ScanStatus.FAILED
    assert any("does not exist" in err for err in result.errors)


@pytest.mark.integration
def test_cli_scan_json_and_table_outputs_with_mocked_trivy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `vexreach scan` CLI end-to-end in both table and json output formats."""
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=FIXTURES_DIR / "sbom_cyclonedx_sample.json",
        vuln_fixture=FIXTURES_DIR / "trivy_vuln_sample.json",
    )
    monkeypatch.setattr(
        "packages.core.engines.discovery.orchestrator.TrivyClient",
        lambda **_kwargs: fake_trivy,
    )

    # Note: DiscoveryOrchestrator initializes TrivyClient() if trivy_client is None
    # Patch TrivyClient inside orchestrator module so CLI uses _FakeTrivyClient
    out_table = tmp_path / "cli_table_out"
    res_table = runner.invoke(
        app,
        ["scan", str(SAMPLE_APP_DIR), "--output", str(out_table), "--format", "table"],
    )
    assert res_table.exit_code == 0
    assert "VEXReach Discovery Assessment" in res_table.output
    assert "Packages discovered: 4" in res_table.output
    assert "Vulnerabilities discovered: 5" in res_table.output
    assert "Assessment status: COMPLETED" in res_table.output
    assert (out_table / "discovery-assessment.json").is_file()

    out_json = tmp_path / "cli_json_out"
    res_json = runner.invoke(
        app,
        ["scan", str(SAMPLE_APP_DIR), "--output", str(out_json), "--format", "json", "--verbose"],
    )
    assert res_json.exit_code == 0
    parsed = DiscoveryResult.model_validate_json(res_json.stdout)
    assert parsed.scan_metadata.scan_status == ScanStatus.COMPLETED
    assert len(parsed.vulnerabilities) == 5


@pytest.mark.integration
def test_orchestrator_malformed_or_unrelated_scanner_json_fails_cleanly(tmp_path: Path) -> None:
    """Arbitrary/unrelated scanner JSON must fail cleanly, never report 0 CVEs COMPLETED."""
    fake_trivy = _FakeTrivyClient(
        sbom_raw_override=json.dumps({"unexpected": "not-cyclonedx"}),
        vuln_raw_override=json.dumps({"unexpected": "not-trivy"}),
    )
    orchestrator = DiscoveryOrchestrator(
        settings=Settings(default_output_dir=tmp_path),
        trivy_client=fake_trivy,
    )
    result, _ = orchestrator.run_discovery(
        target_path=SAMPLE_APP_DIR,
        output_dir=tmp_path / "malformed_json",
    )

    assert result.scan_metadata.scan_status == ScanStatus.FAILED
    assert result.sbom.completeness_status == SBOMCompletenessStatus.FAILED
    assert len(result.errors) == 2


@pytest.mark.integration
def test_cli_scan_partial_exits_with_code_2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI exits with code 2 when scan reaches PARTIAL state."""
    fake_trivy = _FakeTrivyClient(
        sbom_fixture=FIXTURES_DIR / "sbom_cyclonedx_sample.json",
        vuln_error=TrivyTimeoutError("vuln scan timed out"),
    )
    monkeypatch.setattr(
        "packages.core.engines.discovery.orchestrator.TrivyClient",
        lambda **_kwargs: fake_trivy,
    )
    res = runner.invoke(
        app,
        ["scan", str(SAMPLE_APP_DIR), "--output", str(tmp_path / "partial_cli")],
    )
    assert res.exit_code == 2
    assert "Assessment status: PARTIAL" in res.output


@pytest.mark.integration
def test_cli_scan_exits_nonzero_when_trivy_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI exits with code 1 when Trivy is unavailable so CI does not mistake failure for clean."""
    monkeypatch.setattr("shutil.which", lambda _name: None)
    res = runner.invoke(
        app,
        ["scan", str(SAMPLE_APP_DIR), "--output", str(tmp_path / "fail_out")],
    )
    assert res.exit_code == 1
    assert "Assessment status: FAILED" in res.output


@pytest.mark.integration
@pytest.mark.trivy
def test_live_trivy_filesystem_scan_if_available(tmp_path: Path) -> None:
    """Execute a real Trivy scan against sample_app when Trivy binary is installed locally."""
    if shutil.which("trivy") is None:
        pytest.skip("Live Trivy binary is not installed in this environment.")

    orchestrator = DiscoveryOrchestrator(settings=Settings(default_output_dir=tmp_path))
    result, artifacts = orchestrator.run_discovery(
        target_path=SAMPLE_APP_DIR,
        output_dir=tmp_path / "live_trivy",
    )

    assert artifacts is not None
    assert artifacts.sbom_cyclonedx_path.is_file()
    assert artifacts.raw_trivy_vuln_path.is_file()
    assert artifacts.assessment_json_path.is_file()
    assert result.scan_metadata.scan_status == ScanStatus.COMPLETED
    assert result.scan_metadata.scanner_version is not None
