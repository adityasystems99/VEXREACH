"""Unit tests for Typer CLI commands."""

import pytest
from typer.testing import CliRunner
from apps.cli.main import app

runner = CliRunner()


@pytest.mark.unit
def test_cli_help() -> None:
    """Verify that 'vexreach --help' runs and provides usage instructions."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AI-Assisted, Kubernetes-Native Vulnerability Intelligence Platform" in result.output
    assert "version" in result.output
    assert "check-config" in result.output
    assert "scan" in result.output
    assert "intelligence" in result.output


@pytest.mark.unit
def test_cli_scan_help() -> None:
    """Verify 'vexreach scan --help' exposes expected discovery and enrichment options."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--output" in result.output
    assert "--format" in result.output
    assert "--timeout" in result.output
    assert "--enrich" in result.output
    assert "--refresh-cache" in result.output
    assert "--verbose" in result.output


@pytest.mark.unit
def test_cli_intelligence_help() -> None:
    """Verify 'vexreach intelligence --help' exposes expected assessment inspection options."""
    result = runner.invoke(app, ["intelligence", "--help"])
    assert result.exit_code == 0
    assert "--assessments-dir" in result.output
    assert "--format" in result.output
    assert "--enrich" in result.output
    assert "--refresh-cache" in result.output


@pytest.mark.unit
def test_cli_version() -> None:
    """Verify that 'vexreach version' outputs platform and version information."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "VEXReach Version" in result.output
    assert "0.1.0" in result.output


@pytest.mark.unit
def test_cli_check_config() -> None:
    """Verify that 'vexreach check-config' runs and inspects prerequisites."""
    result = runner.invoke(app, ["check-config"])
    assert result.exit_code == 0
    assert "Validating Configuration: VEXReach" in result.output
    assert "Python Runtime" in result.output
