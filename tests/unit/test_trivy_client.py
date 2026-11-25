"""Unit tests for TrivyClient subprocess safety, timeouts, and output validation."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from packages.core.integrations.trivy.client import (
    TrivyClient,
    TrivyExecutionError,
    TrivyInvalidOutputError,
    TrivyNotFoundError,
    TrivyTimeoutError,
)


@pytest.mark.unit
def test_trivy_not_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing Trivy binary raises TrivyNotFoundError and reports unavailable."""
    monkeypatch.setattr("shutil.which", lambda _name: None)
    client = TrivyClient(binary_path="trivy")
    assert client.is_available() is False
    with pytest.raises(TrivyNotFoundError):
        client.resolve_binary()


@pytest.mark.unit
def test_trivy_get_version_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Valid Trivy --version output parses semantic version cleanly."""
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/trivy")
    completed = subprocess.CompletedProcess(
        args=["/usr/bin/trivy", "--version"],
        returncode=0,
        stdout="Version: 0.58.1\nVulnerability DB:\n  Version: 2\n",
        stderr="",
    )
    mock_run = MagicMock(return_value=completed)
    monkeypatch.setattr(subprocess, "run", mock_run)

    client = TrivyClient()
    info = client.get_version()
    assert info.version == "0.58.1"
    # Verify shell=False is enforced
    assert mock_run.call_args.kwargs["shell"] is False


@pytest.mark.unit
def test_trivy_scan_writes_json_and_restricts_scanners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan_filesystem_vulnerabilities uses --scanners vuln, shell=False, and validates JSON."""
    target = tmp_path / "repo"
    target.mkdir()
    out_file = tmp_path / "out" / "vuln.json"
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/trivy")

    def _fake_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        assert "--scanners" in cmd
        idx = cmd.index("--scanners")
        assert cmd[idx + 1] == "vuln"
        out_idx = cmd.index("--output")
        Path(cmd[out_idx + 1]).write_text(
            json.dumps({"SchemaVersion": 2, "Results": []}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    client = TrivyClient()
    res = client.scan_filesystem_vulnerabilities(target_dir=target, output_file=out_file)
    assert res.returncode == 0
    assert res.parsed_json["SchemaVersion"] == 2


@pytest.mark.unit
def test_trivy_timeout_raises_typed_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subprocess TimeoutExpired raises TrivyTimeoutError."""
    target = tmp_path / "repo"
    target.mkdir()
    out_file = tmp_path / "vuln.json"
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/trivy")

    def _timeout_run(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd=["trivy"], timeout=5, output="partial", stderr="hung")

    monkeypatch.setattr(subprocess, "run", _timeout_run)

    client = TrivyClient()
    with pytest.raises(TrivyTimeoutError, match="timed out after 5s"):
        client.scan_filesystem_vulnerabilities(target_dir=target, output_file=out_file, timeout=5)


@pytest.mark.unit
def test_trivy_nonzero_exit_code_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-zero exit code raises TrivyExecutionError with stderr diagnostics."""
    target = tmp_path / "repo"
    target.mkdir()
    out_file = tmp_path / "vuln.json"
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/trivy")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr="FATAL db download failed",
        ),
    )

    client = TrivyClient()
    with pytest.raises(TrivyExecutionError, match="non-zero code 1") as exc_info:
        client.scan_filesystem_vulnerabilities(target_dir=target, output_file=out_file)
    assert "FATAL db download failed" in exc_info.value.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    ("content", "expected_msg"),
    [
        ("", "is empty"),
        ("{not valid json", "malformed JSON"),
        ("[]", "Expected Trivy JSON object root"),
    ],
)
def test_trivy_exit_zero_invalid_output_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
    expected_msg: str,
) -> None:
    """Exit code 0 with empty, malformed, or non-object JSON raises TrivyInvalidOutputError."""
    target = tmp_path / "repo"
    target.mkdir()
    out_file = tmp_path / "vuln.json"
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/trivy")

    def _bad_json_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        out_file.write_text(content, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _bad_json_run)
    client = TrivyClient()
    with pytest.raises(TrivyInvalidOutputError, match=expected_msg):
        client.scan_filesystem_vulnerabilities(target_dir=target, output_file=out_file)


@pytest.mark.unit
def test_trivy_oversized_output_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output exceeding max_output_bytes is rejected to guard memory."""
    target = tmp_path / "repo"
    target.mkdir()
    out_file = tmp_path / "vuln.json"
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/trivy")

    def _huge_run(cmd: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        out_file.write_text('{"SchemaVersion": 2, "Results": []}', encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _huge_run)
    client = TrivyClient(max_output_bytes=10)
    with pytest.raises(TrivyInvalidOutputError, match="exceeds max limit"):
        client.scan_filesystem_vulnerabilities(target_dir=target, output_file=out_file)
