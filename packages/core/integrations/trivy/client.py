"""Safe subprocess integration wrapper for Aqua Security Trivy CLI."""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packages.core.utils.logging import get_logger

logger = get_logger("integrations.trivy")

_MAX_DIAGNOSTIC_CHARS = 65536
_VERSION_PATTERN = re.compile(r"Version:\s*v?([0-9A-Za-z.\-+_]+)", re.IGNORECASE)
_SEMVER_FALLBACK_PATTERN = re.compile(r"\bv?(\d+\.\d+\.\d+(?:[.\-+][0-9A-Za-z]+)?)\b")


class TrivyError(Exception):
    """Base exception for Trivy integration failures."""


class TrivyNotFoundError(TrivyError):
    """Raised when the Trivy CLI binary cannot be located."""


class TrivyTimeoutError(TrivyError):
    """Raised when Trivy subprocess execution exceeds the configured timeout."""

    def __init__(self, message: str, stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class TrivyExecutionError(TrivyError):
    """Raised when Trivy exits with a non-zero exit code or fails to spawn."""

    def __init__(
        self,
        message: str,
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TrivyInvalidOutputError(TrivyError):
    """Raised when Trivy output file is missing, oversized, empty, or malformed JSON."""


@dataclass(frozen=True)
class TrivyVersionInfo:
    """Detected Trivy binary version metadata."""

    version: str
    raw_output: str


@dataclass(frozen=True)
class TrivyCommandResult:
    """Result container from a verified Trivy JSON-producing command."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    output_path: Path
    raw_text: str
    parsed_json: dict[str, Any]


def _truncate_diagnostic(text: str | bytes | None) -> str:
    """Bound captured diagnostic output to avoid excessive memory usage."""
    if text is None:
        return ""
    if isinstance(text, bytes):
        decoded = text.decode("utf-8", errors="replace")
    else:
        decoded = text
    if len(decoded) <= _MAX_DIAGNOSTIC_CHARS:
        return decoded
    return decoded[:_MAX_DIAGNOSTIC_CHARS] + "\n...[truncated]..."


class TrivyClient:
    """Safe, bounded wrapper around the Trivy command-line tool."""

    def __init__(
        self,
        binary_path: str = "trivy",
        max_output_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self.binary_path = binary_path
        self.max_output_bytes = max_output_bytes

    def resolve_binary(self) -> str:
        """Locate the Trivy executable cleanly or raise TrivyNotFoundError."""
        candidate = self.binary_path.strip()
        if not candidate:
            raise TrivyNotFoundError("Configured Trivy binary path is empty.")

        has_sep = os.path.sep in candidate or (os.path.altsep and os.path.altsep in candidate)
        if has_sep:
            explicit = Path(candidate)
            if explicit.is_file():
                return str(explicit.resolve())
            raise TrivyNotFoundError(f"Trivy binary not found at explicit path: {candidate}")

        resolved = shutil.which(candidate)
        if not resolved:
            raise TrivyNotFoundError(
                f"Trivy binary '{candidate}' was not found on PATH. "
                "Install Trivy or set VEXREACH_TRIVY_PATH."
            )
        return resolved

    def is_available(self) -> bool:
        """Return True if the configured Trivy executable can be located."""
        try:
            self.resolve_binary()
            return True
        except TrivyNotFoundError:
            return False

    def get_version(self, timeout: int = 15) -> TrivyVersionInfo:
        """Detect the installed Trivy version safely."""
        binary = self.resolve_binary()
        cmd = [binary, "--version"]
        logger.debug("Checking Trivy version", extra={"command": cmd})

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as err:
            raise TrivyTimeoutError(
                f"Trivy version check timed out after {timeout}s.",
                stdout=_truncate_diagnostic(err.stdout),
                stderr=_truncate_diagnostic(err.stderr),
            ) from err
        except OSError as err:
            raise TrivyExecutionError(f"Failed to execute Trivy version check: {err}") from err

        stdout = _truncate_diagnostic(proc.stdout)
        stderr = _truncate_diagnostic(proc.stderr)

        if proc.returncode != 0:
            raise TrivyExecutionError(
                f"Trivy version check failed with exit code {proc.returncode}: {stderr or stdout}",
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
            )

        combined = f"{stdout}\n{stderr}".strip()
        match = _VERSION_PATTERN.search(combined) or _SEMVER_FALLBACK_PATTERN.search(combined)
        if not match:
            raise TrivyInvalidOutputError(
                f"Unable to parse Trivy version from output: {combined[:500]}"
            )

        return TrivyVersionInfo(version=match.group(1), raw_output=combined)

    def scan_filesystem_vulnerabilities(
        self,
        target_dir: Path,
        output_file: Path,
        timeout: int = 300,
    ) -> TrivyCommandResult:
        """Run Trivy filesystem vulnerability scan and write raw JSON to output_file."""
        canonical_target = self._validate_target_argument(target_dir)
        binary = self.resolve_binary()
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Restrict scanners strictly to 'vuln' to avoid secret scanning leakage into evidence.
        cmd = [
            binary,
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--quiet",
            "--output",
            str(output_file),
            str(canonical_target),
        ]
        return self._run_json_command(cmd=cmd, output_file=output_file, timeout=timeout)

    def generate_cyclonedx_sbom(
        self,
        target_dir: Path,
        output_file: Path,
        timeout: int = 300,
    ) -> TrivyCommandResult:
        """Generate a CycloneDX JSON SBOM for target_dir using Trivy."""
        canonical_target = self._validate_target_argument(target_dir)
        binary = self.resolve_binary()
        output_file.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            binary,
            "fs",
            "--format",
            "cyclonedx",
            "--quiet",
            "--output",
            str(output_file),
            str(canonical_target),
        ]
        return self._run_json_command(cmd=cmd, output_file=output_file, timeout=timeout)

    @staticmethod
    def _validate_target_argument(target_dir: Path) -> Path:
        """Canonicalize target path and guard against CLI flag injection."""
        canonical = target_dir.resolve()
        target_str = str(canonical)
        if not canonical.is_absolute() or target_str.startswith("-"):
            raise TrivyExecutionError(f"Invalid canonical target path for Trivy: {target_str}")
        if not canonical.is_dir():
            raise TrivyExecutionError(f"Target path is not a directory: {target_str}")
        return canonical

    def _run_json_command(
        self,
        cmd: list[str],
        output_file: Path,
        timeout: int,
    ) -> TrivyCommandResult:
        """Execute a Trivy command safely and validate its JSON file artifact."""
        logger.debug("Executing Trivy command", extra={"command": cmd, "timeout": timeout})

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as err:
            raise TrivyTimeoutError(
                f"Trivy command timed out after {timeout}s.",
                stdout=_truncate_diagnostic(err.stdout),
                stderr=_truncate_diagnostic(err.stderr),
            ) from err
        except OSError as err:
            raise TrivyExecutionError(f"Failed to execute Trivy command: {err}") from err

        stdout = _truncate_diagnostic(proc.stdout)
        stderr = _truncate_diagnostic(proc.stderr)

        if proc.returncode != 0:
            detail = stderr.strip() or stdout.strip() or "no diagnostic output"
            raise TrivyExecutionError(
                f"Trivy exited with non-zero code {proc.returncode}: {detail}",
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
            )

        if not output_file.is_file():
            raise TrivyInvalidOutputError(
                f"Trivy exited with code 0 but did not produce expected output file: {output_file}"
            )

        file_size = output_file.stat().st_size
        if file_size == 0:
            raise TrivyInvalidOutputError(f"Trivy output file is empty: {output_file}")
        if file_size > self.max_output_bytes:
            raise TrivyInvalidOutputError(
                f"Trivy output size ({file_size} bytes) exceeds max limit "
                f"({self.max_output_bytes} bytes)."
            )

        raw_text = output_file.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as err:
            raise TrivyInvalidOutputError(
                f"Trivy produced malformed JSON in {output_file}: {err}"
            ) from err

        if not isinstance(parsed, dict):
            raise TrivyInvalidOutputError(
                f"Expected Trivy JSON object root, received {type(parsed).__name__}."
            )

        return TrivyCommandResult(
            command=cmd,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            output_path=output_file,
            raw_text=raw_text,
            parsed_json=parsed,
        )
