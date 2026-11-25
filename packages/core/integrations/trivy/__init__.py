"""Trivy CLI integration and report parsing adapters."""

from packages.core.integrations.trivy.client import (
    TrivyClient,
    TrivyCommandResult,
    TrivyError,
    TrivyExecutionError,
    TrivyInvalidOutputError,
    TrivyNotFoundError,
    TrivyTimeoutError,
    TrivyVersionInfo,
)
from packages.core.integrations.trivy.parser import (
    TrivyParseError,
    TrivyRawPackage,
    TrivyRawVulnerability,
    TrivyReport,
    TrivyReportParser,
    TrivyResultBlock,
)

__all__ = [
    "TrivyClient",
    "TrivyCommandResult",
    "TrivyError",
    "TrivyExecutionError",
    "TrivyInvalidOutputError",
    "TrivyNotFoundError",
    "TrivyTimeoutError",
    "TrivyVersionInfo",
    "TrivyParseError",
    "TrivyRawPackage",
    "TrivyRawVulnerability",
    "TrivyReport",
    "TrivyReportParser",
    "TrivyResultBlock",
]
