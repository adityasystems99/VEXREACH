"""Unit tests for logging infrastructure and JSON formatting."""

import json
import logging
import pytest
from packages.core.utils.logging import JSONFormatter, get_logger, setup_logging


@pytest.mark.unit
def test_json_formatter() -> None:
    """Verify that JSONFormatter produces valid JSON with required keys."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test log message: %s",
        args=("val",),
        exc_info=None,
    )
    # Add custom extra attribute
    record.cve_id = "CVE-2023-12345"  # type: ignore

    formatted = formatter.format(record)
    data = json.loads(formatted)

    assert data["level"] == "INFO"
    assert data["logger"] == "test_logger"
    assert data["message"] == "Test log message: val"
    assert data["cve_id"] == "CVE-2023-12345"
    assert "timestamp" in data


@pytest.mark.unit
def test_get_logger() -> None:
    """Verify that get_logger namespaces loggers under 'vexreach'."""
    logger = get_logger("discovery")
    assert logger.name == "vexreach.discovery"


@pytest.mark.unit
def test_setup_logging() -> None:
    """Verify setup_logging configures root log level."""
    setup_logging(level="DEBUG", log_format="console")
    root = logging.getLogger()
    assert root.level == logging.DEBUG
