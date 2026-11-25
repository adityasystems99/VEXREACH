"""Unit tests for configuration and settings loading."""

import pytest
from packages.core.config.settings import Settings, get_settings


@pytest.mark.unit
def test_default_settings() -> None:
    """Verify default settings instantiation."""
    settings = Settings()
    assert settings.app_name == "VEXReach"
    assert settings.app_version == "0.1.0"
    assert settings.environment == "development"
    assert settings.max_graph_depth == 15
    assert settings.max_call_paths == 50


@pytest.mark.unit
def test_singleton_get_settings() -> None:
    """Verify that get_settings provides a cached instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


@pytest.mark.unit
def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that environment variables override defaults."""
    monkeypatch.setenv("VEXREACH_ENVIRONMENT", "production")
    monkeypatch.setenv("VEXREACH_MAX_GRAPH_DEPTH", "25")
    custom_settings = Settings()
    assert custom_settings.environment == "production"
    assert custom_settings.max_graph_depth == 25
