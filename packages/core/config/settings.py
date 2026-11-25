"""Centralized application settings using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """VEXReach configuration loaded from environment variables and defaults."""

    model_config = SettingsConfigDict(
        env_prefix="VEXREACH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "VEXReach"
    app_version: str = "0.1.0"
    environment: Literal["development", "testing", "production"] = "development"

    # Logging
    log_level: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR")
    log_format: Literal["console", "json"] = Field(
        default="console", description="Format for logs: console (human readable) or json"
    )

    # Storage
    storage_path: Path = Field(
        default=Path(".vexreach/vexreach.db"),
        description="Path to SQLite database file for evidence persistence",
    )

    # Static Analysis Safeguards (Denial-of-Service Defenses)
    max_graph_depth: int = Field(
        default=15, description="Maximum call graph traversal depth before terminating search"
    )
    max_call_paths: int = Field(
        default=50, description="Maximum number of call paths recorded between entry and sink"
    )
    max_file_size_bytes: int = Field(
        default=5 * 1024 * 1024, description="Max source file size (5MB) to parse"
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()
