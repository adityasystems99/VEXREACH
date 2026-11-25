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
    max_python_files: int = Field(
        default=5000,
        ge=1,
        description="Maximum number of Python source files analyzed per repository",
    )
    max_graph_nodes: int = Field(
        default=50000,
        ge=10,
        description="Maximum call graph nodes allowed before recording truncation",
    )
    max_graph_edges: int = Field(
        default=200000,
        ge=10,
        description="Maximum call graph edges allowed before recording truncation",
    )

    # Discovery Engine & Trivy Integration
    trivy_path: str = Field(
        default="trivy",
        description="Executable name or absolute path to the Trivy CLI binary",
    )
    trivy_timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Maximum execution timeout in seconds for a single Trivy invocation",
    )
    max_scanner_output_bytes: int = Field(
        default=50 * 1024 * 1024,
        ge=1024,
        description="Maximum raw scanner JSON / SBOM file size (50MB) permitted during ingestion",
    )
    default_output_dir: Path = Field(
        default=Path(".vexreach/assessments"),
        description="Default root directory for persisting Discovery evidence and reports",
    )

    # Vulnerability Intelligence & OSV.dev Integration
    osv_api_base_url: str = Field(
        default="https://api.osv.dev/v1",
        description="Base URL for the official OSV.dev v1 API",
    )
    osv_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="HTTP request timeout in seconds for OSV API calls",
    )
    osv_max_response_bytes: int = Field(
        default=20 * 1024 * 1024,
        ge=1024,
        description="Maximum HTTP response body size (20MB) allowed from OSV API",
    )
    osv_batch_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum queries per OSV /v1/querybatch request",
    )
    osv_max_pages: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum pagination continuations followed per query",
    )
    osv_max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retry attempts on rate-limit (429) or transient 5xx responses",
    )
    osv_cache_enabled: bool = Field(
        default=True,
        description="Enable SQLite local advisory cache to avoid redundant OSV requests",
    )
    osv_cache_ttl_seconds: int = Field(
        default=86400,
        ge=0,
        description="Time-to-live in seconds before cached OSV records require revalidation",
    )
    osv_user_agent: str = Field(
        default="VEXReach/0.1.0 (+https://github.com/vexreach/vexreach)",
        description="User-Agent header sent on OSV API requests",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()
