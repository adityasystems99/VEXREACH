"""Centralized application settings using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
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

    # Go Static Reachability Engine
    go_path: str = Field(
        default="go",
        description="Executable name or absolute path to Go CLI binary for Go AST/type reachability",
    )
    go_analyzer_binary_path: str | None = Field(
        default=None,
        description="Optional precompiled vexreach-go-analyze binary path bypassing go run/build",
    )
    go_timeout_seconds: int = Field(
        default=120,
        ge=5,
        le=1800,
        description="Maximum execution timeout in seconds for Go static reachability analysis",
    )
    max_go_files: int = Field(
        default=5000,
        ge=1,
        description="Maximum number of Go source files analyzed per repository",
    )
    max_go_output_bytes: int = Field(
        default=50 * 1024 * 1024,
        ge=1024,
        description="Maximum JSON report payload size accepted from Go analyzer",
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

    # AI Security Intelligence & Patch Retrieval
    llm_provider: Literal[
        "disabled",
        "heuristic",
        "openai",
        "openai_compatible",
        "openrouter",
        "anthropic",
        "gemini",
        "ollama",
    ] = Field(
        default="disabled",
        description="Interchangeable LLM provider mode for advisory/patch symbol extraction",
    )
    llm_model: str = Field(
        default="gpt-4o-mini",
        description="Model identifier passed to configured LLM provider",
    )
    llm_api_base_url: str | None = Field(
        default=None,
        description="Optional OpenAI-compatible, OpenRouter, Gemini, or local Ollama/vLLM base URL",
    )
    llm_api_key: SecretStr | None = Field(
        default=None,
        description="Optional API key loaded securely from VEXREACH_LLM_API_KEY env var",
    )
    llm_timeout_seconds: float = Field(
        default=45.0,
        ge=1.0,
        le=300.0,
        description="HTTP timeout in seconds for structured LLM calls",
    )
    llm_max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Bounded retry count for transient 429/5xx LLM responses",
    )
    llm_max_response_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        description="Maximum LLM JSON response payload size permitted",
    )
    patch_fetch_timeout_seconds: float = Field(
        default=20.0,
        ge=1.0,
        le=120.0,
        description="Timeout in seconds for fetching upstream patch diffs",
    )
    patch_max_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        description="Maximum upstream patch diff size permitted (2MB)",
    )
    patch_allowed_hosts: list[str] = Field(
        default_factory=lambda: ["github.com", "api.github.com", "raw.githubusercontent.com"],
        description="Allowlisted HTTPS hosts permitted for automated upstream patch retrieval",
    )

    # Threat Intelligence Feeds (EPSS & CISA KEV)
    epss_api_url: str = Field(
        default="https://api.first.org/data/v1/epss",
        description="FIRST.org EPSS API endpoint URL",
    )
    kev_catalog_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="Official CISA KEV JSON catalog URL",
    )
    threat_feed_timeout_seconds: float = Field(
        default=15.0,
        ge=1.0,
        le=120.0,
        description="HTTP timeout for EPSS / CISA KEV requests",
    )
    threat_feed_max_bytes: int = Field(
        default=20 * 1024 * 1024,
        ge=1024,
        description="Max HTTP payload permitted from EPSS or CISA KEV feed",
    )

    # Backend API Server, Governance & Kubernetes Options
    api_host: str = Field(default="127.0.0.1", description="Bind host for FastAPI REST server")
    api_port: int = Field(default=8000, ge=1, le=65535, description="Bind port for FastAPI server")
    api_auth_enabled: bool = Field(
        default=False,
        description="Enforce Bearer API-key authentication & RBAC on REST endpoints",
    )
    api_keys: SecretStr | None = Field(
        default=None,
        description="Comma-separated key:role mappings (e.g. token1:admin,token2:viewer)",
    )
    api_max_request_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=1024,
        description="Maximum JSON request body size accepted by API",
    )
    api_rate_limit_per_minute: int = Field(
        default=120,
        ge=1,
        description="Per-client in-memory API rate limit per minute",
    )
    api_cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="Explicitly allowed CORS origins for external frontend integration",
    )
    data_retention_days: int = Field(
        default=90,
        ge=1,
        description="Configured retention window in days for stored assessment records",
    )
    kubernetes_enabled: bool = Field(
        default=False,
        description="Enable optional Kubernetes cluster backend adapter (false by default)",
    )
    kubernetes_namespace: str = Field(
        default="default",
        description="Target namespace boundary when Kubernetes discovery/Jobs are enabled",
    )
    kubeconfig_path: str | None = Field(
        default=None,
        description="Optional explicit kubeconfig path when running outside a cluster",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()
