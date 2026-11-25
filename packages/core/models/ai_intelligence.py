"""Domain models for AI Security Intelligence, upstream patches, and symbol extraction."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import Field

from packages.core.models.base import VEXReachBaseModel
from packages.core.models.reachability import (
    CandidateVulnerableSymbol,
    SymbolSource,
    VulnerabilitySymbolManifest,
)


class PatchFetchStatus(str, Enum):
    """Outcome of retrieving an upstream commit/patch artifact."""

    RETRIEVED = "retrieved"
    LOCAL_FIXTURE = "local_fixture"
    UNAVAILABLE = "unavailable"
    BLOCKED_UNTRUSTED_URL = "blocked_untrusted_url"
    SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
    FETCH_ERROR = "fetch_error"


class ModifiedSymbolDiff(VEXReachBaseModel):
    """Function, method, or class identified within an upstream vulnerability patch."""

    file_path: str = Field(..., min_length=1)
    module_name: str = Field(..., min_length=1)
    qualified_name: str = Field(..., min_length=1)
    symbol_type: Literal["function", "method", "class"] = "function"
    change_type: Literal["modified", "added", "deleted", "context_hunk"] = "modified"
    before_lines: tuple[int, int] | None = Field(default=None)
    after_lines: tuple[int, int] | None = Field(default=None)
    ast_verified_from_source: bool = Field(default=False)


class ParsedPatchRecord(VEXReachBaseModel):
    """Normalized record of an inspected upstream patch/commit diff."""

    vulnerability_id: str = Field(..., min_length=1)
    source_ref: str = Field(..., min_length=1)
    fetch_status: PatchFetchStatus
    patch_sha256: str | None = Field(default=None)
    changed_files: list[str] = Field(default_factory=list)
    modified_symbols: list[ModifiedSymbolDiff] = Field(default_factory=list)
    diff_excerpt: str = Field(default="")
    warnings: list[str] = Field(default_factory=list)


class PromptInjectionSignal(VEXReachBaseModel):
    """Detected prompt-injection attempt inside untrusted advisory or patch text."""

    source_field: str = Field(..., min_length=1)
    pattern_name: str = Field(..., min_length=1)
    matched_excerpt: str = Field(..., min_length=1)
    severity: Literal["warning", "high"] = "warning"


class RejectedSymbolCandidate(VEXReachBaseModel):
    """Candidate symbol rejected by deterministic package or AST validation."""

    module: str = Field(..., min_length=1)
    qualified_name: str = Field(..., min_length=1)
    source: SymbolSource
    reason: str = Field(..., min_length=1)
    provider: str | None = Field(default=None)


class AIAdvisoryVulnerabilityAnalysis(VEXReachBaseModel):
    """Per-vulnerability AI + deterministic patch symbol extraction record."""

    vulnerability_id: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    ecosystem: str = Field(..., min_length=1)
    mechanism_summary: str = Field(default="")
    affected_component_hint: str | None = Field(default=None)
    patch_records: list[ParsedPatchRecord] = Field(default_factory=list)
    accepted_symbols: list[CandidateVulnerableSymbol] = Field(default_factory=list)
    rejected_symbols: list[RejectedSymbolCandidate] = Field(default_factory=list)
    prompt_injection_signals: list[PromptInjectionSignal] = Field(default_factory=list)
    llm_provider_used: str | None = Field(default=None)
    llm_model_used: str | None = Field(default=None)
    confidence_notes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AIAdvisoryIntelligenceReport(VEXReachBaseModel):
    """Aggregate report and validated symbol manifest produced by AI Security Intelligence."""

    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    llm_provider: str = Field(default="disabled")
    llm_model: str | None = Field(default=None)
    vulnerabilities_processed: int = Field(default=0, ge=0)
    patches_retrieved: int = Field(default=0, ge=0)
    candidates_accepted: int = Field(default=0, ge=0)
    candidates_rejected: int = Field(default=0, ge=0)
    prompt_injections_detected: int = Field(default=0, ge=0)
    analyses: list[AIAdvisoryVulnerabilityAnalysis] = Field(default_factory=list)
    generated_manifest: VulnerabilitySymbolManifest = Field(
        default_factory=VulnerabilitySymbolManifest
    )
    raw_patch_evidence_path: str | None = Field(default=None)
    raw_patch_evidence_sha256: str | None = Field(default=None)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
