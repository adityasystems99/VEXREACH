"""Versioned REST API v1 request/response contracts strictly separating security states."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from packages.core.models.attack_path import AttackPathReport
from packages.core.models.discovery import PackageRecord
from packages.core.models.extensions import (
    ContinuousReassessmentPlan,
    PackageUpgradeProposal,
    RuntimeEvidenceReport,
    WhatIfSimulationReport,
)
from packages.core.models.openvex import OpenVEXPolicyReport
from packages.core.models.reachability import StaticReachabilityReport
from packages.core.models.risk import RiskIntelligenceReport, WorkloadContext


class APISchemaBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(APISchemaBase):
    status: Literal["ok"] = "ok"
    service: str = "vexreach-api"
    version: str
    api_version: str = "v1"


class ReadinessResponse(APISchemaBase):
    status: Literal["ready", "degraded"]
    storage_writable: bool
    output_dir_accessible: bool
    checks: dict[str, bool]


class ErrorEnvelope(APISchemaBase):
    error_code: str
    message: str
    request_id: str | None = None


class AssessmentCreateRequest(APISchemaBase):
    target_path: str = Field(..., min_length=1)
    enrich_osv: bool = False
    extract_symbols: bool = False
    patch_dir: str | None = None
    symbols_file: str | None = None
    entry_points_file: str | None = None
    dependency_source_dirs: list[str] = Field(default_factory=list)
    analyze_python: bool = True
    analyze_go: bool = True
    attack_paths: bool = False
    compute_risk: bool = True
    emit_vex: bool = True
    workload_context: WorkloadContext = Field(default_factory=WorkloadContext)
    async_execution: bool = True


class JobStatusResponse(APISchemaBase):
    job_id: str
    assessment_id: str | None = None
    target_path: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class AssessmentSummaryItem(APISchemaBase):
    assessment_id: str
    target_path: str
    scan_status: str
    sbom_completeness: str
    packages_count: int
    vulnerabilities_count: int
    has_intelligence: bool
    has_reachability: bool
    has_attack_paths: bool
    has_risk: bool
    has_openvex: bool
    scan_started_at: datetime
    scan_completed_at: datetime | None = None


class PaginatedAssessmentsResponse(APISchemaBase):
    total: int
    limit: int
    offset: int
    items: list[AssessmentSummaryItem]


class VulnerabilityNonConflatedView(APISchemaBase):
    """Strict non-conflated view preserving distinct security assessment states."""

    vulnerability_id: str
    canonical_id: str
    aliases: list[str] = Field(default_factory=list)
    package_id: str
    package_name: str
    package_version: str | None = None
    ecosystem: str
    severity: str
    fixed_versions: list[str] = Field(default_factory=list)
    # Explicitly separated security assertions:
    vulnerable_dependency_detected: bool = True
    candidate_symbol_identified: bool = False
    candidate_symbols: list[str] = Field(default_factory=list)
    static_path_identified: bool | None = None
    reachability_state: str | None = None
    runtime_execution_observed: bool | None = None
    analysis_incomplete: bool = False
    evidence_insufficient: bool = False
    exploitability_established: bool = False
    attack_surface: str | None = None
    data_flow_status: str | None = None
    contextual_risk_score: float | None = None
    risk_priority_tier: str | None = None
    openvex_status: str | None = None
    openvex_justification: str | None = None


class PaginatedVulnerabilitiesResponse(APISchemaBase):
    assessment_id: str
    total: int
    limit: int
    offset: int
    items: list[VulnerabilityNonConflatedView]


class PaginatedDependenciesResponse(APISchemaBase):
    assessment_id: str
    total: int
    limit: int
    offset: int
    items: list[PackageRecord]


class RuntimeObservationInput(APISchemaBase):
    """REST JSON payload for submitting runtime trace observations."""

    qualified_symbol: str = Field(..., min_length=1)
    workload_name: str = Field(default="default-workload", min_length=1)
    container_name: str | None = Field(default=None)
    image_digest: str | None = Field(default=None)
    process_id: int | None = Field(default=None, ge=0)
    instrumentation_source: str = Field(..., min_length=1)
    observed_at: datetime | None = Field(default=None)
    call_count: int = Field(default=1, ge=1)


class RuntimeObservationsIngestRequest(APISchemaBase):
    observations: list[RuntimeObservationInput] = Field(..., min_length=1)
    instrumentation_coverage_percent: float | None = Field(default=None, ge=0.0, le=100.0)
    re_evaluate_vex_and_risk: bool = True


class SimulationRequest(APISchemaBase):
    proposals: list[PackageUpgradeProposal] = Field(..., min_length=1)


class EvidenceArtifactsResponse(APISchemaBase):
    assessment_id: str
    assessment_dir: str
    evidence_hashes: dict[str, str]
    provenance: dict[str, Any] | None = None


class ReassessmentPlanRequest(APISchemaBase):
    current_target_path: str | None = None
    updated_sbom_package_versions: dict[str, str] | None = None
    new_advisory_vulns: list[str] | None = None


class WebhookCIRequest(APISchemaBase):
    event_type: Literal["push", "pull_request", "advisory_update", "manual"]
    repository: str = Field(..., min_length=1)
    ref: str | None = None
    assessment_id: str | None = None
    updated_sbom_package_versions: dict[str, str] | None = None


class WebhookCIResponse(APISchemaBase):
    accepted: bool
    event_type: str
    reassessment_plan: ContinuousReassessmentPlan | None = None
    note: str


class AuditLogEntryResponse(APISchemaBase):
    id: int
    timestamp: str
    actor_id: str
    actor_role: str
    action: str
    resource: str
    status_code: int
    request_id: str | None = None
    detail: str | None = None
