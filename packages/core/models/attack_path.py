"""Domain models for Attack Path Intelligence (Milestone 4)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import Field

from packages.core.models.base import VEXReachBaseModel
from packages.core.models.reachability import CodeLocation


class ExposureSurface(str, Enum):
    """Classified application ingress exposure category."""

    NETWORK_HTTP_PUBLIC = "network_http_public"
    NETWORK_HTTP_AUTHENTICATED = "network_http_authenticated"
    CLI_LOCAL_INPUT = "cli_local_input"
    INTERNAL_FUNCTION = "internal_function"
    UNKNOWN = "unknown"


class TaintFlowStatus(str, Enum):
    """Conservative classification distinguishing static call path from data-flow proof."""

    TAINTED_FLOW_OBSERVED = "tainted_flow_observed"
    CALL_PATH_ONLY_TAINT_NOT_PROVEN = "call_path_only_taint_not_proven"
    SANITIZED_OR_VALIDATED = "sanitized_or_validated"
    UNSUPPORTED_DATA_FLOW = "unsupported_data_flow"


class InputSourceRecord(VEXReachBaseModel):
    """External or caller-controlled input entering an entry point."""

    source_kind: str = Field(..., min_length=1)
    variable_name: str = Field(..., min_length=1)
    location: CodeLocation | None = Field(default=None)
    description: str = Field(default="")


class BarrierEvidence(VEXReachBaseModel):
    """Authentication, authorization, or validation guard observed along a path."""

    barrier_type: Literal["authentication", "authorization", "input_validation", "safe_loader"]
    mechanism: str = Field(..., min_length=1)
    location: CodeLocation | None = Field(default=None)
    confidence: Literal["high", "medium", "low"] = "medium"
    notes: str = Field(default="")


class DataFlowStep(VEXReachBaseModel):
    """Single tracked variable or parameter flow step along a call path."""

    function_qualified_name: str = Field(..., min_length=1)
    variable_or_expr: str = Field(..., min_length=1)
    role: Literal[
        "source",
        "propagation",
        "parameter_binding",
        "validation_barrier",
        "sink_argument",
    ]
    location: CodeLocation | None = Field(default=None)


class AttackPathRecord(VEXReachBaseModel):
    """Explainable end-to-end attack path linking exposure, data flow, barriers, and sink."""

    path_id: str = Field(default_factory=lambda: str(uuid4()))
    vulnerability_id: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    target_symbol: str = Field(..., min_length=1)
    entry_point: str = Field(..., min_length=1)
    exposure_surface: ExposureSurface
    is_network_exposed: bool = Field(default=False)
    input_sources: list[InputSourceRecord] = Field(default_factory=list)
    auth_barriers: list[BarrierEvidence] = Field(default_factory=list)
    validation_barriers: list[BarrierEvidence] = Field(default_factory=list)
    call_hops: list[str] = Field(default_factory=list)
    data_flow_status: TaintFlowStatus
    data_flow_steps: list[DataFlowStep] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    explanation: str = Field(..., min_length=1)
    evidence_references: list[str] = Field(default_factory=list)


class AttackPathReport(VEXReachBaseModel):
    """Aggregate Attack Path Intelligence findings for an assessed Python repository."""

    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    paths_evaluated: int = Field(default=0, ge=0)
    network_exposed_paths: int = Field(default=0, ge=0)
    taint_observed_paths: int = Field(default=0, ge=0)
    call_path_only_paths: int = Field(default=0, ge=0)
    paths: list[AttackPathRecord] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
