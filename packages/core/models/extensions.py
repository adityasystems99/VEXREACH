"""Domain models for Runtime Evidence, Continuous Reassessment, and What-If Simulation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import Field

from packages.core.models.base import VEXReachBaseModel


class RuntimeObservationRecord(VEXReachBaseModel):
    """Confirmed function-level runtime trace observation correlated with workload identity."""

    observation_id: str = Field(default_factory=lambda: str(uuid4()))
    qualified_symbol: str = Field(..., min_length=1)
    workload_name: str = Field(default="default-workload", min_length=1)
    container_name: str | None = Field(default=None)
    image_digest: str | None = Field(default=None)
    process_id: int | None = Field(default=None, ge=0)
    instrumentation_source: str = Field(..., min_length=1)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    call_count: int = Field(default=1, ge=1)


class RuntimeEvidenceReport(VEXReachBaseModel):
    """Runtime execution trace ingestion report explicitly recording coverage gaps."""

    report_id: str = Field(default_factory=lambda: str(uuid4()))
    assessment_id: str = Field(..., min_length=1)
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    observations: list[RuntimeObservationRecord] = Field(default_factory=list)
    matched_vulnerability_ids: list[str] = Field(default_factory=list)
    instrumentation_coverage_percent: float | None = Field(default=None, ge=0.0, le=100.0)
    instrumentation_limitations: list[str] = Field(
        default_factory=lambda: [
            "Absence of runtime observation NEVER proves unreachability; low traffic or untested code paths may omit execution."
        ]
    )


class ReassessmentTriggerType(str, Enum):
    """Detected change trigger requiring targeted re-evaluation."""

    SOURCE_SNAPSHOT_DRIFT = "source_snapshot_drift"
    SBOM_DEPENDENCY_DRIFT = "sbom_dependency_drift"
    ADVISORY_DRIFT = "advisory_drift"
    RUNTIME_OBSERVATION_ADDED = "runtime_observation_added"


class ContinuousReassessmentPlan(VEXReachBaseModel):
    """Targeted reassessment plan computed from evidence drift without redundant full scans."""

    assessment_id: str = Field(..., min_length=1)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reassessment_required: bool
    triggers: list[ReassessmentTriggerType] = Field(default_factory=list)
    affected_packages: list[str] = Field(default_factory=list)
    affected_vulnerabilities: list[str] = Field(default_factory=list)
    engines_to_rerun: list[str] = Field(default_factory=list)
    explanation: str = Field(..., min_length=1)


class PackageUpgradeProposal(VEXReachBaseModel):
    """Proposed dependency version upgrade to simulate in What-If engine."""

    package_name: str = Field(..., min_length=1)
    target_version: str = Field(..., min_length=1)


class SimulatedVulnerabilityDelta(VEXReachBaseModel):
    """Projected before/after status change for a single vulnerability upon dependency upgrade."""

    vulnerability_id: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    current_version: str | None = Field(default=None)
    proposed_version: str = Field(..., min_length=1)
    current_version_affected: str
    projected_version_affected: str
    projected_status_change: Literal[
        "resolved_in_advisory_ranges",
        "remains_affected",
        "uncertain_range_evaluation",
    ]
    notes: str = Field(default="")


class WhatIfSimulationReport(VEXReachBaseModel):
    """Remediation impact report explicitly requiring isolated test verification."""

    simulation_id: str = Field(default_factory=lambda: str(uuid4()))
    assessment_id: str = Field(..., min_length=1)
    simulated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    proposals: list[PackageUpgradeProposal] = Field(default_factory=list)
    vulnerability_deltas: list[SimulatedVulnerabilityDelta] = Field(default_factory=list)
    potentially_impacted_call_sites: list[str] = Field(default_factory=list)
    validation_status: Literal[
        "pending_isolated_test_verification",
        "advisory_check_only_no_test_run",
    ] = "pending_isolated_test_verification"
    warnings: list[str] = Field(
        default_factory=lambda: [
            "Version bump projection checks OSV ranges and call-graph symbols only; isolated test execution is required before confirming safe remediation."
        ]
    )
