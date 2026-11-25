"""Canonical Pydantic domain models for the VEXReach Discovery Engine."""

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from packages.core.models.ai_intelligence import AIAdvisoryIntelligenceReport
from packages.core.models.attack_path import AttackPathReport
from packages.core.models.base import VEXReachBaseModel
from packages.core.models.extensions import RuntimeEvidenceReport
from packages.core.models.intelligence import VulnerabilityIntelligenceReport
from packages.core.models.openvex import OpenVEXPolicyReport
from packages.core.models.reachability import StaticReachabilityReport
from packages.core.models.risk import RiskIntelligenceReport


def _coerce_path_to_str(value: Any) -> Any:
    """Allow Path instances to be passed ergonomically into canonical string path fields."""
    if isinstance(value, Path):
        return str(value)
    return value


class TargetType(str, Enum):
    """Supported assessment target types."""

    FILESYSTEM = "filesystem"
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"


class ScanStatus(str, Enum):
    """Execution outcome of a discovery scan."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class SBOMCompletenessStatus(str, Enum):
    """Completeness state of the generated or ingested SBOM."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class DependencyScope(str, Enum):
    """Relationship of a package to the application root."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Normalized vulnerability severity categories."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"
    UNKNOWN = "UNKNOWN"


class AssessmentTarget(VEXReachBaseModel):
    """Validated target subject for vulnerability discovery."""

    target_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for this validated scan target",
    )
    target_path: str = Field(
        ...,
        min_length=1,
        description="Canonicalized target filesystem or repository path",
    )
    target_type: TargetType = Field(
        default=TargetType.FILESYSTEM,
        description="Kind of target scanned",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when target validation occurred",
    )
    detected_ecosystems: list[str] = Field(
        default_factory=list,
        description="Ecosystem hints inferred statically from manifest filenames",
    )
    detected_manifests: list[str] = Field(
        default_factory=list,
        description="Relative manifest filenames discovered within target",
    )

    @field_validator("target_path", mode="before")
    @classmethod
    def _normalize_target_path(cls, value: Any) -> Any:
        return _coerce_path_to_str(value)


class ScanMetadata(VEXReachBaseModel):
    """Operational telemetry, status, and provenance for a scanner execution."""

    scanner_name: str = Field(default="trivy", min_length=1)
    scanner_version: str | None = Field(
        default=None,
        description="Detected scanner semantic version, or None if unavailable",
    )
    scan_started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    scan_completed_at: datetime | None = Field(default=None)
    scan_status: ScanStatus = Field(default=ScanStatus.FAILED)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence_hashes: dict[str, str] = Field(
        default_factory=dict,
        description="Map of artifact filename/role to SHA-256 hex digest",
    )


class PackageRecord(VEXReachBaseModel):
    """Normalized software component discovered in the target."""

    package_id: str = Field(
        ...,
        min_length=1,
        description="Deterministic canonical identifier unique within an assessment",
    )
    name: str = Field(..., min_length=1)
    version: str | None = Field(
        default=None,
        description="Installed package version, or None if unreported",
    )
    ecosystem: str = Field(
        default="unknown",
        min_length=1,
        description="Normalized ecosystem name (pypi, golang, npm, cargo, unknown, etc.)",
    )
    purl: str | None = Field(
        default=None,
        description="Package URL (PURL) if available from SBOM or scanner",
    )
    dependency_scope: DependencyScope = Field(
        default=DependencyScope.UNKNOWN,
        description="Whether dependency is direct, transitive, or unknown",
    )
    source_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw provenance attributes (e.g., manifest location, bom-ref, pkg type)",
    )


class CVSSMetric(VEXReachBaseModel):
    """Structured CVSS scoring metadata supplied by an advisory source."""

    source: str = Field(..., min_length=1, description="Scoring vendor (nvd, ghsa, redhat, etc.)")
    version: str | None = Field(default=None, description="CVSS specification version (e.g., 3.1)")
    base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    vector: str | None = Field(default=None, description="CVSS vector string")


class VulnerabilityRecord(VEXReachBaseModel):
    """Normalized vulnerability finding linked to a PackageRecord by package_id."""

    vulnerability_id: str = Field(
        ...,
        min_length=1,
        description="Primary vulnerability identifier (e.g., CVE-2023-32681, GHSA-xxxx)",
    )
    package_id: str = Field(
        ...,
        min_length=1,
        description="Foreign key referencing PackageRecord.package_id",
    )
    installed_version: str | None = Field(
        default=None,
        description="Version reported by the scanner as installed",
    )
    fixed_version: str | None = Field(
        default=None,
        description="Patched version if known, else None",
    )
    severity: SeverityLevel = Field(default=SeverityLevel.UNKNOWN)
    cvss: list[CVSSMetric] = Field(
        default_factory=list,
        description="Available CVSS scores across advisory sources",
    )
    description: str = Field(default="")
    references: list[str] = Field(default_factory=list)
    primary_url: str | None = Field(default=None)
    source: str = Field(default="trivy", min_length=1)
    detection_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    title: str | None = Field(default=None)
    cwe_ids: list[str] = Field(default_factory=list)


class SBOMRecord(VEXReachBaseModel):
    """Metadata and package index references for an SBOM artifact."""

    sbom_id: str = Field(default_factory=lambda: str(uuid4()))
    format: str = Field(default="cyclonedx", min_length=1)
    format_version: str | None = Field(default=None)
    document_path: str | None = Field(
        default=None,
        description="Path where the raw SBOM file was preserved",
    )
    packages: list[str] = Field(
        default_factory=list,
        description="List of PackageRecord.package_id values represented in this SBOM",
    )
    generation_timestamp: datetime | None = Field(default=None)
    completeness_status: SBOMCompletenessStatus = Field(
        default=SBOMCompletenessStatus.FAILED,
    )
    document_sha256: str | None = Field(default=None)

    @field_validator("document_path", mode="before")
    @classmethod
    def _normalize_document_path(cls, value: Any) -> Any:
        return _coerce_path_to_str(value)


class DiscoveryResult(VEXReachBaseModel):
    """Complete, evidence-backed result of a Discovery Engine assessment."""

    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    target: AssessmentTarget
    scan_metadata: ScanMetadata
    sbom: SBOMRecord
    packages: list[PackageRecord] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityRecord] = Field(default_factory=list)
    intelligence: VulnerabilityIntelligenceReport | None = Field(
        default=None,
        description="Enriched OSV vulnerability intelligence report when enrichment is enabled",
    )
    ai_intelligence: AIAdvisoryIntelligenceReport | None = Field(
        default=None,
        description="AI-assisted advisory & patch symbol intelligence report when enabled",
    )
    reachability: StaticReachabilityReport | None = Field(
        default=None,
        description="Static reachability analysis report when static analysis is executed",
    )
    attack_paths: AttackPathReport | None = Field(
        default=None,
        description="Conservative Attack Path Intelligence report when attack-path analysis runs",
    )
    risk_assessment: RiskIntelligenceReport | None = Field(
        default=None,
        description="Explainable Risk Intelligence report correlating CVSS, EPSS, KEV, and reachability",
    )
    runtime_evidence: RuntimeEvidenceReport | None = Field(
        default=None,
        description="Correlated runtime trace observations and coverage bounds",
    )
    policy_evaluation: OpenVEXPolicyReport | None = Field(
        default=None,
        description="Deterministic OpenVEX 0.2.0 policy evaluation & emitted statements report",
    )
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_referential_integrity(self) -> "DiscoveryResult":
        """Ensure all package_id references in SBOM, vulnerabilities, and intelligence exist."""
        known_pkg_ids = {pkg.package_id for pkg in self.packages}
        if len(known_pkg_ids) != len(self.packages):
            raise ValueError("Duplicate package_id values detected in DiscoveryResult.packages")

        missing_vuln_refs = {
            v.package_id for v in self.vulnerabilities if v.package_id not in known_pkg_ids
        }
        if missing_vuln_refs:
            raise ValueError(
                f"Vulnerabilities reference unknown package_id(s): {sorted(missing_vuln_refs)}"
            )

        missing_sbom_refs = {pid for pid in self.sbom.packages if pid not in known_pkg_ids}
        if missing_sbom_refs:
            raise ValueError(
                f"SBOMRecord.packages references unknown package_id(s): {sorted(missing_sbom_refs)}"
            )

        if self.intelligence is not None:
            missing_intel_refs = {
                v.package_id
                for v in self.intelligence.vulnerabilities
                if v.package_id not in known_pkg_ids
            }
            if missing_intel_refs:
                raise ValueError(
                    "Intelligence vulnerabilities reference unknown package_id(s): "
                    f"{sorted(missing_intel_refs)}"
                )

        return self

    def severity_counts(self) -> dict[str, int]:
        """Return vulnerability counts grouped by normalized severity level."""
        counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts
