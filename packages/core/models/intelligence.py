"""Canonical Pydantic domain models for the VEXReach Vulnerability Intelligence Engine."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import Field

from packages.core.models.base import VEXReachBaseModel


class IntelligenceStatus(str, Enum):
    """Enrichment status for a vulnerability finding or overall intelligence report."""

    ENRICHED = "enriched"
    PARTIALLY_ENRICHED = "partially_enriched"
    FAILED = "failed"
    NO_FINDINGS = "no_findings"


class CorrelationOutcome(str, Enum):
    """Explicit correlation classification between scanner findings and authoritative advisories."""

    EXACT_IDENTIFIER_MATCH = "exact_identifier_match"
    AUTHORITATIVE_ALIAS_MATCH = "authoritative_alias_match"
    PACKAGE_VERSION_MATCH = "package_version_match"
    PARTIAL_MATCH = "partial_match"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    NO_MATCH = "no_match"


class VersionMatchStatus(str, Enum):
    """Three-valued version range evaluation result preserving uncertainty."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class OSVRangeType(str, Enum):
    """Documented OSV affected version range schemes."""

    SEMVER = "SEMVER"
    ECOSYSTEM = "ECOSYSTEM"
    GIT = "GIT"
    UNKNOWN = "UNKNOWN"


class SeverityInfo(VEXReachBaseModel):
    """Structured severity or CVSS vector entry reported by an advisory source."""

    scheme: str = Field(..., min_length=1, description="e.g., CVSS_V3, CVSS_V4, CVSS_V2, ECOSYSTEM")
    score: str = Field(..., min_length=1, description="CVSS vector string or ecosystem score text")
    base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    source: str | None = Field(default=None)


class AdvisoryReference(VEXReachBaseModel):
    """Typed external reference attached to an advisory."""

    ref_type: str = Field(default="WEB", min_length=1)
    url: str = Field(..., min_length=1)


class RangeEvent(VEXReachBaseModel):
    """Single chronological boundary event within an OSV version range."""

    event_type: Literal["introduced", "fixed", "last_affected", "limit"]
    value: str = Field(..., min_length=1)


class AffectedPackageRange(VEXReachBaseModel):
    """Normalized affected package entry and its preserved OSV version range events."""

    ecosystem: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    purl: str | None = Field(default=None)
    affected_versions: list[str] = Field(default_factory=list)
    introduced_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    last_affected_versions: list[str] = Field(default_factory=list)
    limit_versions: list[str] = Field(default_factory=list)
    events: list[RangeEvent] = Field(default_factory=list)
    range_type: OSVRangeType = Field(default=OSVRangeType.UNKNOWN)
    repo: str | None = Field(default=None)
    ecosystem_specific: dict[str, Any] = Field(default_factory=dict)
    database_specific: dict[str, Any] = Field(default_factory=dict)


class AdvisoryRecord(VEXReachBaseModel):
    """Authoritative vulnerability advisory normalized from OSV.dev (or future feeds)."""

    advisory_id: str = Field(..., min_length=1)
    aliases: list[str] = Field(default_factory=list)
    summary: str = Field(default="")
    details: str = Field(default="")
    published_at: datetime | None = Field(default=None)
    modified_at: datetime | None = Field(default=None)
    withdrawn_at: datetime | None = Field(default=None)
    is_withdrawn: bool = Field(default=False)
    references: list[AdvisoryReference] = Field(default_factory=list)
    severity_information: list[SeverityInfo] = Field(default_factory=list)
    affected_ranges: list[AffectedPackageRange] = Field(default_factory=list)
    source: str = Field(default="osv", min_length=1)
    source_url: str | None = Field(default=None)
    retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    from_cache: bool = Field(default=False)
    raw_source_metadata: dict[str, Any] = Field(default_factory=dict)


class VersionEvaluationResult(VEXReachBaseModel):
    """Detailed explanation of evaluating an installed package version against an affected range."""

    advisory_id: str = Field(..., min_length=1)
    package_id: str = Field(..., min_length=1)
    installed_version: str | None = Field(default=None)
    ecosystem: str = Field(..., min_length=1)
    status: VersionMatchStatus
    explanation: str = Field(..., min_length=1)
    matched_range_type: str | None = Field(default=None)
    evaluated_events: list[RangeEvent] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)


class CorrelationEvidence(VEXReachBaseModel):
    """Audit trail explaining how an advisory was correlated to a scanner finding."""

    advisory_id: str = Field(..., min_length=1)
    outcome: CorrelationOutcome
    reason: str = Field(..., min_length=1)
    matched_identifiers: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)


class PackageQueryRecord(VEXReachBaseModel):
    """Traceable status of an individual OSV package or advisory query."""

    package_id: str = Field(..., min_length=1)
    query_type: Literal["purl", "ecosystem_name", "vuln_id"]
    query_payload: dict[str, Any] = Field(default_factory=dict)
    succeeded: bool
    from_cache: bool = Field(default=False)
    advisory_ids_found: list[str] = Field(default_factory=list)
    error: str | None = Field(default=None)


class VulnerabilityIntelligence(VEXReachBaseModel):
    """Enriched vulnerability record preserving scanner finding, advisories, and correlations."""

    vulnerability_id: str = Field(..., min_length=1)
    canonical_id: str = Field(..., min_length=1)
    aliases: list[str] = Field(default_factory=list)
    package_id: str = Field(..., min_length=1)
    advisories: list[AdvisoryRecord] = Field(default_factory=list)
    affected_ranges: list[AffectedPackageRange] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    severity_information: list[SeverityInfo] = Field(default_factory=list)
    version_evaluations: list[VersionEvaluationResult] = Field(default_factory=list)
    correlation_decisions: list[CorrelationEvidence] = Field(default_factory=list)
    overall_correlation: CorrelationOutcome = Field(default=CorrelationOutcome.NO_MATCH)
    overall_version_status: VersionMatchStatus = Field(default=VersionMatchStatus.UNKNOWN)
    source_records: list[str] = Field(default_factory=list)
    intelligence_status: IntelligenceStatus
    retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    data_quality_warnings: list[str] = Field(default_factory=list)


class VulnerabilityIntelligenceReport(VEXReachBaseModel):
    """Assessment-wide intelligence summary and enriched records."""

    assessment_id: str = Field(..., min_length=1)
    intelligence_status: IntelligenceStatus
    retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    findings_discovered: int = Field(default=0, ge=0)
    advisories_retrieved: int = Field(default=0, ge=0)
    identifier_correlations: int = Field(default=0, ge=0)
    affected_ranges_evaluated: int = Field(default=0, ge=0)
    conflicting_records: int = Field(default=0, ge=0)
    incomplete_intelligence_records: int = Field(default=0, ge=0)
    withdrawn_advisories: int = Field(default=0, ge=0)
    cache_hits: int = Field(default=0, ge=0)
    batch_queries_executed: int = Field(default=0, ge=0)
    individual_queries_executed: int = Field(default=0, ge=0)
    package_queries: list[PackageQueryRecord] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityIntelligence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    raw_osv_evidence_path: str | None = Field(default=None)
    raw_osv_sha256: str | None = Field(default=None)
