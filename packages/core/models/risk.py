"""Domain models for explainable contextual Risk Intelligence (Engine 5)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import Field

from packages.core.models.base import VEXReachBaseModel


class RiskPriorityTier(str, Enum):
    """Explainable remediation priority buckets (not exploitability verdicts)."""

    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"
    P4_MITIGATED = "P4_MITIGATED"


class WorkloadContext(VEXReachBaseModel):
    """Deployment environment metadata influencing contextual remediation priority."""

    workload_name: str = Field(default="default-workload", min_length=1)
    internet_facing: bool = Field(default=False)
    criticality: Literal["critical", "high", "medium", "low"] = "medium"
    mitigating_controls: list[str] = Field(default_factory=list)


class ThreatIntelligenceSignals(VEXReachBaseModel):
    """Retrieved external exploitation signals (EPSS and CISA KEV)."""

    cve_id: str = Field(..., min_length=1)
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    in_cisa_kev: bool | None = Field(default=None)
    kev_date_added: str | None = Field(default=None)
    kev_due_date: str | None = Field(default=None)
    kev_known_ransomware_use: str | None = Field(default=None)
    sources_consulted: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScoreFactorContribution(VEXReachBaseModel):
    """Single deterministic factor contribution to a contextual risk score."""

    factor_name: str = Field(..., min_length=1)
    points: float
    rationale: str = Field(..., min_length=1)
    evidence_basis: str = Field(default="")


class VulnerabilityRiskAssessment(VEXReachBaseModel):
    """Explainable risk assessment preserving separation between security facts and score."""

    vulnerability_id: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    ecosystem: str = Field(..., min_length=1)
    contextual_score: float = Field(..., ge=0.0, le=100.0)
    priority_tier: RiskPriorityTier
    # Explicit non-conflation state indicators required across CLI & API responses:
    vulnerable_dependency_detected: bool = True
    candidate_symbol_identified: bool = False
    static_path_identified: bool | None = None
    runtime_execution_observed: bool | None = None
    analysis_incomplete: bool = False
    evidence_insufficient: bool = False
    exploitability_established: bool = False
    cvss_base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    threat_signals: ThreatIntelligenceSignals
    evidence_quality: Literal["high", "medium", "low"]
    score_breakdown: list[ScoreFactorContribution] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    score_note: str = Field(
        default="Deterministic remediation priority score [0-100]; NOT a mathematical probability of exploitation."
    )


class RiskIntelligenceReport(VEXReachBaseModel):
    """Assessment-wide Risk Intelligence summary ranked by priority score."""

    report_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    workload_context: WorkloadContext = Field(default_factory=WorkloadContext)
    findings_scored: int = Field(default=0, ge=0)
    kev_matches: int = Field(default=0, ge=0)
    priority_counts: dict[str, int] = Field(default_factory=dict)
    assessments: list[VulnerabilityRiskAssessment] = Field(default_factory=list)
    methodology_notes: list[str] = Field(
        default_factory=lambda: [
            "Contextual score combines CVSS, optional EPSS/CISA KEV, static reachability, attack-path exposure/barriers, and evidence quality deterministically.",
            "Scores are deterministic remediation priorities, never probabilities of exploitation, and never assigned by an LLM.",
        ]
    )
    warnings: list[str] = Field(default_factory=list)
