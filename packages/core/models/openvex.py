"""OpenVEX 0.2.0 compliant data models and deterministic policy evaluation contracts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from packages.core.models.base import VEXReachBaseModel


class VEXStatus(str, Enum):
    """OpenVEX defined status values."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification(str, Enum):
    """OpenVEX defined justification values for 'not_affected' status."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class VEXProduct(VEXReachBaseModel):
    """Identifies a product or subcomponent affected by a statement."""

    id: str | None = Field(default=None, alias="@id")
    subcomponents: list[str | dict[str, Any]] = Field(
        default_factory=list,
        description="List of PURLs or {'@id': purl} objects representing subcomponents",
    )


class VEXStatement(VEXReachBaseModel):
    """An individual OpenVEX 0.2.0 statement asserting vulnerability status for a product."""

    vulnerability: dict[str, Any] = Field(
        ...,
        description="Object with 'name' (and optional '@id', 'description', 'aliases') identifying the CVE",
    )
    products: list[str | dict[str, Any]] = Field(
        ...,
        min_length=1,
        description="Identifiers (PURL strings or {'@id': ...} objects) of target products",
    )
    status: VEXStatus
    justification: VEXJustification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    action_statement_timestamp: str | None = None
    status_notes: str | None = None
    timestamp: str | None = None

    @model_validator(mode="after")
    def _enforce_openvex_020_invariants(self) -> "VEXStatement":
        """Enforce strict OpenVEX 0.2.0 statement validity rules."""
        vuln_name = self.vulnerability.get("name") or self.vulnerability.get("@id")
        if not isinstance(vuln_name, str) or not vuln_name.strip():
            raise ValueError("VEXStatement.vulnerability must define non-empty 'name' or '@id'.")

        if self.status == VEXStatus.NOT_AFFECTED:
            has_just = self.justification is not None
            has_impact = bool(self.impact_statement and self.impact_statement.strip())
            if not (has_just or has_impact):
                raise ValueError(
                    "OpenVEX 'not_affected' statement MUST include 'justification' or 'impact_statement'."
                )
        elif self.justification is not None:
            raise ValueError(
                f"OpenVEX 'justification' is only valid when status is 'not_affected' (got '{self.status.value}')."
            )
        return self


class OpenVEXDocument(VEXReachBaseModel):
    """Full OpenVEX 0.2.0 document container."""

    context: str = Field(
        default="https://openvex.dev/ns/v0.2.0",
        alias="@context",
        description="JSON-LD context URL",
    )
    id: str = Field(
        default_factory=lambda: f"https://vexreach.org/vex/{uuid4()}",
        alias="@id",
        description="Unique IRI identifying this OpenVEX document",
    )
    author: str = Field(default="VEXReach Automated Assessment Engine", min_length=1)
    role: str = Field(default="Tool", min_length=1)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 creation timestamp",
    )
    version: int = Field(default=1, ge=1, description="Monotonic OpenVEX document version")
    tooling: str = Field(default="VEXReach v0.1.0", min_length=1)
    statements: list[VEXStatement] = Field(default_factory=list)

    def to_openvex_json(self) -> str:
        """Serialize strictly to OpenVEX 0.2.0 JSON using `@context`/`@id` aliases."""
        return self.model_dump_json(by_alias=True, exclude_none=True, indent=2)


# ---------------------------------------------------------------------------
# Phase 6 / Milestone 5: Evidence Completeness & Deterministic Policy Audit
# ---------------------------------------------------------------------------


class EvidenceCompletenessReport(VEXReachBaseModel):
    """Explicit completeness gate inputs constraining VEX policy conclusions."""

    scan_completed: bool
    sbom_complete: bool
    intelligence_checked: bool
    intelligence_conflict_free: bool
    reachability_executed: bool
    reachability_complete_without_truncation: bool
    dependency_sources_verified: bool
    blocking_gaps: list[str] = Field(default_factory=list)


class VEXPolicyDecision(VEXReachBaseModel):
    """Auditable deterministic policy decision explaining one OpenVEX statement."""

    vulnerability_id: str = Field(..., min_length=1)
    package_name: str = Field(..., min_length=1)
    product_identifier: str = Field(..., min_length=1)
    decided_status: VEXStatus
    justification: VEXJustification | None = None
    confidence: Literal["high", "medium", "low"]
    decision_rule: str = Field(..., min_length=1)
    rationale: str = Field(..., min_length=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    uncertainty_notes: list[str] = Field(default_factory=list)


class OpenVEXPolicyReport(VEXReachBaseModel):
    """Complete Evidence Aggregation, Policy Evaluation, and OpenVEX emission audit record."""

    evaluation_id: str = Field(default_factory=lambda: str(uuid4()))
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_path: str = Field(..., min_length=1)
    openvex_document: OpenVEXDocument
    openvex_sha256: str | None = Field(default=None)
    openvex_file_path: str | None = Field(default=None)
    schema_valid: bool = Field(default=False)
    schema_errors: list[str] = Field(default_factory=list)
    completeness: EvidenceCompletenessReport
    decisions: list[VEXPolicyDecision] = Field(default_factory=list)
    status_counts: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
