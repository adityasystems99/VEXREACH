"""OpenVEX 0.2.0 compliant data models for standardized security advisories."""

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4
from pydantic import Field
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

    subcomponents: list[str] = Field(default_factory=list, description="List of PURLs representing subcomponents")


class VEXStatement(VEXReachBaseModel):
    """An individual OpenVEX statement asserting vulnerability status for a product."""

    vulnerability: dict[str, str] = Field(..., description="Object with 'name' or 'aliases' identifying the CVE")
    products: list[str] = Field(..., description="Identifiers (PURLs) of target products")
    status: VEXStatus
    justification: VEXJustification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    status_notes: str | None = None


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
    author: str = Field(default="VEXReach Automated Assessment Engine")
    role: str = Field(default="Tool")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 creation timestamp",
    )
    version: int = Field(default=1, description="Document revision number")
    tooling: str = Field(default="VEXReach v0.1.0")
    statements: list[VEXStatement] = Field(default_factory=list)
