"""Isolated parser for Trivy filesystem vulnerability JSON output."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class TrivyParseError(Exception):
    """Raised when raw Trivy JSON fails structural schema validation."""


class _TrivyBoundaryModel(BaseModel):
    """Tolerant boundary model ignoring undocumented vendor extension fields."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class TrivyCVSSEntry(_TrivyBoundaryModel):
    """Vendor-provided CVSS scores embedded within a Trivy vulnerability object."""

    v2_vector: str | None = Field(default=None, alias="V2Vector")
    v2_score: float | None = Field(default=None, alias="V2Score")
    v3_vector: str | None = Field(default=None, alias="V3Vector")
    v3_score: float | None = Field(default=None, alias="V3Score")
    v40_vector: str | None = Field(default=None, alias="V40Vector")
    v40_score: float | None = Field(default=None, alias="V40Score")


class TrivyRawPackage(_TrivyBoundaryModel):
    """Package entry emitted inside Trivy Result.Packages."""

    pkg_id: str | None = Field(default=None, alias="ID")
    name: str = Field(..., min_length=1, alias="Name")
    version: str | None = Field(default=None, alias="Version")
    identifier: dict[str, Any] = Field(default_factory=dict, alias="Identifier")
    relationship: str | None = Field(default=None, alias="Relationship")
    depends_on: list[str] = Field(default_factory=list, alias="DependsOn")

    @field_validator("identifier", mode="before")
    @classmethod
    def _none_to_dict(cls, value: Any) -> Any:
        return {} if value is None else value

    @field_validator("depends_on", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


class TrivyRawVulnerability(_TrivyBoundaryModel):
    """Raw vulnerability object emitted inside Trivy Result.Vulnerabilities."""

    vulnerability_id: str = Field(..., min_length=1, alias="VulnerabilityID")
    pkg_id: str | None = Field(default=None, alias="PkgID")
    pkg_name: str = Field(..., min_length=1, alias="PkgName")
    pkg_identifier: dict[str, Any] = Field(default_factory=dict, alias="PkgIdentifier")
    installed_version: str | None = Field(default=None, alias="InstalledVersion")
    fixed_version: str | None = Field(default=None, alias="FixedVersion")
    status: str | None = Field(default=None, alias="Status")
    title: str | None = Field(default=None, alias="Title")
    description: str | None = Field(default=None, alias="Description")
    severity: str | None = Field(default=None, alias="Severity")
    severity_source: str | None = Field(default=None, alias="SeveritySource")
    primary_url: str | None = Field(default=None, alias="PrimaryURL")
    references: list[str] = Field(default_factory=list, alias="References")
    cwe_ids: list[str] = Field(default_factory=list, alias="CweIDs")
    cvss: dict[str, TrivyCVSSEntry] = Field(default_factory=dict, alias="CVSS")
    data_source: dict[str, Any] = Field(default_factory=dict, alias="DataSource")

    @field_validator("pkg_identifier", "cvss", "data_source", mode="before")
    @classmethod
    def _none_to_dict(cls, value: Any) -> Any:
        return {} if value is None else value

    @field_validator("references", "cwe_ids", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


class TrivyResultBlock(_TrivyBoundaryModel):
    """Per-manifest/target scan result block within a Trivy JSON report."""

    target: str = Field(..., min_length=1, alias="Target")
    result_class: str | None = Field(default=None, alias="Class")
    result_type: str | None = Field(default=None, alias="Type")
    packages: list[TrivyRawPackage] = Field(default_factory=list, alias="Packages")
    vulnerabilities: list[TrivyRawVulnerability] = Field(
        default_factory=list,
        alias="Vulnerabilities",
    )

    @field_validator("packages", "vulnerabilities", mode="before")
    @classmethod
    def _null_list_to_empty(cls, value: Any) -> Any:
        return [] if value is None else value


class TrivyReport(_TrivyBoundaryModel):
    """Validated top-level Trivy JSON vulnerability report."""

    schema_version: int | None = Field(default=None, alias="SchemaVersion")
    artifact_name: str | None = Field(default=None, alias="ArtifactName")
    artifact_type: str | None = Field(default=None, alias="ArtifactType")
    results: list[TrivyResultBlock] = Field(default_factory=list, alias="Results")

    @field_validator("results", mode="before")
    @classmethod
    def _null_results_to_empty(cls, value: Any) -> Any:
        return [] if value is None else value


class TrivyReportParser:
    """Validates and parses raw Trivy JSON dictionaries into TrivyReport."""

    def parse(self, raw_payload: dict[str, Any]) -> TrivyReport:
        """Parse a Trivy JSON report dict, rejecting non-Trivy structures."""
        if not isinstance(raw_payload, dict):
            raise TrivyParseError("Trivy report root must be a JSON object.")

        # Guard against silently treating arbitrary JSON objects (e.g., {"foo": "bar"})
        # as a clean Trivy scan with zero vulnerabilities.
        has_trivy_marker = any(
            key in raw_payload for key in ("SchemaVersion", "Results", "ArtifactType", "ArtifactName")
        )
        if not has_trivy_marker:
            raise TrivyParseError(
                "JSON payload does not contain expected Trivy report keys "
                "(SchemaVersion, ArtifactName, ArtifactType, or Results)."
            )

        try:
            return TrivyReport.model_validate(raw_payload)
        except ValidationError as err:
            raise TrivyParseError(f"Invalid Trivy JSON structure: {err}") from err
