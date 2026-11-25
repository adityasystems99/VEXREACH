"""Pydantic v2 request and boundary response schemas matching api.osv.dev/v1 contracts."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _OSVBoundaryModel(BaseModel):
    """Tolerant boundary base model preserving forward-compatibility with OSV schema extensions."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class OSVPackageSpec(_OSVBoundaryModel):
    """Package identifier block in OSV query requests."""

    name: str | None = Field(default=None)
    ecosystem: str | None = Field(default=None)
    purl: str | None = Field(default=None)

    @model_validator(mode="after")
    def _validate_package_spec(self) -> "OSVPackageSpec":
        has_purl = bool(self.purl and self.purl.strip())
        has_eco_name = bool(
            self.name and self.name.strip() and self.ecosystem and self.ecosystem.strip()
        )
        if not has_purl and not has_eco_name:
            raise ValueError("OSVPackageSpec requires either 'purl' or both 'ecosystem' and 'name'.")
        return self


class OSVQueryRequest(_OSVBoundaryModel):
    """Request payload for POST /v1/query and elements of POST /v1/querybatch."""

    package: OSVPackageSpec | None = Field(default=None)
    version: str | None = Field(default=None)
    commit: str | None = Field(default=None)
    page_token: str | None = Field(default=None)

    @model_validator(mode="after")
    def _validate_query_constraints(self) -> "OSVQueryRequest":
        if self.package is None and not (self.commit and self.commit.strip()):
            raise ValueError("OSVQueryRequest requires either 'package' or 'commit'.")

        # OSV API returns 400 Bad Request if both a versioned PURL and top-level version are sent.
        if (
            self.package is not None
            and self.package.purl
            and "@" in self.package.purl.split("?", 1)[0]
            and self.version is not None
        ):
            raise ValueError(
                "OSV API forbids specifying top-level 'version' alongside a versioned 'purl'."
            )
        return self


class OSVBatchQueryRequest(_OSVBoundaryModel):
    """Request body for POST /v1/querybatch."""

    queries: list[OSVQueryRequest] = Field(..., min_length=1, max_length=1000)


class OSVEvent(_OSVBoundaryModel):
    """Range event object containing exactly one boundary key."""

    introduced: str | None = Field(default=None)
    fixed: str | None = Field(default=None)
    last_affected: str | None = Field(default=None)
    limit: str | None = Field(default=None)


class OSVRange(_OSVBoundaryModel):
    """Version or commit range within an affected block."""

    type: str = Field(..., min_length=1)
    repo: str | None = Field(default=None)
    events: list[OSVEvent] = Field(default_factory=list)
    database_specific: dict[str, Any] = Field(default_factory=dict)

    @field_validator("events", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value

    @field_validator("database_specific", mode="before")
    @classmethod
    def _none_to_dict(cls, value: Any) -> Any:
        return {} if value is None else value


class OSVAffectedPackage(_OSVBoundaryModel):
    """Package descriptor inside an OSV affected item."""

    ecosystem: str | None = Field(default=None)
    name: str | None = Field(default=None)
    purl: str | None = Field(default=None)


class OSVAffected(_OSVBoundaryModel):
    """Affected package entry describing impacted versions and ranges."""

    package: OSVAffectedPackage | None = Field(default=None)
    ranges: list[OSVRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    ecosystem_specific: dict[str, Any] = Field(default_factory=dict)
    database_specific: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ranges", "versions", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value

    @field_validator("ecosystem_specific", "database_specific", mode="before")
    @classmethod
    def _none_to_dict(cls, value: Any) -> Any:
        return {} if value is None else value


class OSVSeverity(_OSVBoundaryModel):
    """Severity entry inside an OSV vulnerability record."""

    type: str = Field(..., min_length=1)
    score: str = Field(..., min_length=1)
    source: str | None = Field(default=None)


class OSVReference(_OSVBoundaryModel):
    """Reference URL entry inside an OSV vulnerability record."""

    type: str = Field(default="WEB")
    url: str = Field(..., min_length=1)


class OSVVulnerability(_OSVBoundaryModel):
    """Full OSV vulnerability entry returned by GET /v1/vulns/{id} and POST /v1/query."""

    schema_version: str | None = Field(default=None)
    id: str = Field(..., min_length=1)
    summary: str | None = Field(default=None)
    details: str | None = Field(default=None)
    aliases: list[str] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list)
    modified: str | None = Field(default=None)
    published: str | None = Field(default=None)
    withdrawn: str | None = Field(default=None)
    affected: list[OSVAffected] = Field(default_factory=list)
    references: list[OSVReference] = Field(default_factory=list)
    severity: list[OSVSeverity] = Field(default_factory=list)
    database_specific: dict[str, Any] = Field(default_factory=dict)
    credits: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("aliases", "related", "affected", "references", "severity", "credits", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value

    @field_validator("database_specific", mode="before")
    @classmethod
    def _none_to_dict(cls, value: Any) -> Any:
        return {} if value is None else value


class OSVVulnerabilityStub(_OSVBoundaryModel):
    """Lightweight vulnerability reference returned by POST /v1/querybatch."""

    id: str = Field(..., min_length=1)
    modified: str | None = Field(default=None)


class OSVQueryResponse(_OSVBoundaryModel):
    """Response body from POST /v1/query."""

    vulns: list[OSVVulnerability] = Field(default_factory=list)
    next_page_token: str | None = Field(default=None)

    @field_validator("vulns", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


class OSVBatchQueryResultItem(_OSVBoundaryModel):
    """Single element in POST /v1/querybatch results array."""

    vulns: list[OSVVulnerabilityStub] = Field(default_factory=list)
    next_page_token: str | None = Field(default=None)

    @field_validator("vulns", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


class OSVBatchQueryResponse(_OSVBoundaryModel):
    """Response body from POST /v1/querybatch."""

    results: list[OSVBatchQueryResultItem] = Field(default_factory=list)

    @field_validator("results", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value
