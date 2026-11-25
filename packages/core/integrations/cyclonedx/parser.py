"""CycloneDX 1.4/1.5/1.6 JSON SBOM parser with dependency scope & completeness checks."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from packages.core.models.discovery import DependencyScope, SBOMCompletenessStatus


class CycloneDXParseError(Exception):
    """Raised when an SBOM file or JSON payload is malformed or not CycloneDX."""


class _CDXBoundaryModel(BaseModel):
    """Tolerant boundary model for CycloneDX JSON structures."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class CycloneDXProperty(_CDXBoundaryModel):
    """Key-value property inside CycloneDX components (e.g., Trivy PkgType/FilePath)."""

    name: str = Field(..., min_length=1)
    value: str = Field(default="")

    @field_validator("value", mode="before")
    @classmethod
    def _coerce_value(cls, value: Any) -> str:
        if value is None:
            return ""
        return str(value)


class CycloneDXComponent(_CDXBoundaryModel):
    """Software component entry within CycloneDX."""

    bom_ref: str | None = Field(default=None, alias="bom-ref")
    component_type: str = Field(default="library", alias="type")
    name: str = Field(..., min_length=1)
    version: str | None = Field(default=None)
    purl: str | None = Field(default=None)
    properties: list[CycloneDXProperty] = Field(default_factory=list)

    @field_validator("properties", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


class CycloneDXDependency(_CDXBoundaryModel):
    """Directed dependency edge list entry."""

    ref: str = Field(..., min_length=1)
    depends_on: list[str] = Field(default_factory=list, alias="dependsOn")

    @field_validator("depends_on", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


class CycloneDXMetadata(_CDXBoundaryModel):
    """CycloneDX metadata block containing timestamp, root component, and tools."""

    timestamp: str | None = Field(default=None)
    component: CycloneDXComponent | None = Field(default=None)
    tools: Any = Field(default=None)


class CycloneDXBom(_CDXBoundaryModel):
    """Validated top-level CycloneDX JSON document."""

    bom_format: str = Field(..., alias="bomFormat")
    spec_version: str = Field(..., min_length=1, alias="specVersion")
    serial_number: str | None = Field(default=None, alias="serialNumber")
    version: int | None = Field(default=None)
    metadata: CycloneDXMetadata | None = Field(default=None)
    components: list[CycloneDXComponent] = Field(default_factory=list)
    dependencies: list[CycloneDXDependency] = Field(default_factory=list)

    @field_validator("bom_format")
    @classmethod
    def _must_be_cyclonedx(cls, value: str) -> str:
        if value != "CycloneDX":
            raise ValueError(f"Unsupported bomFormat '{value}'; expected 'CycloneDX'")
        return value

    @field_validator("components", "dependencies", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        return [] if value is None else value


@dataclass
class CycloneDXParseResult:
    """Parsed CycloneDX document enriched with dependency scopes and completeness signals."""

    bom: CycloneDXBom
    generation_timestamp: datetime | None
    scanner_version: str | None
    scope_by_ref: dict[str, DependencyScope] = field(default_factory=dict)
    completeness_status: SBOMCompletenessStatus = SBOMCompletenessStatus.COMPLETE
    warnings: list[str] = field(default_factory=list)


def _parse_iso_timestamp(raw_ts: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string safely into a timezone-aware UTC datetime."""
    if not raw_ts:
        return None
    normalized = raw_ts.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _extract_trivy_tool_version(tools_obj: Any) -> str | None:
    """Extract Trivy tool version across CycloneDX 1.4 list and 1.5/1.6 object schemas."""
    if isinstance(tools_obj, list):
        for entry in tools_obj:
            if isinstance(entry, dict) and str(entry.get("name", "")).lower() == "trivy":
                ver = entry.get("version")
                return str(ver) if ver else None
    elif isinstance(tools_obj, dict):
        components = tools_obj.get("components")
        if isinstance(components, list):
            for entry in components:
                if isinstance(entry, dict) and str(entry.get("name", "")).lower() == "trivy":
                    ver = entry.get("version")
                    return str(ver) if ver else None
    return None


class CycloneDXParser:
    """Parses CycloneDX JSON SBOMs, resolves dependency scopes, and checks completeness."""

    def parse(
        self,
        raw_payload: dict[str, Any],
        detected_manifests: list[str] | None = None,
    ) -> CycloneDXParseResult:
        """Validate and parse CycloneDX JSON payload.

        Args:
            raw_payload: Parsed JSON dictionary of a CycloneDX BOM.
            detected_manifests: Optional manifest files found in the target repository
                to detect empty/incomplete SBOMs when manifests are present.
        """
        if not isinstance(raw_payload, dict):
            raise CycloneDXParseError("CycloneDX document root must be a JSON object.")

        try:
            bom = CycloneDXBom.model_validate(raw_payload)
        except ValidationError as err:
            raise CycloneDXParseError(f"Invalid CycloneDX SBOM document: {err}") from err

        warnings: list[str] = []

        if bom.spec_version not in {"1.4", "1.5", "1.6"}:
            warnings.append(
                f"Unverified CycloneDX specVersion '{bom.spec_version}'; "
                "proceeding with compatible structural parsing."
            )

        gen_ts: datetime | None = None
        scanner_version: str | None = None
        if bom.metadata is not None:
            if bom.metadata.timestamp:
                gen_ts = _parse_iso_timestamp(bom.metadata.timestamp)
                if gen_ts is None:
                    warnings.append(
                        f"Unable to parse SBOM metadata.timestamp '{bom.metadata.timestamp}'."
                    )
            scanner_version = _extract_trivy_tool_version(bom.metadata.tools)

        scope_by_ref = self._resolve_dependency_scopes(bom)
        completeness = self._evaluate_completeness(
            bom=bom,
            warnings=warnings,
            detected_manifests=detected_manifests or [],
        )

        return CycloneDXParseResult(
            bom=bom,
            generation_timestamp=gen_ts,
            scanner_version=scanner_version,
            scope_by_ref=scope_by_ref,
            completeness_status=completeness,
            warnings=warnings,
        )

    @staticmethod
    def _resolve_dependency_scopes(bom: CycloneDXBom) -> dict[str, DependencyScope]:
        """Classify components as direct, transitive, or unknown from the dependency graph."""
        if not bom.dependencies or not bom.metadata or not bom.metadata.component:
            return {}

        root_ref = bom.metadata.component.bom_ref
        if not root_ref:
            return {}

        adjacency: dict[str, list[str]] = {
            dep.ref: list(dep.depends_on) for dep in bom.dependencies
        }
        if root_ref not in adjacency:
            return {}

        comp_type_by_ref = {
            c.bom_ref: c.component_type for c in bom.components if c.bom_ref is not None
        }
        comp_type_by_ref[root_ref] = bom.metadata.component.component_type

        # Trivy filesystem SBOMs model:
        # root repository -> application manifest(s) (type="application") -> direct packages -> transitive packages
        direct_roots: deque[str] = deque()
        visited_roots: set[str] = {root_ref}
        scopes: dict[str, DependencyScope] = {}

        for child in adjacency.get(root_ref, []):
            if child in visited_roots:
                continue
            visited_roots.add(child)
            if comp_type_by_ref.get(child) == "application":
                # Manifest application node; its immediate library children are direct dependencies.
                for manifest_child in adjacency.get(child, []):
                    if manifest_child not in scopes:
                        scopes[manifest_child] = DependencyScope.DIRECT
                        direct_roots.append(manifest_child)
            else:
                scopes[child] = DependencyScope.DIRECT
                direct_roots.append(child)

        # BFS from direct dependencies to discover transitive dependencies
        while direct_roots:
            current = direct_roots.popleft()
            for dep_ref in adjacency.get(current, []):
                if dep_ref not in scopes and dep_ref not in visited_roots:
                    scopes[dep_ref] = DependencyScope.TRANSITIVE
                    direct_roots.append(dep_ref)

        return scopes

    @staticmethod
    def _evaluate_completeness(
        bom: CycloneDXBom,
        warnings: list[str],
        detected_manifests: list[str],
    ) -> SBOMCompletenessStatus:
        """Determine whether the SBOM is complete or incomplete without silently masking gaps."""
        incomplete = False

        # Filter out application manifest container nodes when checking library package completeness
        package_components = [c for c in bom.components if c.component_type != "application"]

        if not package_components and detected_manifests:
            warnings.append(
                f"CycloneDX SBOM lists 0 packages despite detected manifest file(s): "
                f"{', '.join(detected_manifests[:5])}. Marking SBOM incomplete."
            )
            incomplete = True

        missing_version_count = sum(1 for c in package_components if not c.version)
        if missing_version_count > 0:
            warnings.append(
                f"{missing_version_count} SBOM component(s) lack version metadata."
            )
            incomplete = True

        missing_purl_count = sum(1 for c in package_components if not c.purl)
        if missing_purl_count > 0:
            warnings.append(
                f"{missing_purl_count} SBOM component(s) lack Package URL (PURL) identifiers."
            )
            incomplete = True

        if package_components and not bom.dependencies:
            warnings.append(
                "CycloneDX SBOM omits dependency graph edges; direct vs. transitive scope is unknown."
            )
            incomplete = True

        return (
            SBOMCompletenessStatus.INCOMPLETE
            if incomplete
            else SBOMCompletenessStatus.COMPLETE
        )
