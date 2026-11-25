"""Normalization logic for PURLs, packages, CVSS scores, severities, and vulnerabilities."""

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any
from urllib.parse import unquote

from packages.core.integrations.cyclonedx.parser import CycloneDXComponent, CycloneDXParseResult
from packages.core.integrations.trivy.parser import (
    TrivyCVSSEntry,
    TrivyRawVulnerability,
    TrivyReport,
    TrivyResultBlock,
)
from packages.core.models.discovery import (
    CVSSMetric,
    DependencyScope,
    PackageRecord,
    SeverityLevel,
    VulnerabilityRecord,
)

_ECOSYSTEM_ALIASES: dict[str, str] = {
    "pip": "pypi",
    "pipenv": "pypi",
    "poetry": "pypi",
    "uv": "pypi",
    "python-pkg": "pypi",
    "pypi": "pypi",
    "gomod": "golang",
    "gobinary": "golang",
    "golang": "golang",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "node-pkg": "npm",
    "cargo": "cargo",
    "pom": "maven",
    "gradle": "maven",
    "jar": "maven",
    "maven": "maven",
    "bundler": "gem",
    "gemspec": "gem",
    "gem": "gem",
    "composer": "composer",
    "nuget": "nuget",
    "dotnet-core": "nuget",
    "alpine": "apk",
    "apk": "apk",
    "debian": "deb",
    "ubuntu": "deb",
    "deb": "deb",
    "redhat": "rpm",
    "centos": "rpm",
    "fedora": "rpm",
    "rpm": "rpm",
}

_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "NEGLIGIBLE": SeverityLevel.NEGLIGIBLE,
}


@dataclass(frozen=True)
class ParsedPURL:
    """Lightweight representation of a Package URL (pkg:<type>/[namespace/]<name>[@version])."""

    raw: str
    ecosystem: str
    namespace: str | None
    name: str
    version: str | None


def parse_purl(purl: str | None) -> ParsedPURL | None:
    """Parse a standard Package URL without raising on malformed/missing inputs."""
    if not purl or not isinstance(purl, str):
        return None
    stripped = purl.strip()
    if not stripped.startswith("pkg:"):
        return None

    body = stripped[4:]
    # Drop #subpath and ?qualifiers before parsing package coordinates
    body = body.split("#", 1)[0]
    body = body.split("?", 1)[0]

    if "/" not in body:
        return None

    pkg_type, remainder = body.split("/", 1)
    pkg_type = pkg_type.strip().lower()
    if not pkg_type or not remainder:
        return None

    version: str | None = None
    if "@" in remainder:
        name_part, raw_version = remainder.rsplit("@", 1)
        version = unquote(raw_version).strip() or None
    else:
        name_part = remainder

    if "/" in name_part:
        namespace_raw, name_raw = name_part.rsplit("/", 1)
        namespace = unquote(namespace_raw).strip("/") or None
        name = unquote(name_raw).strip()
    else:
        namespace = None
        name = unquote(name_part).strip()

    if not name:
        return None

    return ParsedPURL(
        raw=stripped,
        ecosystem=normalize_ecosystem(pkg_type),
        namespace=namespace,
        name=name,
        version=version,
    )


def normalize_ecosystem(raw_type: str | None) -> str:
    """Map scanner-specific package type identifiers into canonical ecosystem names."""
    if not raw_type:
        return "unknown"
    cleaned = raw_type.strip().lower()
    if not cleaned:
        return "unknown"
    return _ECOSYSTEM_ALIASES.get(cleaned, cleaned)


def normalize_severity(raw_severity: str | None) -> SeverityLevel:
    """Normalize arbitrary scanner severity strings conservatively."""
    if not raw_severity:
        return SeverityLevel.UNKNOWN
    return _SEVERITY_MAP.get(raw_severity.strip().upper(), SeverityLevel.UNKNOWN)


def _infer_cvss_version(vector: str | None, fallback: str) -> str:
    """Infer CVSS version string from a vector prefix when available."""
    if vector:
        upper = vector.upper()
        if upper.startswith("CVSS:4.0/"):
            return "4.0"
        if upper.startswith("CVSS:3.1/"):
            return "3.1"
        if upper.startswith("CVSS:3.0/"):
            return "3.0"
    return fallback


def normalize_cvss(cvss_map: dict[str, TrivyCVSSEntry]) -> list[CVSSMetric]:
    """Convert Trivy vendor CVSS dictionary into canonical CVSSMetric entries."""
    metrics: list[CVSSMetric] = []
    for source_name, entry in sorted(cvss_map.items()):
        if entry.v40_score is not None or entry.v40_vector:
            metrics.append(
                CVSSMetric(
                    source=source_name,
                    version=_infer_cvss_version(entry.v40_vector, "4.0"),
                    base_score=entry.v40_score,
                    vector=entry.v40_vector,
                )
            )
        if entry.v3_score is not None or entry.v3_vector:
            metrics.append(
                CVSSMetric(
                    source=source_name,
                    version=_infer_cvss_version(entry.v3_vector, "3.x"),
                    base_score=entry.v3_score,
                    vector=entry.v3_vector,
                )
            )
        if entry.v2_score is not None or entry.v2_vector:
            metrics.append(
                CVSSMetric(
                    source=source_name,
                    version="2.0",
                    base_score=entry.v2_score,
                    vector=entry.v2_vector,
                )
            )
    return metrics


def _make_package_id(
    ecosystem: str,
    name: str,
    version: str | None,
    purl: str | None,
    disambiguator: str,
    existing_ids: set[str],
) -> str:
    """Build a deterministic, unique package_id without losing readability."""
    base = purl if purl else f"{ecosystem}:{name}@{version or 'unknown'}"
    if base not in existing_ids:
        return base
    suffix = sha256(f"{base}|{disambiguator}".encode()).hexdigest()[:8]
    candidate = f"{base}#{suffix}"
    counter = 1
    while candidate in existing_ids:
        candidate = f"{base}#{suffix}-{counter}"
        counter += 1
    return candidate


def _extract_cdx_properties(comp: CycloneDXComponent) -> dict[str, str]:
    """Extract key-value properties from a CycloneDX component."""
    return {prop.name: prop.value for prop in comp.properties}


def _scope_from_trivy_relationship(rel: str | None) -> DependencyScope:
    """Translate Trivy Package.Relationship string into canonical DependencyScope."""
    if not rel:
        return DependencyScope.UNKNOWN
    lower = rel.strip().lower()
    if lower in {"direct", "root"}:
        return DependencyScope.DIRECT
    if lower == "indirect":
        return DependencyScope.TRANSITIVE
    return DependencyScope.UNKNOWN


class DiscoveryNormalizer:
    """Correlates and normalizes CycloneDX SBOM components and Trivy vulnerabilities."""

    def normalize(
        self,
        cyclonedx_result: CycloneDXParseResult | None,
        trivy_report: TrivyReport | None,
        detection_timestamp: datetime,
        scanner_source: str = "trivy",
    ) -> tuple[list[PackageRecord], list[VulnerabilityRecord], list[str], list[str]]:
        """Normalize packages and vulnerabilities into canonical records.

        Returns:
            (packages, vulnerabilities, sbom_package_ids, warnings)
        """
        packages: list[PackageRecord] = []
        sbom_package_ids: list[str] = []
        warnings: list[str] = []
        existing_ids: set[str] = set()

        # Lookup indexes for matching Trivy vulnerability findings back to PackageRecords
        by_purl: dict[str, PackageRecord] = {}
        by_bom_ref: dict[str, PackageRecord] = {}
        by_coords: dict[tuple[str, str | None, str], PackageRecord] = {}
        by_name_ver: dict[tuple[str, str | None], PackageRecord] = {}

        def _register_package(pkg: PackageRecord, bom_ref: str | None = None) -> None:
            packages.append(pkg)
            existing_ids.add(pkg.package_id)
            if pkg.purl and pkg.purl not in by_purl:
                by_purl[pkg.purl] = pkg
            if bom_ref and bom_ref not in by_bom_ref:
                by_bom_ref[bom_ref] = pkg
            coord_key = (pkg.name.lower(), pkg.version, pkg.ecosystem)
            if coord_key not in by_coords:
                by_coords[coord_key] = pkg
            nv_key = (pkg.name.lower(), pkg.version)
            if nv_key not in by_name_ver:
                by_name_ver[nv_key] = pkg

        # 1. Normalize packages from CycloneDX SBOM (primary package inventory)
        if cyclonedx_result is not None:
            for idx, comp in enumerate(cyclonedx_result.bom.components):
                if comp.component_type == "application":
                    # Application nodes represent manifest containers (e.g., requirements.txt),
                    # not installable library packages.
                    continue

                props = _extract_cdx_properties(comp)
                parsed_purl = parse_purl(comp.purl)
                raw_pkg_type = props.get("aquasecurity:trivy:PkgType")
                ecosystem = (
                    parsed_purl.ecosystem
                    if parsed_purl
                    else normalize_ecosystem(raw_pkg_type)
                )
                version = comp.version.strip() if comp.version and comp.version.strip() else None
                purl = comp.purl.strip() if comp.purl and comp.purl.strip() else None
                scope = (
                    cyclonedx_result.scope_by_ref.get(comp.bom_ref, DependencyScope.UNKNOWN)
                    if comp.bom_ref
                    else DependencyScope.UNKNOWN
                )

                file_path = props.get("aquasecurity:trivy:FilePath")
                disambiguator = comp.bom_ref or file_path or f"cdx-{idx}"
                package_id = _make_package_id(
                    ecosystem=ecosystem,
                    name=comp.name,
                    version=version,
                    purl=purl,
                    disambiguator=disambiguator,
                    existing_ids=existing_ids,
                )

                source_metadata: dict[str, Any] = {
                    "component_type": comp.component_type,
                    "from_sbom": True,
                }
                if comp.bom_ref:
                    source_metadata["bom_ref"] = comp.bom_ref
                if file_path:
                    source_metadata["manifest_path"] = file_path
                if raw_pkg_type:
                    source_metadata["pkg_type"] = raw_pkg_type

                pkg = PackageRecord(
                    package_id=package_id,
                    name=comp.name,
                    version=version,
                    ecosystem=ecosystem,
                    purl=purl,
                    dependency_scope=scope,
                    source_metadata=source_metadata,
                )
                _register_package(pkg, bom_ref=comp.bom_ref)
                sbom_package_ids.append(pkg.package_id)

        # 2. Enrich scope or missing packages from Trivy Results[].Packages & Vulnerabilities
        vulnerabilities_by_key: dict[tuple[str, str], VulnerabilityRecord] = {}

        if trivy_report is not None:
            for block in trivy_report.results:
                block_ecosystem = normalize_ecosystem(block.result_type)

                for raw_pkg in block.packages:
                    raw_purl = self._extract_identifier_purl(raw_pkg.identifier)
                    matched = self._find_package(
                        purl=raw_purl,
                        bom_ref=raw_pkg.identifier.get("UID") or raw_pkg.pkg_id,
                        name=raw_pkg.name,
                        version=raw_pkg.version,
                        ecosystem=block_ecosystem,
                        by_purl=by_purl,
                        by_bom_ref=by_bom_ref,
                        by_coords=by_coords,
                        by_name_ver=by_name_ver,
                    )
                    trivy_scope = _scope_from_trivy_relationship(raw_pkg.relationship)
                    if matched is not None:
                        if (
                            matched.dependency_scope == DependencyScope.UNKNOWN
                            and trivy_scope != DependencyScope.UNKNOWN
                        ):
                            matched.dependency_scope = trivy_scope
                    elif cyclonedx_result is None:
                        # Only synthesize packages from Trivy Results[].Packages when SBOM was unavailable.
                        pkg_id = _make_package_id(
                            ecosystem=block_ecosystem,
                            name=raw_pkg.name,
                            version=raw_pkg.version,
                            purl=raw_purl,
                            disambiguator=raw_pkg.pkg_id or block.target,
                            existing_ids=existing_ids,
                        )
                        synthesized = PackageRecord(
                            package_id=pkg_id,
                            name=raw_pkg.name,
                            version=raw_pkg.version,
                            ecosystem=block_ecosystem,
                            purl=raw_purl,
                            dependency_scope=trivy_scope,
                            source_metadata={
                                "from_sbom": False,
                                "synthesized_from": "trivy_packages",
                                "manifest_path": block.target,
                            },
                        )
                        _register_package(synthesized, bom_ref=raw_pkg.pkg_id)

                for raw_vuln in block.vulnerabilities:
                    pkg_record = self._resolve_or_synthesize_pkg_for_vuln(
                        raw_vuln=raw_vuln,
                        block=block,
                        block_ecosystem=block_ecosystem,
                        by_purl=by_purl,
                        by_bom_ref=by_bom_ref,
                        by_coords=by_coords,
                        by_name_ver=by_name_ver,
                        existing_ids=existing_ids,
                        register_fn=_register_package,
                        warnings=warnings,
                    )

                    dedup_key = (raw_vuln.vulnerability_id, pkg_record.package_id)
                    fixed_ver = (
                        raw_vuln.fixed_version.strip()
                        if raw_vuln.fixed_version and raw_vuln.fixed_version.strip()
                        else None
                    )
                    installed_ver = (
                        raw_vuln.installed_version.strip()
                        if raw_vuln.installed_version and raw_vuln.installed_version.strip()
                        else pkg_record.version
                    )
                    refs = list(dict.fromkeys(r for r in raw_vuln.references if r))
                    cwes = list(dict.fromkeys(c for c in raw_vuln.cwe_ids if c))

                    if dedup_key in vulnerabilities_by_key:
                        existing_vuln = vulnerabilities_by_key[dedup_key]
                        merged_refs = list(dict.fromkeys(existing_vuln.references + refs))
                        existing_vuln.references = merged_refs
                        continue

                    vulnerabilities_by_key[dedup_key] = VulnerabilityRecord(
                        vulnerability_id=raw_vuln.vulnerability_id,
                        package_id=pkg_record.package_id,
                        installed_version=installed_ver,
                        fixed_version=fixed_ver,
                        severity=normalize_severity(raw_vuln.severity),
                        cvss=normalize_cvss(raw_vuln.cvss),
                        description=raw_vuln.description or "",
                        references=refs,
                        primary_url=raw_vuln.primary_url,
                        source=scanner_source,
                        detection_timestamp=detection_timestamp,
                        title=raw_vuln.title,
                        cwe_ids=cwes,
                    )

        return packages, list(vulnerabilities_by_key.values()), sbom_package_ids, warnings

    @staticmethod
    def _extract_identifier_purl(identifier: dict[str, Any]) -> str | None:
        raw = identifier.get("PURL")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        return None

    @staticmethod
    def _find_package(
        purl: str | None,
        bom_ref: str | None,
        name: str,
        version: str | None,
        ecosystem: str,
        by_purl: dict[str, PackageRecord],
        by_bom_ref: dict[str, PackageRecord],
        by_coords: dict[tuple[str, str | None, str], PackageRecord],
        by_name_ver: dict[tuple[str, str | None], PackageRecord],
    ) -> PackageRecord | None:
        if purl and purl in by_purl:
            return by_purl[purl]
        if bom_ref and bom_ref in by_bom_ref:
            return by_bom_ref[bom_ref]

        clean_ver = version.strip() if version and version.strip() else None
        coord_key = (name.lower(), clean_ver, ecosystem)
        if coord_key in by_coords:
            return by_coords[coord_key]

        if ecosystem == "unknown":
            return by_name_ver.get((name.lower(), clean_ver))
        return by_coords.get((name.lower(), clean_ver, "unknown"))

    def _resolve_or_synthesize_pkg_for_vuln(
        self,
        raw_vuln: TrivyRawVulnerability,
        block: TrivyResultBlock,
        block_ecosystem: str,
        by_purl: dict[str, PackageRecord],
        by_bom_ref: dict[str, PackageRecord],
        by_coords: dict[tuple[str, str | None, str], PackageRecord],
        by_name_ver: dict[tuple[str, str | None], PackageRecord],
        existing_ids: set[str],
        register_fn: Any,
        warnings: list[str],
    ) -> PackageRecord:
        purl = self._extract_identifier_purl(raw_vuln.pkg_identifier)
        parsed_purl = parse_purl(purl)
        ecosystem = parsed_purl.ecosystem if parsed_purl else block_ecosystem
        uid = raw_vuln.pkg_identifier.get("UID")
        bom_ref = str(uid) if uid else raw_vuln.pkg_id

        matched = self._find_package(
            purl=purl,
            bom_ref=bom_ref,
            name=raw_vuln.pkg_name,
            version=raw_vuln.installed_version,
            ecosystem=ecosystem,
            by_purl=by_purl,
            by_bom_ref=by_bom_ref,
            by_coords=by_coords,
            by_name_ver=by_name_ver,
        )
        if matched is not None:
            return matched

        clean_ver = (
            raw_vuln.installed_version.strip()
            if raw_vuln.installed_version and raw_vuln.installed_version.strip()
            else None
        )
        pkg_id = _make_package_id(
            ecosystem=ecosystem,
            name=raw_vuln.pkg_name,
            version=clean_ver,
            purl=purl,
            disambiguator=bom_ref or block.target,
            existing_ids=existing_ids,
        )
        synthesized = PackageRecord(
            package_id=pkg_id,
            name=raw_vuln.pkg_name,
            version=clean_ver,
            ecosystem=ecosystem,
            purl=purl,
            dependency_scope=DependencyScope.UNKNOWN,
            source_metadata={
                "from_sbom": False,
                "synthesized_from": "trivy_vuln_scan",
                "manifest_path": block.target,
            },
        )
        register_fn(synthesized, bom_ref=bom_ref)
        warnings.append(
            f"Package '{raw_vuln.pkg_name}' ({clean_ver or 'unknown'}) reported by vulnerability "
            f"scanner was missing from SBOM; synthesized record '{pkg_id}'."
        )
        return synthesized
