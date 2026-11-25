"""Vulnerability symbol manifest loading and conservative dependency symbol verification."""

from __future__ import annotations

import ast
import functools
import importlib.metadata
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from packages.core.models.reachability import (
    AnalysisDiagnostic,
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    VulnerabilitySymbolManifest,
)
from packages.core.utils.safe_path import PathTraversalError, calculate_file_sha256, safe_resolve_path

WELL_KNOWN_PYPI_TO_IMPORT_MAP: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "pyjwt": ("jwt",),
    "pycryptodome": ("Crypto",),
    "pyopenssl": ("OpenSSL",),
    "attrs": ("attr", "attrs"),
    "msgpack-python": ("msgpack",),
}


def canonicalize_pypi_name(name: str) -> str:
    """Normalize a PyPI distribution name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def load_symbol_manifest(manifest_path: Path | str) -> tuple[VulnerabilitySymbolManifest, str]:
    """Load and validate a candidate vulnerable symbol manifest JSON file.

    Supports either a full ``VulnerabilitySymbolManifest`` object, a single
    ``VulnerabilitySymbolEntry`` object, or a JSON list of entries.

    Returns:
        Tuple of ``(validated_manifest, file_sha256)``.
    """
    path = Path(manifest_path)
    if not path.is_file():
        raise FileNotFoundError(f"Symbol manifest file not found: {path}")

    sha256 = calculate_file_sha256(path)
    raw = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(raw, list):
        payload = {"manifest_version": "1.0", "entries": raw}
    elif isinstance(raw, dict) and "vulnerability_id" in raw and "entries" not in raw:
        payload = {"manifest_version": "1.0", "entries": [raw]}
    else:
        payload = raw

    manifest = VulnerabilitySymbolManifest.model_validate(payload, strict=False)
    return manifest, sha256


@dataclass
class DependencySymbolCheck:
    """Result of verifying a single candidate vulnerable symbol against dependency sources."""

    status: DependencySymbolResolutionStatus
    candidate_graph_targets: list[str] = field(default_factory=list)
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)


@functools.lru_cache(maxsize=1)
def _installed_dist_module_map() -> dict[str, tuple[str, ...]]:
    """Cache distribution-to-top-level-module mappings from local Python metadata."""
    mapping: dict[str, set[str]] = {}
    try:
        pkg_dists = importlib.metadata.packages_distributions()
        for top_pkg, dists in pkg_dists.items():
            for dist in dists:
                mapping.setdefault(canonicalize_pypi_name(dist), set()).add(top_pkg)
    except Exception:
        pass
    return {k: tuple(sorted(v)) for k, v in mapping.items()}


class DependencySymbolResolver:
    """Maps distribution names to Python import namespaces and checks local dependency ASTs."""

    def __init__(
        self,
        dependency_source_dirs: list[Path] | None = None,
        explicit_package_map: dict[str, list[str]] | None = None,
    ) -> None:
        self._dependency_source_dirs = [
            p.resolve() for p in (dependency_source_dirs or []) if p.is_dir()
        ]
        self._explicit_package_map: dict[str, list[str]] = {
            canonicalize_pypi_name(k): list(v)
            for k, v in (explicit_package_map or {}).items()
        }
        self._dist_to_modules = self._build_dist_module_map()

    def _build_dist_module_map(self) -> dict[str, list[str]]:
        mapping: dict[str, set[str]] = {
            canonicalize_pypi_name(k): set(v)
            for k, v in WELL_KNOWN_PYPI_TO_IMPORT_MAP.items()
        }

        # Read dist-info top_level.txt if unpacked wheel/site-packages passed as dependency source
        for src_dir in self._dependency_source_dirs:
            for top_level in sorted(src_dir.glob("*.dist-info/top_level.txt")):
                dist_raw = top_level.parent.name.split("-", 1)[0]
                norm = canonicalize_pypi_name(dist_raw)
                lines = [
                    line.strip()
                    for line in top_level.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip()
                ]
                if lines:
                    mapping.setdefault(norm, set()).update(lines)

        for norm_dist, mods in self._explicit_package_map.items():
            mapping[norm_dist] = set(mods)

        return {k: sorted(v) for k, v in mapping.items()}

    def resolve_import_roots(
        self,
        package_name: str,
        declared_import_names: list[str] | None = None,
    ) -> list[str]:
        """Resolve possible top-level Python import package names for a PyPI distribution."""
        roots: list[str] = []
        if declared_import_names:
            roots.extend(declared_import_names)
        norm = canonicalize_pypi_name(package_name)
        if norm in self._explicit_package_map:
            roots.extend(self._explicit_package_map[norm])
        if norm in self._dist_to_modules:
            roots.extend(self._dist_to_modules[norm])
        elif not declared_import_names:
            roots.extend(_installed_dist_module_map().get(norm, ()))

        # Standard Python fallback: hyphen-to-underscore
        fallback = package_name.strip().replace("-", "_")
        if fallback:
            roots.append(fallback)

        seen: set[str] = set()
        ordered: list[str] = []
        for item in roots:
            if item and item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered

    def verify_symbol(
        self,
        *,
        package_name: str,
        candidate: CandidateVulnerableSymbol,
        declared_import_names: list[str] | None = None,
    ) -> DependencySymbolCheck:
        """Evaluate whether ``candidate`` can be verified statically in ``dependency_source_dirs``.

        Never imports or executes dependency code. When no dependency source exists for
        the package, returns ``DEPENDENCY_SOURCE_UNAVAILABLE`` while still preserving the
        candidate's ``qualified_name`` for call-graph matching.
        """
        qual = candidate.qualified_name.strip()
        if not qual or " " in qual or "(" in qual or not candidate.module.strip():
            return DependencySymbolCheck(
                status=DependencySymbolResolutionStatus.UNSUPPORTED_SYMBOL_STRUCTURE,
                candidate_graph_targets=[qual] if qual else [],
                diagnostics=[
                    AnalysisDiagnostic(
                        code="UNSUPPORTED_SYMBOL_STRUCTURE",
                        severity="warning",
                        message=f"Candidate symbol '{qual}' has unsupported structure.",
                        construct_kind="candidate_symbol",
                        affected_scope=package_name,
                    )
                ],
            )

        targets = [qual]
        top_module = candidate.module.split(".", 1)[0]
        import_roots = self.resolve_import_roots(package_name, declared_import_names)

        # Check explicit mapping ambiguity only when explicit mappings exist and conflict
        if (
            declared_import_names
            and top_module not in declared_import_names
            and top_module not in import_roots
        ):
            return DependencySymbolCheck(
                status=DependencySymbolResolutionStatus.IMPORT_MAPPING_AMBIGUOUS,
                candidate_graph_targets=targets,
                diagnostics=[
                    AnalysisDiagnostic(
                        code="IMPORT_MAPPING_AMBIGUOUS",
                        severity="warning",
                        message=(
                            f"Candidate module '{candidate.module}' does not match declared "
                            f"import root(s) {declared_import_names} for package '{package_name}'."
                        ),
                        construct_kind="import_mapping",
                        affected_scope=qual,
                    )
                ],
            )

        if not self._dependency_source_dirs:
            return DependencySymbolCheck(
                status=DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE,
                candidate_graph_targets=targets,
            )

        module_files = self._locate_module_files(candidate.module)
        package_root_exists = self._package_root_present(top_module)

        if not module_files and not package_root_exists:
            return DependencySymbolCheck(
                status=DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE,
                candidate_graph_targets=targets,
            )

        if not module_files and package_root_exists:
            return DependencySymbolCheck(
                status=DependencySymbolResolutionStatus.NOT_FOUND_IN_DEPENDENCY_SOURCE,
                candidate_graph_targets=targets,
                diagnostics=[
                    AnalysisDiagnostic(
                        code="DEPENDENCY_MODULE_NOT_FOUND",
                        severity="warning",
                        message=(
                            f"Module '{candidate.module}' for candidate symbol '{qual}' "
                            f"was not found inside supplied dependency source directories."
                        ),
                        construct_kind="dependency_source",
                        affected_scope=qual,
                    )
                ],
            )

        rel_symbol = (
            qual[len(candidate.module) + 1 :]
            if qual.startswith(f"{candidate.module}.")
            else qual
        )
        for mod_file in module_files:
            if self._ast_contains_symbol(mod_file, rel_symbol, candidate.symbol_type):
                return DependencySymbolCheck(
                    status=DependencySymbolResolutionStatus.VERIFIED_IN_DEPENDENCY_SOURCE,
                    candidate_graph_targets=targets,
                )

        return DependencySymbolCheck(
            status=DependencySymbolResolutionStatus.NOT_FOUND_IN_DEPENDENCY_SOURCE,
            candidate_graph_targets=targets,
            diagnostics=[
                AnalysisDiagnostic(
                    code="TARGET_SYMBOL_NOT_FOUND_IN_SOURCE",
                    severity="warning",
                    message=(
                        f"Symbol '{qual}' was not defined in dependency AST for module "
                        f"'{candidate.module}'."
                    ),
                    construct_kind="dependency_source",
                    affected_scope=qual,
                )
            ],
        )

    def _package_root_present(self, top_module: str) -> bool:
        for src_dir in self._dependency_source_dirs:
            for base in (src_dir, src_dir / "src"):
                if not base.is_dir():
                    continue
                if (base / top_module).is_dir() or (base / f"{top_module}.py").is_file():
                    return True
        return False

    def _locate_module_files(self, dotted_module: str) -> list[Path]:
        parts = [p for p in dotted_module.split(".") if p]
        if not parts:
            return []

        found: list[Path] = []
        for src_dir in self._dependency_source_dirs:
            for base in (src_dir, src_dir / "src"):
                if not base.is_dir():
                    continue
                candidates = [
                    base.joinpath(*parts[:-1], f"{parts[-1]}.py")
                    if len(parts) > 1
                    else base / f"{parts[0]}.py",
                    base.joinpath(*parts, "__init__.py"),
                ]
                for candidate in candidates:
                    try:
                        safe_candidate = safe_resolve_path(src_dir, candidate)
                    except PathTraversalError:
                        continue
                    if safe_candidate.is_file() and not safe_candidate.is_symlink():
                        found.append(safe_candidate)
        return found

    @staticmethod
    def _ast_contains_symbol(
        file_path: Path, rel_symbol: str, symbol_type: str
    ) -> bool:
        try:
            tree = ast.parse(
                file_path.read_text(encoding="utf-8-sig"),
                filename=str(file_path),
            )
        except (OSError, SyntaxError, UnicodeDecodeError, RecursionError):
            return False

        parts = [p for p in rel_symbol.split(".") if p]
        if not parts:
            return False

        # Direct nested class/function/attribute lookup
        if _find_in_body(tree.body, parts, symbol_type=symbol_type):
            return True

        # Check top-level re-exports like `from .sub import target`
        if len(parts) == 1:
            target = parts[0]
            for stmt in tree.body:
                if isinstance(stmt, ast.ImportFrom):
                    for alias in stmt.names:
                        if (alias.asname or alias.name) == target:
                            return True
        return False


def _find_in_body(
    stmts: list[ast.stmt], parts: list[str], *, symbol_type: str
) -> bool:
    head = parts[0]
    rest = parts[1:]

    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == head:
            if not rest:
                return symbol_type in {"function", "method", "attribute"}
        elif isinstance(stmt, ast.ClassDef) and stmt.name == head:
            if not rest:
                return symbol_type in {"class", "function", "attribute"}
            return _find_in_body(stmt.body, rest, symbol_type=symbol_type)
        elif not rest:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == head:
                        return True
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if stmt.target.id == head:
                    return True
    return False
