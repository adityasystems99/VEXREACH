"""Deterministic Python source discovery for static reachability analysis."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from packages.core.config.settings import Settings, get_settings
from packages.core.models.reachability import AnalysisDiagnostic, CodeLocation
from packages.core.utils.logging import get_logger
from packages.core.utils.safe_path import (
    PathTraversalError,
    calculate_file_sha256,
    safe_resolve_path,
)

logger = get_logger(__name__)

DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "node_modules",
        "dist",
        "build",
        "site-packages",
        ".eggs",
    }
)


@dataclass(frozen=True)
class DiscoveredPythonFile:
    """Metadata for a single discovered Python source file."""

    absolute_path: Path
    relative_path: str
    module_name: str
    package_parts: tuple[str, ...]
    is_package: bool
    size_bytes: int
    sha256: str


@dataclass
class PythonDiscoveryResult:
    """Result of scanning a repository for Python source files."""

    root_path: Path
    files: list[DiscoveredPythonFile] = field(default_factory=list)
    source_snapshot_hash: str = ""
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)
    truncated: bool = False


def derive_module_identity(
    relative_posix_path: str,
    *,
    strip_src_root: bool = False,
) -> tuple[str, tuple[str, ...], bool]:
    """Convert a repository-relative POSIX path to `(module_name, package_parts, is_package)`.

    Args:
        relative_posix_path: Forward-slash path relative to repository root.
        strip_src_root: Whether a leading ``src/`` directory acts as a source root
            rather than a regular Python package.

    Returns:
        Tuple of dotted module name, tuple of owning package segments (for relative
        import resolution), and whether the file is an ``__init__.py`` package module.
    """
    parts = [part for part in relative_posix_path.split("/") if part]
    if strip_src_root and len(parts) > 1 and parts[0] == "src":
        parts = parts[1:]

    if not parts:
        return "__unknown__", (), False

    filename = parts[-1]
    dir_parts = tuple(parts[:-1])
    if filename == "__init__.py":
        if dir_parts:
            return ".".join(dir_parts), dir_parts, True
        return "__init__", (), True

    stem = filename[:-3] if filename.endswith(".py") else filename
    module_parts = (*dir_parts, stem)
    return ".".join(module_parts), dir_parts, False


class PythonSourceDiscovery:
    """Discovers Python source files within a repository without following symlinks."""

    def __init__(
        self,
        settings: Settings | None = None,
        ignored_dirs: frozenset[str] = DEFAULT_IGNORED_DIRS,
    ) -> None:
        self._settings = settings or get_settings()
        self._ignored_dirs = ignored_dirs

    def discover(self, target_path: Path | str) -> PythonDiscoveryResult:
        """Discover Python source files inside ``target_path``.

        Raises:
            FileNotFoundError: If ``target_path`` does not exist.
            ValueError: If ``target_path`` is not a readable directory or ``.py`` file.
        """
        raw_path = Path(target_path)
        if not raw_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {raw_path}")

        if raw_path.is_file():
            if raw_path.is_symlink():
                raise ValueError(f"Refusing to analyze symlink target: {raw_path}")
            if raw_path.suffix != ".py":
                raise ValueError(f"Target file must be a .py file: {raw_path}")
            resolved_file = raw_path.resolve()
            root_path = resolved_file.parent
            return self._discover_single_file(root_path, resolved_file)

        if not raw_path.is_dir():
            raise ValueError(f"Target path must be a directory or .py file: {raw_path}")

        root_path = raw_path.resolve()
        has_src_init = (root_path / "src" / "__init__.py").is_file()
        strip_src_root = (root_path / "src").is_dir() and not has_src_init

        discovered: list[DiscoveredPythonFile] = []
        diagnostics: list[AnalysisDiagnostic] = []
        truncated = False
        max_files = self._settings.max_python_files

        for current_root, dirnames, filenames in os.walk(
            root_path, topdown=True, followlinks=False
        ):
            current_dir = Path(current_root)
            filtered_dirs: list[str] = []
            for dirname in sorted(dirnames):
                if dirname in self._ignored_dirs or dirname.endswith(".egg-info"):
                    continue
                candidate_dir = current_dir / dirname
                if candidate_dir.is_symlink():
                    diagnostics.append(
                        AnalysisDiagnostic(
                            code="SYMLINK_SKIPPED",
                            severity="info",
                            message=f"Skipped symlink directory: {candidate_dir.relative_to(root_path).as_posix()}",
                            location=CodeLocation(
                                file=candidate_dir.relative_to(root_path).as_posix(),
                                line=1,
                            ),
                            construct_kind="symlink_dir",
                        )
                    )
                    continue
                try:
                    safe_resolve_path(root_path, candidate_dir)
                except PathTraversalError:
                    diagnostics.append(
                        AnalysisDiagnostic(
                            code="PATH_OUTSIDE_ROOT_SKIPPED",
                            severity="warning",
                            message=f"Skipped directory resolving outside repository root: {dirname}",
                            construct_kind="path_containment",
                        )
                    )
                    continue
                filtered_dirs.append(dirname)
            dirnames[:] = filtered_dirs

            for filename in sorted(filenames):
                if not filename.endswith(".py"):
                    continue
                candidate_file = current_dir / filename
                rel_posix = candidate_file.relative_to(root_path).as_posix()

                if candidate_file.is_symlink():
                    diagnostics.append(
                        AnalysisDiagnostic(
                            code="SYMLINK_SKIPPED",
                            severity="info",
                            message=f"Skipped symlink file: {rel_posix}",
                            location=CodeLocation(file=rel_posix, line=1),
                            construct_kind="symlink_file",
                        )
                    )
                    continue

                if len(discovered) >= max_files:
                    truncated = True
                    diagnostics.append(
                        AnalysisDiagnostic(
                            code="PYTHON_FILE_LIMIT_EXCEEDED",
                            severity="warning",
                            message=(
                                f"Stopped Python file discovery at configured limit of {max_files} files."
                            ),
                            location=CodeLocation(file=rel_posix, line=1),
                            construct_kind="discovery_limit",
                        )
                    )
                    break

                record = self._inspect_file(
                    root_path=root_path,
                    file_path=candidate_file,
                    rel_posix=rel_posix,
                    strip_src_root=strip_src_root,
                    diagnostics=diagnostics,
                )
                if record is not None:
                    discovered.append(record)

            if truncated:
                break

        discovered.sort(key=lambda item: item.relative_path)
        snapshot_hash = self._compute_snapshot_hash(discovered)

        if not discovered and not diagnostics:
            diagnostics.append(
                AnalysisDiagnostic(
                    code="NO_PYTHON_FILES",
                    severity="warning",
                    message="No Python source files discovered under target path.",
                    construct_kind="python_discovery",
                )
            )

        logger.info(
            "Discovered %d Python source files under %s (truncated=%s)",
            len(discovered),
            root_path,
            truncated,
        )
        return PythonDiscoveryResult(
            root_path=root_path,
            files=discovered,
            source_snapshot_hash=snapshot_hash,
            diagnostics=diagnostics,
            truncated=truncated,
        )

    def _discover_single_file(
        self, root_path: Path, resolved_file: Path
    ) -> PythonDiscoveryResult:
        diagnostics: list[AnalysisDiagnostic] = []
        rel_posix = resolved_file.relative_to(root_path).as_posix()
        record = self._inspect_file(
            root_path=root_path,
            file_path=resolved_file,
            rel_posix=rel_posix,
            strip_src_root=False,
            diagnostics=diagnostics,
        )
        files = [record] if record is not None else []
        return PythonDiscoveryResult(
            root_path=root_path,
            files=files,
            source_snapshot_hash=self._compute_snapshot_hash(files),
            diagnostics=diagnostics,
            truncated=False,
        )

    def _inspect_file(
        self,
        *,
        root_path: Path,
        file_path: Path,
        rel_posix: str,
        strip_src_root: bool,
        diagnostics: list[AnalysisDiagnostic],
    ) -> DiscoveredPythonFile | None:
        try:
            safe_file = safe_resolve_path(root_path, file_path)
        except PathTraversalError:
            diagnostics.append(
                AnalysisDiagnostic(
                    code="PATH_OUTSIDE_ROOT_SKIPPED",
                    severity="warning",
                    message=f"Skipped file resolving outside repository root: {rel_posix}",
                    location=CodeLocation(file=rel_posix, line=1),
                    construct_kind="path_containment",
                )
            )
            return None

        try:
            size_bytes = safe_file.stat().st_size
        except OSError as exc:
            diagnostics.append(
                AnalysisDiagnostic(
                    code="FILE_STAT_ERROR",
                    severity="warning",
                    message=f"Unable to inspect file metadata for {rel_posix}: {exc}",
                    location=CodeLocation(file=rel_posix, line=1),
                    construct_kind="filesystem",
                )
            )
            return None

        if size_bytes > self._settings.max_file_size_bytes:
            diagnostics.append(
                AnalysisDiagnostic(
                    code="FILE_TOO_LARGE",
                    severity="warning",
                    message=(
                        f"Skipped {rel_posix} ({size_bytes} bytes exceeds "
                        f"limit of {self._settings.max_file_size_bytes} bytes)."
                    ),
                    location=CodeLocation(file=rel_posix, line=1),
                    construct_kind="file_size_limit",
                )
            )
            return None

        sha256 = calculate_file_sha256(safe_file)
        module_name, package_parts, is_package = derive_module_identity(
            rel_posix, strip_src_root=strip_src_root
        )
        return DiscoveredPythonFile(
            absolute_path=safe_file,
            relative_path=rel_posix,
            module_name=module_name,
            package_parts=package_parts,
            is_package=is_package,
            size_bytes=size_bytes,
            sha256=sha256,
        )

    @staticmethod
    def _compute_snapshot_hash(files: list[DiscoveredPythonFile]) -> str:
        digest = hashlib.sha256()
        for item in sorted(files, key=lambda entry: entry.relative_path):
            digest.update(item.relative_path.encode("utf-8"))
            digest.update(b":")
            digest.update(item.sha256.encode("utf-8"))
            digest.update(b"\n")
        return digest.hexdigest()
