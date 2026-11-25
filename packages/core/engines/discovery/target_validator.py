"""Repository and filesystem target validation without executing repository code."""

import os
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from packages.core.models.discovery import AssessmentTarget, TargetType
from packages.core.utils.logging import get_logger

logger = get_logger("discovery.target_validator")

# Map well-known dependency manifest filenames to ecosystem hints.
# Matched strictly by filename/extension without ever importing or executing files.
_MANIFEST_ECOSYSTEM_MAP: dict[str, str] = {
    "pyproject.toml": "pypi",
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "pipfile": "pypi",
    "pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "go.mod": "golang",
    "go.sum": "golang",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "cargo.toml": "cargo",
    "cargo.lock": "cargo",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "gemfile": "gem",
    "gemfile.lock": "gem",
    "composer.json": "composer",
    "composer.lock": "composer",
}

_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".vexreach",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


class TargetValidationError(Exception):
    """Raised when a scan target path is missing, unreadable, or unsupported."""


class TargetValidator:
    """Validates local filesystem/repository targets safely without script execution."""

    def __init__(self, max_scan_depth: int = 4, max_entries: int = 5000) -> None:
        self.max_scan_depth = max_scan_depth
        self.max_entries = max_entries

    def validate(self, target_path: str | Path) -> AssessmentTarget:
        """Validate target_path exists as a readable directory and detect manifest hints."""
        raw_str = str(target_path).strip() if target_path is not None else ""
        if not raw_str:
            raise TargetValidationError("Target path cannot be empty.")

        candidate = Path(raw_str)

        try:
            exists = candidate.exists()
        except OSError as err:
            raise TargetValidationError(f"Unable to access target path '{raw_str}': {err}") from err

        if not exists:
            raise TargetValidationError(f"Target path does not exist: '{raw_str}'")

        if not candidate.is_dir():
            raise TargetValidationError(
                f"Target path must be a directory for filesystem discovery: '{raw_str}'"
            )

        try:
            canonical = candidate.resolve(strict=True)
        except OSError as err:
            raise TargetValidationError(
                f"Failed to canonicalize target path '{raw_str}': {err}"
            ) from err

        # Verify directory read permission cleanly
        try:
            with os.scandir(canonical) as it:
                next(it, None)
        except PermissionError as err:
            raise TargetValidationError(
                f"Permission denied reading target directory '{canonical}': {err}"
            ) from err
        except OSError as err:
            raise TargetValidationError(
                f"Error reading target directory '{canonical}': {err}"
            ) from err

        manifests, ecosystems, warnings = self._inspect_manifests(canonical)
        for warning in warnings:
            logger.warning(warning)

        target_id = f"target-{uuid5(NAMESPACE_URL, str(canonical)).hex[:16]}"
        return AssessmentTarget(
            target_id=target_id,
            target_path=str(canonical),
            target_type=TargetType.FILESYSTEM,
            detected_ecosystems=sorted(ecosystems),
            detected_manifests=sorted(manifests),
        )

    def _inspect_manifests(self, root: Path) -> tuple[list[str], set[str], list[str]]:
        """Walk bounded directory depth without following external symlinks to detect manifests."""
        manifests: list[str] = []
        ecosystems: set[str] = set()
        warnings: list[str] = []
        entries_visited = 0

        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            current = Path(dirpath)
            rel_dir = current.relative_to(root)
            depth = len(rel_dir.parts)

            # Prune ignored directories and bound recursion depth
            if depth >= self.max_scan_depth:
                dirnames[:] = []
            else:
                pruned: list[str] = []
                for dirname in dirnames:
                    if dirname in _IGNORED_DIRS:
                        continue
                    sub_path = current / dirname
                    if sub_path.is_symlink():
                        # Never traverse symlinks that could point outside the explicit target
                        continue
                    pruned.append(dirname)
                dirnames[:] = pruned

            for filename in filenames:
                entries_visited += 1
                if entries_visited > self.max_entries:
                    warnings.append(
                        f"Manifest inspection truncated after {self.max_entries} files in {root}."
                    )
                    return manifests, ecosystems, warnings

                lower = filename.lower()
                matched_ecosystem = _MANIFEST_ECOSYSTEM_MAP.get(lower)
                if not matched_ecosystem and lower.startswith("requirements") and lower.endswith(".txt"):
                    matched_ecosystem = "pypi"

                if matched_ecosystem:
                    rel_file = (rel_dir / filename).as_posix() if rel_dir != Path(".") else filename
                    manifests.append(rel_file)
                    ecosystems.add(matched_ecosystem)

        return manifests, ecosystems, warnings
