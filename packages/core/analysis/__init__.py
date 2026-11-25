"""Unified cross-language static reachability exports and hybrid Python/Go orchestrator."""

from __future__ import annotations

from pathlib import Path

from packages.core.analysis.go import (
    GoReachabilityAnalyzer,
    merge_reachability_bundles,
    repository_contains_go,
    repository_contains_python,
)
from packages.core.analysis.python import (
    PythonReachabilityAnalyzer,
    ReachabilityAnalysisBundle,
)
from packages.core.config.settings import Settings, get_settings
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.reachability import EntryPointConfig, VulnerabilitySymbolManifest


def run_hybrid_reachability_repository(
    target_path: Path | str,
    *,
    language: str = "auto",
    settings: Settings | None = None,
    manifest: VulnerabilitySymbolManifest | None = None,
    manifest_sha256: str | None = None,
    entry_point_config: EntryPointConfig | None = None,
    dependency_source_dirs: list[Path] | None = None,
    max_depth: int | None = None,
    max_paths: int | None = None,
) -> ReachabilityAnalysisBundle:
    """Execute Python, Go, or combined static reachability analysis over a target path."""
    cfg = settings or get_settings()
    lang = language.strip().lower()
    if lang not in {"auto", "python", "go"}:
        raise ValueError(f"Unsupported reachability language '{language}'; expected 'auto', 'python', or 'go'.")

    has_py = repository_contains_python(target_path) if lang == "auto" else (lang == "python")
    has_go = repository_contains_go(target_path) if lang == "auto" else (lang == "go")

    bundles: list[ReachabilityAnalysisBundle] = []
    if has_py or (lang == "auto" and not has_go):
        bundles.append(
            PythonReachabilityAnalyzer(settings=cfg).analyze_repository(
                target_path,
                manifest=manifest,
                manifest_sha256=manifest_sha256,
                entry_point_config=entry_point_config,
                dependency_source_dirs=dependency_source_dirs,
                max_depth=max_depth,
                max_paths=max_paths,
            )
        )
    if has_go:
        bundles.append(
            GoReachabilityAnalyzer(settings=cfg).analyze_repository(
                target_path,
                manifest=manifest,
                manifest_sha256=manifest_sha256,
                entry_point_config=entry_point_config,
                dependency_source_dirs=dependency_source_dirs,
                max_depth=max_depth,
                max_paths=max_paths,
            )
        )

    return merge_reachability_bundles(bundles)


def run_hybrid_reachability_discovery(
    discovery_result: DiscoveryResult,
    *,
    target_path: Path | str | None = None,
    analyze_python: bool = True,
    analyze_go: bool = True,
    settings: Settings | None = None,
    manifest: VulnerabilitySymbolManifest | None = None,
    manifest_sha256: str | None = None,
    entry_point_config: EntryPointConfig | None = None,
    dependency_source_dirs: list[Path] | None = None,
    max_depth: int | None = None,
    max_paths: int | None = None,
) -> tuple[DiscoveryResult, ReachabilityAnalysisBundle]:
    """Run applicable Python and/or Go static analyzers against a DiscoveryResult."""
    cfg = settings or get_settings()
    resolved_target = Path(target_path or discovery_result.target.target_path)

    pkg_ecos = {p.ecosystem.lower() for p in discovery_result.packages}
    run_go = analyze_go and (
        repository_contains_go(resolved_target)
        or bool(pkg_ecos & {"golang", "go", "gomod", "gobinary"})
    )
    run_py = analyze_python and (
        repository_contains_python(resolved_target)
        or bool(pkg_ecos & {"pypi", "python"})
        or not run_go
    )

    bundles: list[ReachabilityAnalysisBundle] = []
    if run_py:
        _, py_bundle = PythonReachabilityAnalyzer(settings=cfg).analyze_discovery_result(
            discovery_result,
            target_path=resolved_target,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            entry_point_config=entry_point_config,
            dependency_source_dirs=dependency_source_dirs,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        bundles.append(py_bundle)
    if run_go:
        _, go_bundle = GoReachabilityAnalyzer(settings=cfg).analyze_discovery_result(
            discovery_result,
            target_path=resolved_target,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            entry_point_config=entry_point_config,
            dependency_source_dirs=dependency_source_dirs,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        bundles.append(go_bundle)

    if not bundles:
        _, fallback = PythonReachabilityAnalyzer(settings=cfg).analyze_discovery_result(
            discovery_result,
            target_path=resolved_target,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            entry_point_config=entry_point_config,
            dependency_source_dirs=dependency_source_dirs,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        bundles.append(fallback)

    merged = merge_reachability_bundles(bundles)
    return discovery_result.model_copy(update={"reachability": merged.report}), merged


__all__ = [
    "GoReachabilityAnalyzer",
    "PythonReachabilityAnalyzer",
    "ReachabilityAnalysisBundle",
    "merge_reachability_bundles",
    "repository_contains_go",
    "repository_contains_python",
    "run_hybrid_reachability_discovery",
    "run_hybrid_reachability_repository",
]
