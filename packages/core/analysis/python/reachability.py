"""End-to-end Python static reachability analysis orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from packages.core.analysis.python.call_graph import (
    PathSearchResult,
    PythonCallGraph,
    PythonCallGraphBuilder,
)
from packages.core.analysis.python.dependency_symbols import (
    DependencySymbolCheck,
    DependencySymbolResolver,
    canonicalize_pypi_name,
)
from packages.core.analysis.python.discovery import PythonSourceDiscovery
from packages.core.analysis.python.entry_points import (
    EntryPointDetectionResult,
    EntryPointDetector,
)
from packages.core.analysis.python.imports import ImportTable, extract_import_table
from packages.core.analysis.python.parser import parse_python_module
from packages.core.analysis.python.resolver import (
    PythonCallResolver,
    RepositoryModuleIndex,
    ResolutionOutcome,
)
from packages.core.analysis.python.symbols import ModuleSymbols, extract_module_symbols
from packages.core.config.settings import Settings, get_settings
from packages.core.models.discovery import (
    DiscoveryResult,
    PackageRecord,
    VulnerabilityRecord,
)
from packages.core.models.reachability import (
    AnalysisDiagnostic,
    CandidateVulnerableSymbol,
    DependencySymbolResolutionStatus,
    EntryPointConfig,
    ReachabilityResult,
    ReachabilityState,
    StaticReachabilityReport,
    SymbolPackageTarget,
    UnresolvedCall,
    VulnerabilitySymbolEntry,
    VulnerabilitySymbolManifest,
)
from packages.core.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ReachabilityAnalysisBundle:
    """Bundled reachability report plus raw serializable call-graph artifact."""

    report: StaticReachabilityReport
    call_graph_artifact: dict[str, Any]
    manifest: VulnerabilitySymbolManifest | None = None


@dataclass(frozen=True)
class _AnalysisTarget:
    vulnerability_id: str
    lookup_ids: tuple[str, ...]
    package_id: str | None
    package_name: str
    ecosystem: str
    import_names: list[str]
    evidence_references: list[str]


class PythonReachabilityAnalyzer:
    """Performs conservative Python AST static call-graph reachability analysis."""

    def __init__(
        self,
        settings: Settings | None = None,
        source_discovery: PythonSourceDiscovery | None = None,
        call_resolver: PythonCallResolver | None = None,
        call_graph_builder: PythonCallGraphBuilder | None = None,
        entry_point_detector: EntryPointDetector | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._discovery = source_discovery or PythonSourceDiscovery(settings=self._settings)
        self._call_resolver = call_resolver or PythonCallResolver()
        self._graph_builder = call_graph_builder or PythonCallGraphBuilder(
            settings=self._settings
        )
        self._entry_detector = entry_point_detector or EntryPointDetector()

    def analyze_repository(
        self,
        target_path: Path | str,
        *,
        manifest: VulnerabilitySymbolManifest | None = None,
        manifest_sha256: str | None = None,
        entry_point_config: EntryPointConfig | None = None,
        dependency_source_dirs: list[Path] | None = None,
        explicit_package_map: dict[str, list[str]] | None = None,
        vulnerabilities: list[VulnerabilityRecord] | None = None,
        packages: list[PackageRecord] | None = None,
        vulnerability_aliases: dict[str, list[str]] | None = None,
        max_depth: int | None = None,
        max_paths: int | None = None,
    ) -> ReachabilityAnalysisBundle:
        """Analyze a Python repository statically and evaluate candidate symbol reachability."""
        depth_limit = max_depth if max_depth is not None else self._settings.max_graph_depth
        path_limit = max_paths if max_paths is not None else self._settings.max_call_paths

        discovery_res = self._discovery.discover(target_path)
        all_diagnostics: list[AnalysisDiagnostic] = list(discovery_res.diagnostics)

        module_symbols_list: list[ModuleSymbols] = []
        import_tables: list[ImportTable] = []
        files_parsed = 0
        files_failed = 0

        for py_file in discovery_res.files:
            parsed = parse_python_module(py_file)
            all_diagnostics.extend(parsed.diagnostics)
            if parsed.parsed_successfully:
                files_parsed += 1
                mod_sym = extract_module_symbols(parsed)
                imp_table = extract_import_table(parsed, mod_sym)
                module_symbols_list.append(mod_sym)
                import_tables.append(imp_table)
                all_diagnostics.extend(imp_table.diagnostics)
            else:
                files_failed += 1

        index = RepositoryModuleIndex.build(module_symbols_list, import_tables)
        resolution = self._call_resolver.resolve_repository(index)
        all_diagnostics.extend(resolution.diagnostics)

        call_graph = self._graph_builder.build(index, resolution)
        all_diagnostics.extend(call_graph.diagnostics)

        ep_result = self._entry_detector.detect(index, config=entry_point_config)
        all_diagnostics.extend(ep_result.diagnostics)
        call_graph.mark_entry_points(ep_result.entry_points)

        active_entries = ep_result.active_entry_point_ids
        entry_reachable_funcs = self._compute_entry_reachable_functions(
            call_graph, active_entries
        )

        # Map unresolved calls & wildcard modules to quickly check entry-reachable obscuration
        unresolved_by_caller: dict[str, list[UnresolvedCall]] = {}
        for ucall in resolution.unresolved_calls:
            unresolved_by_caller.setdefault(ucall.caller, []).append(ucall)

        entry_reachable_unresolved: list[UnresolvedCall] = []
        for fn_id in sorted(entry_reachable_funcs):
            entry_reachable_unresolved.extend(unresolved_by_caller.get(fn_id, []))

        entry_reachable_wildcard_modules: set[str] = set()
        for fn_id in entry_reachable_funcs:
            fn_sym = index.functions.get(fn_id)
            if fn_sym is not None:
                imp = index.imports.get(fn_sym.module_name)
                if imp is not None and imp.wildcard_imports:
                    entry_reachable_wildcard_modules.add(fn_sym.module_name)

        dep_resolver = DependencySymbolResolver(
            dependency_source_dirs=dependency_source_dirs,
            explicit_package_map=explicit_package_map,
        )

        analysis_incomplete_globally = (
            discovery_res.truncated
            or files_failed > 0
            or call_graph.truncated
            or len(active_entries) == 0
            or any(ep.confidence == "unresolved" for ep in ep_result.entry_points)
        )

        targets = self._build_analysis_targets(
            manifest=manifest,
            vulnerabilities=vulnerabilities,
            packages=packages,
            vulnerability_aliases=vulnerability_aliases,
            diagnostics=all_diagnostics,
        )

        results: list[ReachabilityResult] = []
        unique_vulns_analyzed: set[str] = set()
        candidate_symbols_evaluated = 0
        manifest_index = self._index_manifest(manifest)

        if manifest is None and not vulnerabilities:
            all_diagnostics.append(
                AnalysisDiagnostic(
                    code="NO_SYMBOL_MANIFEST",
                    severity="info",
                    message=(
                        "No vulnerability candidate symbol manifest was provided; "
                        "built call graph and detected entry points only."
                    ),
                    construct_kind="symbol_manifest",
                )
            )

        for target in targets:
            unique_vulns_analyzed.add(target.vulnerability_id)
            entry = self._match_manifest_entry(
                target=target, manifest_index=manifest_index
            )

            if entry is None or not entry.symbols:
                results.append(
                    ReachabilityResult(
                        vulnerability_id=target.vulnerability_id,
                        package_id=target.package_id,
                        package_name=target.package_name,
                        ecosystem=target.ecosystem,
                        candidate_symbol=None,
                        dependency_symbol_status=(
                            DependencySymbolResolutionStatus.DEPENDENCY_SOURCE_UNAVAILABLE
                        ),
                        reachable=None,
                        state=ReachabilityState.MISSING_CANDIDATE_SYMBOLS,
                        diagnostics=[
                            AnalysisDiagnostic(
                                code="MISSING_CANDIDATE_SYMBOLS",
                                severity="info",
                                message=(
                                    f"No candidate vulnerable symbols defined in manifest for "
                                    f"{target.vulnerability_id} ({target.package_name})."
                                ),
                                construct_kind="symbol_manifest",
                                affected_scope=target.vulnerability_id,
                            )
                        ],
                        evidence_references=target.evidence_references,
                    )
                )
                continue

            declared_imports = sorted(
                set(target.import_names) | set(entry.package.import_names)
            )
            for candidate in entry.symbols:
                candidate_symbols_evaluated += 1
                dep_check = dep_resolver.verify_symbol(
                    package_name=target.package_name or entry.package.name,
                    candidate=candidate,
                    declared_import_names=declared_imports or None,
                )
                result_item = self._evaluate_candidate_symbol(
                    target=target,
                    candidate=candidate,
                    dep_check=dep_check,
                    call_graph=call_graph,
                    active_entries=active_entries,
                    entry_reachable_unresolved=entry_reachable_unresolved,
                    entry_reachable_wildcard_modules=entry_reachable_wildcard_modules,
                    analysis_incomplete_globally=analysis_incomplete_globally,
                    depth_limit=depth_limit,
                    path_limit=path_limit,
                )
                results.append(result_item)

        truncated_overall = (
            discovery_res.truncated
            or call_graph.truncated
            or any(
                any(d.code in {"CALL_PATH_ENUMERATION_TRUNCATED", "DEPTH_LIMIT_EXCEEDED"} for d in r.diagnostics)
                for r in results
            )
        )

        report = StaticReachabilityReport(
            source_snapshot_hash=discovery_res.source_snapshot_hash,
            manifest_sha256=manifest_sha256,
            files_discovered=len(discovery_res.files),
            files_parsed=files_parsed,
            files_failed=files_failed,
            graph_node_count=len(call_graph.nodes),
            graph_edge_count=len(call_graph.edges),
            max_graph_depth=depth_limit,
            max_call_paths=path_limit,
            truncated=truncated_overall,
            vulnerabilities_analyzed=len(unique_vulns_analyzed),
            candidate_symbols_evaluated=candidate_symbols_evaluated,
            entry_points=ep_result.entry_points,
            results=results,
            unresolved_calls=resolution.unresolved_calls,
            diagnostics=self._deduplicate_diagnostics(all_diagnostics),
        )

        logger.info(
            "Completed Python static reachability analysis: %d files parsed, %d graph nodes, %d graph edges, %d results",
            files_parsed,
            report.graph_node_count,
            report.graph_edge_count,
            len(results),
        )
        return ReachabilityAnalysisBundle(
            report=report,
            call_graph_artifact=call_graph.to_serializable_dict(),
            manifest=manifest,
        )

    def analyze_discovery_result(
        self,
        discovery_result: DiscoveryResult,
        *,
        target_path: Path | str | None = None,
        manifest: VulnerabilitySymbolManifest | None = None,
        manifest_sha256: str | None = None,
        entry_point_config: EntryPointConfig | None = None,
        dependency_source_dirs: list[Path] | None = None,
        explicit_package_map: dict[str, list[str]] | None = None,
        max_depth: int | None = None,
        max_paths: int | None = None,
    ) -> tuple[DiscoveryResult, ReachabilityAnalysisBundle]:
        """Run Python static reachability analysis over findings inside ``discovery_result``."""
        resolved_target = Path(target_path or discovery_result.target.target_path)

        alias_map: dict[str, list[str]] = {}
        if discovery_result.intelligence is not None:
            for intel in discovery_result.intelligence.vulnerabilities:
                alias_map[intel.vulnerability_id] = list(
                    dict.fromkeys([intel.canonical_id, *intel.aliases])
                )

        bundle = self.analyze_repository(
            target_path=resolved_target,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            entry_point_config=entry_point_config,
            dependency_source_dirs=dependency_source_dirs,
            explicit_package_map=explicit_package_map,
            vulnerabilities=discovery_result.vulnerabilities,
            packages=discovery_result.packages,
            vulnerability_aliases=alias_map,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        updated_discovery = discovery_result.model_copy(
            update={"reachability": bundle.report}
        )
        return updated_discovery, bundle

    @staticmethod
    def _compute_entry_reachable_functions(
        call_graph: PythonCallGraph, active_entries: list[str]
    ) -> set[str]:
        reachable: set[str] = set()
        for entry_id in active_entries:
            if entry_id not in call_graph.graph:
                continue
            reachable.add(entry_id)
            reachable.update(nx.descendants(call_graph.graph, entry_id))
        return reachable

    def _build_analysis_targets(
        self,
        *,
        manifest: VulnerabilitySymbolManifest | None,
        vulnerabilities: list[VulnerabilityRecord] | None,
        packages: list[PackageRecord] | None,
        vulnerability_aliases: dict[str, list[str]] | None,
        diagnostics: list[AnalysisDiagnostic],
    ) -> list[_AnalysisTarget]:
        pkg_by_id = {pkg.package_id: pkg for pkg in (packages or [])}
        alias_lookup = vulnerability_aliases or {}
        targets: list[_AnalysisTarget] = []

        if vulnerabilities:
            skipped_non_python = 0
            for vuln in vulnerabilities:
                pkg = pkg_by_id.get(vuln.package_id)
                ecosystem = (pkg.ecosystem if pkg else "unknown").lower()
                pkg_name = pkg.name if pkg else vuln.package_id
                if ecosystem not in {"pypi", "python"}:
                    skipped_non_python += 1
                    continue

                lookup_ids = tuple(
                    dict.fromkeys([vuln.vulnerability_id, *alias_lookup.get(vuln.vulnerability_id, [])])
                )
                targets.append(
                    _AnalysisTarget(
                        vulnerability_id=vuln.vulnerability_id,
                        lookup_ids=lookup_ids,
                        package_id=vuln.package_id,
                        package_name=pkg_name,
                        ecosystem=pkg.ecosystem if pkg else "pypi",
                        import_names=[],
                        evidence_references=list(vuln.references),
                    )
                )

            if skipped_non_python > 0:
                diagnostics.append(
                    AnalysisDiagnostic(
                        code="NON_PYTHON_FINDINGS_SKIPPED",
                        severity="info",
                        message=(
                            f"Skipped {skipped_non_python} non-Python vulnerability finding(s); "
                            "only Python ('pypi') findings are within scope of this analyzer."
                        ),
                        construct_kind="ecosystem_scope",
                    )
                )

            # Also include standalone manifest entries targeting pypi packages not matched by Trivy findings?
            # Preserve clean correlation: if vulnerabilities were supplied, correlate discovered vulnerabilities.
            return targets

        if manifest is not None:
            pkg_by_norm_name: dict[str, PackageRecord] = {}
            for pkg in packages or []:
                if pkg.ecosystem.lower() in {"pypi", "python"}:
                    pkg_by_norm_name[canonicalize_pypi_name(pkg.name)] = pkg

            for entry in manifest.entries:
                if entry.package.ecosystem.lower() not in {"pypi", "python"}:
                    diagnostics.append(
                        AnalysisDiagnostic(
                            code="NON_PYTHON_MANIFEST_ENTRY_SKIPPED",
                            severity="info",
                            message=(
                                f"Skipped non-Python manifest entry for {entry.vulnerability_id} "
                                f"({entry.package.name}, ecosystem={entry.package.ecosystem})."
                            ),
                            construct_kind="ecosystem_scope",
                        )
                    )
                    continue
                matched_pkg = pkg_by_norm_name.get(
                    canonicalize_pypi_name(entry.package.name)
                )
                targets.append(
                    _AnalysisTarget(
                        vulnerability_id=entry.vulnerability_id,
                        lookup_ids=(entry.vulnerability_id,),
                        package_id=matched_pkg.package_id if matched_pkg else None,
                        package_name=entry.package.name,
                        ecosystem=entry.package.ecosystem,
                        import_names=list(entry.package.import_names),
                        evidence_references=[
                            sym.evidence_reference
                            for sym in entry.symbols
                            if sym.evidence_reference
                        ],
                    )
                )
        return targets

    @staticmethod
    def _index_manifest(
        manifest: VulnerabilitySymbolManifest | None,
    ) -> dict[str, list[VulnerabilitySymbolEntry]]:
        indexed: dict[str, list[VulnerabilitySymbolEntry]] = {}
        if manifest is None:
            return indexed
        for entry in manifest.entries:
            indexed.setdefault(entry.vulnerability_id.upper(), []).append(entry)
        return indexed

    @staticmethod
    def _match_manifest_entry(
        *,
        target: _AnalysisTarget,
        manifest_index: dict[str, list[VulnerabilitySymbolEntry]],
    ) -> VulnerabilitySymbolEntry | None:
        norm_target_pkg = canonicalize_pypi_name(target.package_name)
        for vid in target.lookup_ids:
            for entry in manifest_index.get(vid.upper(), []):
                if entry.package.ecosystem.lower() not in {"pypi", "python"}:
                    continue
                if canonicalize_pypi_name(entry.package.name) == norm_target_pkg:
                    return entry
        return None

    def _evaluate_candidate_symbol(
        self,
        *,
        target: _AnalysisTarget,
        candidate: CandidateVulnerableSymbol,
        dep_check: DependencySymbolCheck,
        call_graph: PythonCallGraph,
        active_entries: list[str],
        entry_reachable_unresolved: list[UnresolvedCall],
        entry_reachable_wildcard_modules: set[str],
        analysis_incomplete_globally: bool,
        depth_limit: int,
        path_limit: int,
    ) -> ReachabilityResult:
        diags: list[AnalysisDiagnostic] = list(dep_check.diagnostics)
        evidence_refs = list(target.evidence_references)
        if candidate.evidence_reference and candidate.evidence_reference not in evidence_refs:
            evidence_refs.append(candidate.evidence_reference)

        if dep_check.status in {
            DependencySymbolResolutionStatus.UNSUPPORTED_SYMBOL_STRUCTURE,
            DependencySymbolResolutionStatus.IMPORT_MAPPING_AMBIGUOUS,
        }:
            return ReachabilityResult(
                vulnerability_id=target.vulnerability_id,
                package_id=target.package_id,
                package_name=target.package_name,
                ecosystem=target.ecosystem,
                candidate_symbol=candidate,
                dependency_symbol_status=dep_check.status,
                reachable=None,
                state=ReachabilityState.UNRESOLVED,
                diagnostics=diags,
                evidence_references=evidence_refs,
            )

        if dep_check.status == DependencySymbolResolutionStatus.NOT_FOUND_IN_DEPENDENCY_SOURCE:
            return ReachabilityResult(
                vulnerability_id=target.vulnerability_id,
                package_id=target.package_id,
                package_name=target.package_name,
                ecosystem=target.ecosystem,
                candidate_symbol=candidate,
                dependency_symbol_status=dep_check.status,
                reachable=None,
                state=ReachabilityState.TARGET_SYMBOL_NOT_FOUND,
                diagnostics=diags,
                evidence_references=evidence_refs,
            )

        search = self._search_candidate_targets(
            call_graph=call_graph,
            active_entries=active_entries,
            candidate_targets=dep_check.candidate_graph_targets,
            depth_limit=depth_limit,
            path_limit=path_limit,
        )

        if search.paths:
            if search.truncated:
                diags.append(
                    AnalysisDiagnostic(
                        code="CALL_PATH_ENUMERATION_TRUNCATED",
                        severity="info",
                        message=(
                            f"Path enumeration reached max_call_paths limit ({path_limit}) for "
                            f"target '{candidate.qualified_name}'."
                        ),
                        construct_kind="path_traversal",
                        affected_scope=candidate.qualified_name,
                    )
                )
            shortest = search.paths[0]
            return ReachabilityResult(
                vulnerability_id=target.vulnerability_id,
                package_id=target.package_id,
                package_name=target.package_name,
                ecosystem=target.ecosystem,
                candidate_symbol=candidate,
                dependency_symbol_status=dep_check.status,
                entry_point=shortest.entry_point,
                reachable=True,
                state=ReachabilityState.REACHABLE,
                path=shortest.nodes,
                paths=search.paths,
                path_length=shortest.path_length,
                supporting_edges=search.supporting_edges,
                unresolved_calls=[],
                diagnostics=diags,
                evidence_references=evidence_refs,
            )

        # No static bounded path was found
        if search.depth_limit_exceeded:
            diags.append(
                AnalysisDiagnostic(
                    code="DEPTH_LIMIT_EXCEEDED",
                    severity="warning",
                    message=(
                        f"A call path to '{candidate.qualified_name}' exists beyond "
                        f"max_graph_depth={depth_limit}; static reachability could not "
                        "finish bounded path extraction."
                    ),
                    construct_kind="depth_cutoff",
                    affected_scope=candidate.qualified_name,
                )
            )
            return ReachabilityResult(
                vulnerability_id=target.vulnerability_id,
                package_id=target.package_id,
                package_name=target.package_name,
                ecosystem=target.ecosystem,
                candidate_symbol=candidate,
                dependency_symbol_status=dep_check.status,
                reachable=None,
                state=ReachabilityState.ANALYSIS_INCOMPLETE,
                diagnostics=diags,
                evidence_references=evidence_refs,
            )

        if analysis_incomplete_globally:
            diags.append(
                AnalysisDiagnostic(
                    code="ANALYSIS_INCOMPLETE",
                    severity="warning",
                    message=(
                        "Static analysis is incomplete (missing/failed source files, "
                        "truncated graph, or missing resolved entry points); cannot rule out reachability."
                    ),
                    construct_kind="analysis_completeness",
                    affected_scope=candidate.qualified_name,
                )
            )
            return ReachabilityResult(
                vulnerability_id=target.vulnerability_id,
                package_id=target.package_id,
                package_name=target.package_name,
                ecosystem=target.ecosystem,
                candidate_symbol=candidate,
                dependency_symbol_status=dep_check.status,
                reachable=None,
                state=ReachabilityState.ANALYSIS_INCOMPLETE,
                diagnostics=diags,
                evidence_references=evidence_refs,
            )

        if entry_reachable_unresolved or entry_reachable_wildcard_modules:
            diags.append(
                AnalysisDiagnostic(
                    code="DYNAMIC_OR_UNRESOLVED_CALLS_PRESENT",
                    severity="warning",
                    message=(
                        "Entry-reachable code contains dynamic or unresolved calls/imports; "
                        "absence of a static path does not prove unreachability."
                    ),
                    construct_kind="dynamic_constructs",
                    affected_scope=candidate.qualified_name,
                )
            )
            return ReachabilityResult(
                vulnerability_id=target.vulnerability_id,
                package_id=target.package_id,
                package_name=target.package_name,
                ecosystem=target.ecosystem,
                candidate_symbol=candidate,
                dependency_symbol_status=dep_check.status,
                reachable=None,
                state=ReachabilityState.UNRESOLVED,
                unresolved_calls=list(entry_reachable_unresolved),
                diagnostics=diags,
                evidence_references=evidence_refs,
            )

        return ReachabilityResult(
            vulnerability_id=target.vulnerability_id,
            package_id=target.package_id,
            package_name=target.package_name,
            ecosystem=target.ecosystem,
            candidate_symbol=candidate,
            dependency_symbol_status=dep_check.status,
            reachable=False,
            state=ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
            diagnostics=diags,
            evidence_references=evidence_refs,
        )

    @staticmethod
    def _search_candidate_targets(
        *,
        call_graph: PythonCallGraph,
        active_entries: list[str],
        candidate_targets: list[str],
        depth_limit: int,
        path_limit: int,
    ) -> PathSearchResult:
        merged_paths = []
        edge_map = {}
        truncated = False
        depth_exceeded = False

        for target_symbol in candidate_targets:
            res = call_graph.find_paths(
                active_entries,
                target_symbol,
                max_depth=depth_limit,
                max_paths=path_limit,
            )
            merged_paths.extend(res.paths)
            for edge in res.supporting_edges:
                edge_map[(edge.caller, edge.callee)] = edge
            truncated = truncated or res.truncated
            depth_exceeded = depth_exceeded or res.depth_limit_exceeded

        merged_paths.sort(key=lambda item: (item.path_length, tuple(item.nodes)))
        if len(merged_paths) > path_limit:
            merged_paths = merged_paths[:path_limit]
            truncated = True

        return PathSearchResult(
            paths=merged_paths,
            supporting_edges=[edge_map[k] for k in sorted(edge_map)],
            truncated=truncated,
            depth_limit_exceeded=depth_exceeded,
        )

    @staticmethod
    def _deduplicate_diagnostics(
        diagnostics: list[AnalysisDiagnostic],
    ) -> list[AnalysisDiagnostic]:
        seen: set[tuple[str, str, str | None, int | None, str | None]] = set()
        deduped: list[AnalysisDiagnostic] = []
        for diag in diagnostics:
            key = (
                diag.code,
                diag.message,
                diag.location.file if diag.location else None,
                diag.location.line if diag.location else None,
                diag.affected_scope,
            )
            if key not in seen:
                seen.add(key)
                deduped.append(diag)
        return deduped
