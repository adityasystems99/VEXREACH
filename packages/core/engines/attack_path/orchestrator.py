"""Attack Path Intelligence orchestrator correlating entry exposure, taint flow, and static paths."""

from __future__ import annotations

from pathlib import Path

from packages.core.analysis.python.discovery import PythonSourceDiscovery
from packages.core.analysis.python.imports import extract_import_table
from packages.core.analysis.python.parser import parse_python_module
from packages.core.analysis.python.resolver import RepositoryModuleIndex
from packages.core.analysis.python.symbols import extract_module_symbols
from packages.core.config.settings import Settings, get_settings
from packages.core.engines.attack_path.surface_classifier import classify_entry_surface
from packages.core.engines.attack_path.taint_tracer import trace_taint_along_path
from packages.core.models.attack_path import (
    AttackPathRecord,
    AttackPathReport,
    TaintFlowStatus,
)
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.reachability import ReachabilityState, StaticReachabilityReport
from packages.core.utils.logging import get_logger

logger = get_logger("attack_path.orchestrator")


class AttackPathOrchestrator:
    """Evaluates exposure surfaces, barriers, and conservative taint along reachable call paths."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def analyze_from_reachability(
        self,
        *,
        target_path: Path | str,
        reachability_report: StaticReachabilityReport,
    ) -> AttackPathReport:
        """Build `AttackPathReport` for all `REACHABLE` results in `reachability_report`."""
        reachable_results = [
            res
            for res in reachability_report.results
            if res.state == ReachabilityState.REACHABLE and res.paths
        ]
        if not reachable_results:
            return AttackPathReport(
                paths_evaluated=0,
                warnings=[
                    "No statically reachable call paths present in reachability report; zero attack paths generated."
                ],
            )

        has_py_paths = any(
            r.analysis_scope.startswith("python") for r in reachable_results
        )
        index = None
        if has_py_paths:
            source_discovery = PythonSourceDiscovery(settings=self._settings).discover(target_path)
            mod_syms = []
            imp_tables = []
            for py_file in source_discovery.files:
                parsed = parse_python_module(py_file)
                if parsed.parsed_successfully:
                    sym = extract_module_symbols(parsed)
                    imp = extract_import_table(parsed, sym)
                    mod_syms.append(sym)
                    imp_tables.append(imp)
            index = RepositoryModuleIndex.build(mod_syms, imp_tables)

        entry_by_qname = {ep.qualified_name: ep for ep in reachability_report.entry_points}
        records: list[AttackPathRecord] = []

        for r_res in reachable_results:
            for r_path in r_res.paths:
                ep = entry_by_qname.get(r_path.entry_point)
                if ep is None:
                    continue
                fn_sym = index.functions.get(ep.qualified_name) if index is not None else None
                surface = classify_entry_surface(ep, fn_sym)
                if index is not None and r_res.analysis_scope.startswith("python"):
                    taint = trace_taint_along_path(
                        reach_path=r_path,
                        index=index,
                        initial_tainted_vars=surface.tainted_initial_vars,
                    )
                    taint_status = taint.status
                    taint_steps = taint.steps
                    taint_sources = taint.discovered_sources
                    taint_barriers = taint.validation_barriers
                    taint_assumptions = taint.assumptions
                    taint_missing = taint.missing_evidence
                else:
                    taint_status = TaintFlowStatus.CALL_PATH_ONLY_TAINT_NOT_PROVEN
                    taint_steps = []
                    taint_sources = []
                    taint_barriers = []
                    taint_assumptions = [
                        "Go static call path traced via Go AST; inter-procedural data-flow taint is conservatively marked unverified."
                    ]
                    taint_missing = [
                        "Go SSA inter-procedural taint proof is not yet enabled; path confirms call reachability only."
                    ]

                all_sources = [*surface.input_sources, *taint_sources]
                all_validation_barriers = [
                    *surface.validation_barriers,
                    *taint_barriers,
                ]
                trust_boundaries = [
                    *surface.trust_boundaries,
                    f"Application Code -> External Dependency Symbol ({r_path.target_symbol})",
                ]
                missing_ev = [*surface.missing_evidence, *taint_missing]
                assumptions = [
                    "Attack path evaluation models static AST control/data flow only; runtime execution and practical exploitability require separate confirmation.",
                    *taint_assumptions,
                ]
                explanation = (
                    f"{surface.exposure_surface.value} entry '{ep.qualified_name}' reaches "
                    f"'{r_path.target_symbol}' in {r_path.path_length} hop(s) "
                    f"({' -> '.join(r_path.nodes)}); data flow: {taint_status.value}."
                )

                records.append(
                    AttackPathRecord(
                        vulnerability_id=r_res.vulnerability_id,
                        package_name=r_res.package_name,
                        target_symbol=r_path.target_symbol,
                        entry_point=ep.qualified_name,
                        exposure_surface=surface.exposure_surface,
                        is_network_exposed=surface.is_network_exposed,
                        input_sources=all_sources,
                        auth_barriers=surface.auth_barriers,
                        validation_barriers=all_validation_barriers,
                        call_hops=list(r_path.nodes),
                        data_flow_status=taint_status,
                        data_flow_steps=taint_steps,
                        trust_boundaries=trust_boundaries,
                        assumptions=assumptions,
                        missing_evidence=missing_ev,
                        explanation=explanation,
                        evidence_references=list(r_res.evidence_references),
                    )
                )

        net_exposed = sum(1 for r in records if r.is_network_exposed)
        taint_obs = sum(
            1 for r in records if r.data_flow_status == TaintFlowStatus.TAINTED_FLOW_OBSERVED
        )
        call_only = sum(
            1
            for r in records
            if r.data_flow_status == TaintFlowStatus.CALL_PATH_ONLY_TAINT_NOT_PROVEN
        )
        return AttackPathReport(
            paths_evaluated=len(records),
            network_exposed_paths=net_exposed,
            taint_observed_paths=taint_obs,
            call_path_only_paths=call_only,
            paths=records,
        )

    def analyze_discovery_result(
        self,
        discovery_result: DiscoveryResult,
        *,
        target_path: Path | str | None = None,
    ) -> tuple[DiscoveryResult, AttackPathReport]:
        """Attach `AttackPathReport` onto `DiscoveryResult` when reachability exists."""
        if discovery_result.reachability is None:
            empty = AttackPathReport(
                warnings=["Reachability analysis has not been executed; attack path evaluation skipped."]
            )
            return discovery_result.model_copy(update={"attack_paths": empty}), empty

        resolved_target = Path(target_path or discovery_result.target.target_path)
        report = self.analyze_from_reachability(
            target_path=resolved_target,
            reachability_report=discovery_result.reachability,
        )
        updated = discovery_result.model_copy(update={"attack_paths": report})
        logger.info(
            "Attack Path Intelligence evaluated %d path(s): network_exposed=%d, tainted=%d",
            report.paths_evaluated,
            report.network_exposed_paths,
            report.taint_observed_paths,
        )
        return updated, report
