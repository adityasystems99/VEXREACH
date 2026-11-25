"""Conservative static forward taint tracer across Python AST call-path hops."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from packages.core.analysis.python.resolver import RepositoryModuleIndex
from packages.core.analysis.python.symbols import FunctionSymbol, extract_dotted_name
from packages.core.models.attack_path import (
    BarrierEvidence,
    DataFlowStep,
    InputSourceRecord,
    TaintFlowStatus,
)
from packages.core.models.reachability import CodeLocation, ReachabilityPath

_AMBIENT_TAINT_CALLS: frozenset[str] = frozenset(
    {
        "input",
        "os.getenv",
        "os.environ.get",
        "request.args.get",
        "request.form.get",
        "request.headers.get",
        "request.get_json",
        "request.json",
    }
)
_AMBIENT_TAINT_ATTRS: frozenset[str] = frozenset(
    {
        "sys.argv",
        "os.environ",
        "request.args",
        "request.form",
        "request.data",
        "request.json",
        "request.headers",
        "request.values",
    }
)
_SAFE_LOADER_INDICATORS: frozenset[str] = frozenset(
    {
        "yaml.SafeLoader",
        "SafeLoader",
        "yaml.safe_load",
    }
)


@dataclass
class TaintTraceResult:
    """Result of propagating taint conservatively along one static call path."""

    status: TaintFlowStatus
    steps: list[DataFlowStep] = field(default_factory=list)
    discovered_sources: list[InputSourceRecord] = field(default_factory=list)
    validation_barriers: list[BarrierEvidence] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)


def trace_taint_along_path(
    *,
    reach_path: ReachabilityPath,
    index: RepositoryModuleIndex,
    initial_tainted_vars: set[str],
) -> TaintTraceResult:
    """Trace caller-controlled data conservatively along `reach_path.nodes`.

    Distinguishes static call reachability (`CALL_PATH_ONLY_TAINT_NOT_PROVEN`) from
    observed data propagation (`TAINTED_FLOW_OBSERVED`).
    """
    nodes = reach_path.nodes
    if len(nodes) < 2:
        return TaintTraceResult(
            status=TaintFlowStatus.UNSUPPORTED_DATA_FLOW,
            missing_evidence=["Path contains fewer than two nodes."],
        )

    steps: list[DataFlowStep] = []
    discovered_sources: list[InputSourceRecord] = []
    validation_barriers: list[BarrierEvidence] = []
    assumptions: list[str] = [
        "Intra-procedural forward AST data flow approximates assignments, returns, and explicit call arguments; aliasing via shared mutable objects or closures is out of scope."
    ]
    missing_evidence: list[str] = []

    current_tainted = set(initial_tainted_vars)
    entry_sym = index.functions.get(nodes[0])
    if entry_sym is not None and current_tainted:
        for var in sorted(current_tainted):
            steps.append(
                DataFlowStep(
                    function_qualified_name=nodes[0],
                    variable_or_expr=var,
                    role="source",
                    location=entry_sym.location,
                )
            )

    # Walk each internal hop nodes[hop_idx] -> nodes[hop_idx + 1]
    for hop_idx in range(len(nodes) - 1):
        caller_id = nodes[hop_idx]
        callee_id = nodes[hop_idx + 1]
        is_final_sink_hop = hop_idx == len(nodes) - 2
        fn_sym = index.functions.get(caller_id)
        if fn_sym is None:
            return TaintTraceResult(
                status=TaintFlowStatus.UNSUPPORTED_DATA_FLOW,
                steps=steps,
                discovered_sources=discovered_sources,
                validation_barriers=validation_barriers,
                assumptions=assumptions,
                missing_evidence=[f"Missing AST for intermediate function '{caller_id}'."],
            )

        hop_result = _analyze_function_hop(
            fn_sym=fn_sym,
            callee_id=callee_id,
            edge=next(
                (e for e in reach_path.supporting_edges if e.caller == caller_id and e.callee == callee_id),
                None,
            ),
            tainted_vars=current_tainted,
            is_final_sink_hop=is_final_sink_hop,
            callee_sym=index.functions.get(callee_id),
        )
        steps.extend(hop_result.steps)
        discovered_sources.extend(hop_result.discovered_sources)
        validation_barriers.extend(hop_result.validation_barriers)
        assumptions.extend(hop_result.assumptions)

        if not hop_result.taint_reaches_callee:
            missing_evidence.append(
                f"Call to '{callee_id}' from '{caller_id}' did not pass statically tracked tainted variables/arguments (constant literals or untracked expressions observed)."
            )
            return TaintTraceResult(
                status=TaintFlowStatus.CALL_PATH_ONLY_TAINT_NOT_PROVEN,
                steps=steps,
                discovered_sources=discovered_sources,
                validation_barriers=validation_barriers,
                assumptions=assumptions,
                missing_evidence=missing_evidence,
            )

        current_tainted = hop_result.next_callee_tainted_params

    if any(b.barrier_type == "safe_loader" for b in validation_barriers):
        assumptions.append(
            "Safe loader configuration detected at sink call site; semantic safety depends on dependency version and non-overridden defaults."
        )
        return TaintTraceResult(
            status=TaintFlowStatus.SANITIZED_OR_VALIDATED,
            steps=steps,
            discovered_sources=discovered_sources,
            validation_barriers=validation_barriers,
            assumptions=assumptions,
            missing_evidence=missing_evidence,
        )

    return TaintTraceResult(
        status=TaintFlowStatus.TAINTED_FLOW_OBSERVED,
        steps=steps,
        discovered_sources=discovered_sources,
        validation_barriers=validation_barriers,
        assumptions=assumptions,
        missing_evidence=missing_evidence,
    )


@dataclass
class _HopOutcome:
    taint_reaches_callee: bool
    next_callee_tainted_params: set[str]
    steps: list[DataFlowStep] = field(default_factory=list)
    discovered_sources: list[InputSourceRecord] = field(default_factory=list)
    validation_barriers: list[BarrierEvidence] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)


def _analyze_function_hop(
    *,
    fn_sym: FunctionSymbol,
    callee_id: str,
    edge,
    tainted_vars: set[str],
    is_final_sink_hop: bool,
    callee_sym: FunctionSymbol | None,
) -> _HopOutcome:
    local_tainted = set(tainted_vars)
    steps: list[DataFlowStep] = []
    sources: list[InputSourceRecord] = []
    barriers: list[BarrierEvidence] = []
    rel_file = fn_sym.location.file
    target_lines = (
        {loc.line for loc in edge.source_locations} if edge is not None else set()
    )
    callee_short = callee_id.rsplit(".", 1)[-1]

    tainted_arg_positions: set[int] = set()
    tainted_arg_keywords: set[str] = set()
    taint_reached = False

    def expr_has_ambient_taint(expr: ast.AST) -> str | None:
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                cname = extract_dotted_name(node.func)
                if cname and (
                    cname in _AMBIENT_TAINT_CALLS
                    or any(cname.endswith(suffix) for suffix in (".args.get", ".form.get", ".headers.get", ".get_json"))
                ):
                    return cname
            elif isinstance(node, ast.Attribute):
                aname = extract_dotted_name(node)
                if aname and aname in _AMBIENT_TAINT_ATTRS:
                    return aname
        return None

    def expr_references_tainted(expr: ast.AST) -> str | None:
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in local_tainted:
                return node.id
            if isinstance(node, ast.Call):
                # Propagate taint through simple helper/wrapper expressions like expr.strip()
                cname = extract_dotted_name(node.func)
                if cname and any(cname.startswith(f"{tv}.") for tv in local_tainted):
                    return cname
        ambient = expr_has_ambient_taint(expr)
        return ambient

    def scan_stmts(stmts: list[ast.stmt]) -> None:
        nonlocal taint_reached
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Only skip unrelated nested scopes; nested calls to target line still checked below
                if stmt.name == callee_short or getattr(stmt, "lineno", None) in target_lines:
                    pass
                else:
                    continue

            loc = CodeLocation(
                file=rel_file,
                line=max(1, getattr(stmt, "lineno", fn_sym.location.line)),
                column=max(0, getattr(stmt, "col_offset", 0)),
            )

            # Detect validation guards like `if not re.fullmatch(...)` or `isinstance(...)`
            if isinstance(stmt, ast.If):
                test_text = ast.unparse(stmt.test)
                if "isinstance(" in test_text or "fullmatch(" in test_text or "allowlist" in test_text.lower():
                    barriers.append(
                        BarrierEvidence(
                            barrier_type="input_validation",
                            mechanism=f"conditional_guard:{test_text[:80]}",
                            location=loc,
                            confidence="low",
                            notes="Conditional validation check present; static analysis does not prove sanitization completeness.",
                        )
                    )

            if isinstance(stmt, ast.Assign):
                ref = expr_references_tainted(stmt.value)
                ambient = expr_has_ambient_taint(stmt.value)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if ambient:
                            local_tainted.add(target.id)
                            sources.append(
                                InputSourceRecord(
                                    source_kind="ambient_runtime_input",
                                    variable_name=target.id,
                                    location=loc,
                                    description=f"Assigned from ambient input '{ambient}'.",
                                )
                            )
                            steps.append(
                                DataFlowStep(
                                    function_qualified_name=fn_sym.qualified_name,
                                    variable_or_expr=f"{target.id} = {ambient}",
                                    role="source",
                                    location=loc,
                                )
                            )
                        elif ref:
                            local_tainted.add(target.id)
                            steps.append(
                                DataFlowStep(
                                    function_qualified_name=fn_sym.qualified_name,
                                    variable_or_expr=f"{target.id} <- {ref}",
                                    role="propagation",
                                    location=loc,
                                )
                            )
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                ref = expr_references_tainted(stmt.value)
                if ref:
                    local_tainted.add(stmt.target.id)
                    steps.append(
                        DataFlowStep(
                            function_qualified_name=fn_sym.qualified_name,
                            variable_or_expr=f"{stmt.target.id} <- {ref}",
                            role="propagation",
                            location=loc,
                        )
                    )

            # Inspect ast.Call expressions in this statement for calls to callee_id
            for sub in ast.walk(stmt):
                if not isinstance(sub, ast.Call):
                    continue
                sub_line = max(1, getattr(sub, "lineno", loc.line))
                sub_name = extract_dotted_name(sub.func) or ""
                matches_line = (sub_line in target_lines) if target_lines else False
                matches_name = (
                    sub_name == callee_id
                    or sub_name == callee_short
                    or sub_name.endswith(f".{callee_short}")
                )
                if not (matches_line or matches_name):
                    continue

                call_loc = CodeLocation(
                    file=rel_file,
                    line=sub_line,
                    column=max(0, getattr(sub, "col_offset", 0)),
                )
                # Detect SafeLoader keyword barrier if final sink
                if is_final_sink_hop:
                    for kw in sub.keywords:
                        kw_val = ast.unparse(kw.value)
                        if any(sl in kw_val for sl in _SAFE_LOADER_INDICATORS):
                            barriers.append(
                                BarrierEvidence(
                                    barrier_type="safe_loader",
                                    mechanism=f"{kw.arg}={kw_val}",
                                    location=call_loc,
                                    confidence="medium",
                                    notes="Explicit SafeLoader argument observed at call site.",
                                )
                            )

                for arg_idx, arg_expr in enumerate(sub.args):
                    tainted_ref = expr_references_tainted(arg_expr)
                    if tainted_ref is not None:
                        taint_reached = True
                        tainted_arg_positions.add(arg_idx)
                        steps.append(
                            DataFlowStep(
                                function_qualified_name=fn_sym.qualified_name,
                                variable_or_expr=f"{ast.unparse(arg_expr)} (from {tainted_ref})",
                                role="sink_argument" if is_final_sink_hop else "parameter_binding",
                                location=call_loc,
                            )
                        )
                for kw in sub.keywords:
                    tainted_ref = expr_references_tainted(kw.value)
                    if tainted_ref is not None:
                        taint_reached = True
                        if kw.arg:
                            tainted_arg_keywords.add(kw.arg)
                        steps.append(
                            DataFlowStep(
                                function_qualified_name=fn_sym.qualified_name,
                                variable_or_expr=f"{kw.arg}={ast.unparse(kw.value)} (from {tainted_ref})",
                                role="sink_argument" if is_final_sink_hop else "parameter_binding",
                                location=call_loc,
                            )
                        )

            # Recurse into child blocks (if/try/with/for)
            for child_attr in ("body", "orelse", "finalbody"):
                blk = getattr(stmt, child_attr, None)
                if isinstance(blk, list) and not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    scan_stmts(blk)
            for handler in getattr(stmt, "handlers", []) or []:
                if isinstance(handler, ast.ExceptHandler):
                    scan_stmts(handler.body)

    scan_stmts(fn_sym.body_stmts)

    # Bind positional/keyword tainted args to callee parameter names
    next_params: set[str] = set(tainted_arg_keywords)
    if callee_sym is not None and isinstance(
        callee_sym.ast_node, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        param_list = list(callee_sym.ast_node.args.posonlyargs) + list(
            callee_sym.ast_node.args.args
        )
        # Drop self/cls for bound method calls
        if param_list and param_list[0].arg in {"self", "cls"}:
            param_list = param_list[1:]
        for pos in tainted_arg_positions:
            if pos < len(param_list):
                next_params.add(param_list[pos].arg)

    return _HopOutcome(
        taint_reaches_callee=taint_reached,
        next_callee_tainted_params=next_params,
        steps=steps,
        discovered_sources=sources,
        validation_barriers=barriers,
    )
