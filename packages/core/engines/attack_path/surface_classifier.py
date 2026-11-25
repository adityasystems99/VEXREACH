"""Entry-point exposure, input-source, and authentication/validation barrier classifier."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from packages.core.analysis.python.symbols import FunctionSymbol
from packages.core.models.attack_path import (
    BarrierEvidence,
    ExposureSurface,
    InputSourceRecord,
)
from packages.core.models.reachability import CodeLocation, EntryPoint

_AUTH_KEYWORDS = (
    "auth",
    "login_required",
    "requires_auth",
    "jwt",
    "oauth",
    "permission",
    "current_user",
    "verify_token",
    "require_api_key",
    "security",
)
_FASTAPI_INTERNAL_ANNOTATIONS = {
    "Depends",
    "BackgroundTasks",
    "Response",
    "WebSocket",
}
_VALIDATION_DECORATORS = ("validate", "validator", "schema", "pydantic")


@dataclass
class EntrySurfaceClassification:
    """Classified ingress surface, inputs, and guards for a single entry point."""

    exposure_surface: ExposureSurface
    is_network_exposed: bool
    input_sources: list[InputSourceRecord] = field(default_factory=list)
    auth_barriers: list[BarrierEvidence] = field(default_factory=list)
    validation_barriers: list[BarrierEvidence] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    tainted_initial_vars: set[str] = field(default_factory=set)
    missing_evidence: list[str] = field(default_factory=list)


def classify_entry_surface(
    entry: EntryPoint,
    fn_sym: FunctionSymbol | None,
) -> EntrySurfaceClassification:
    """Classify exposure surface, input parameters, and auth barriers statically."""
    source_kind = entry.source.lower()
    input_sources: list[InputSourceRecord] = []
    auth_barriers: list[BarrierEvidence] = []
    validation_barriers: list[BarrierEvidence] = []
    trust_boundaries: list[str] = []
    tainted_params: set[str] = set()
    missing_evidence: list[str] = []

    is_http = source_kind in {
        "fastapi_route",
        "flask_route",
        "go_http_handler",
        "go_gin_route",
        "go_chi_route",
        "go_echo_route",
    }
    is_cli = source_kind in {
        "typer_command",
        "click_command",
        "python_main_block",
        "go_main",
        "go_cobra_command",
    }

    if fn_sym is not None:
        # 1. Inspect decorators for authentication/authorization barriers
        for dec in fn_sym.decorators:
            dec_low = dec.raw_name.lower()
            if any(kw in dec_low for kw in _AUTH_KEYWORDS):
                auth_barriers.append(
                    BarrierEvidence(
                        barrier_type="authentication",
                        mechanism=f"decorator:{dec.raw_name}",
                        location=dec.location,
                        confidence="medium",
                        notes="Authentication/authorization decorator detected on handler.",
                    )
                )

        # 2. Inspect AST parameters and Depends(...) defaults when FunctionDef/AsyncFunctionDef
        if isinstance(fn_sym.ast_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_node = fn_sym.ast_node
            all_pos_kw = list(fn_node.args.posonlyargs) + list(fn_node.args.args)
            defaults = list(fn_node.args.defaults)
            default_offset = len(all_pos_kw) - len(defaults)

            for idx, arg in enumerate(all_pos_kw):
                if arg.arg in {"self", "cls"}:
                    continue
                default_node = (
                    defaults[idx - default_offset] if idx >= default_offset else None
                )
                ann_str = ast.unparse(arg.annotation) if arg.annotation else ""
                default_str = ast.unparse(default_node) if default_node else ""
                loc = CodeLocation(
                    file=fn_sym.location.file,
                    line=max(1, getattr(arg, "lineno", fn_sym.location.line)),
                    column=max(0, getattr(arg, "col_offset", 0)),
                )

                if "Depends(" in default_str or "Security(" in default_str:
                    if any(kw in default_str.lower() for kw in _AUTH_KEYWORDS):
                        auth_barriers.append(
                            BarrierEvidence(
                                barrier_type="authentication",
                                mechanism=f"fastapi_dependency:{default_str}",
                                location=loc,
                                confidence="medium",
                                notes="FastAPI Depends/Security authentication parameter observed.",
                            )
                        )
                    continue

                if any(tok in ann_str for tok in _FASTAPI_INTERNAL_ANNOTATIONS):
                    continue

                if is_http:
                    src_type = _classify_http_param(ann_str, default_str)
                    input_sources.append(
                        InputSourceRecord(
                            source_kind=src_type,
                            variable_name=arg.arg,
                            location=loc,
                            description=f"HTTP handler parameter '{arg.arg}' (annotation='{ann_str or 'untyped'}').",
                        )
                    )
                    if ann_str and ann_str[0].isupper() and ann_str not in {"str", "bytes", "Request"}:
                        validation_barriers.append(
                            BarrierEvidence(
                                barrier_type="input_validation",
                                mechanism=f"typed_model_parameter:{arg.arg}:{ann_str}",
                                location=loc,
                                confidence="low",
                                notes="Parameter type annotation may enforce structural schema validation, not payload safety.",
                            )
                        )
                    tainted_params.add(arg.arg)
                elif is_cli:
                    input_sources.append(
                        InputSourceRecord(
                            source_kind="cli_argument",
                            variable_name=arg.arg,
                            location=loc,
                            description=f"CLI command parameter '{arg.arg}'.",
                        )
                    )
                    tainted_params.add(arg.arg)
                else:
                    input_sources.append(
                        InputSourceRecord(
                            source_kind="function_parameter",
                            variable_name=arg.arg,
                            location=loc,
                            description=f"Entry function parameter '{arg.arg}'.",
                        )
                    )
                    tainted_params.add(arg.arg)

    if is_http:
        if fn_sym is None and source_kind.startswith("go_") and not input_sources:
            input_sources.append(
                InputSourceRecord(
                    source_kind="http_request_object",
                    variable_name="r *http.Request",
                    location=entry.location,
                    description="Go HTTP handler receiving incoming *http.Request payload/parameters.",
                )
            )
        route_label = entry.metadata.get("route", entry.qualified_name)
        if auth_barriers:
            surface = ExposureSurface.NETWORK_HTTP_AUTHENTICATED
            trust_boundaries.append(
                f"Internet -> Authenticated HTTP Endpoint ({route_label})"
            )
        else:
            surface = ExposureSurface.NETWORK_HTTP_PUBLIC
            trust_boundaries.append(f"Internet -> HTTP Endpoint ({route_label})")
            missing_evidence.append(
                "No handler-level authentication decorator or Depends() security dependency detected statically; middleware auth outside handler cannot be ruled out."
            )
        return EntrySurfaceClassification(
            exposure_surface=surface,
            is_network_exposed=True,
            input_sources=input_sources,
            auth_barriers=auth_barriers,
            validation_barriers=validation_barriers,
            trust_boundaries=trust_boundaries,
            tainted_initial_vars=tainted_params,
            missing_evidence=missing_evidence,
        )

    if is_cli:
        if entry.source in {"python_main_block", "go_main"}:
            input_sources.append(
                InputSourceRecord(
                    source_kind="process_argv_env_stdin",
                    variable_name="os.Args/os.Getenv" if entry.source == "go_main" else "sys.argv/os.environ",
                    location=entry.location,
                    description="Application main entry point executing with local CLI/env/stdin context.",
                )
            )
        trust_boundaries.append(f"Local Operator / CLI -> {entry.qualified_name}")
        return EntrySurfaceClassification(
            exposure_surface=ExposureSurface.CLI_LOCAL_INPUT,
            is_network_exposed=False,
            input_sources=input_sources,
            auth_barriers=auth_barriers,
            validation_barriers=validation_barriers,
            trust_boundaries=trust_boundaries,
            tainted_initial_vars=tainted_params,
            missing_evidence=missing_evidence,
        )

    trust_boundaries.append(f"Internal Caller -> {entry.qualified_name}")
    missing_evidence.append(
        "Entry point configured internally without HTTP/CLI ingress metadata; external network exposure not established."
    )
    return EntrySurfaceClassification(
        exposure_surface=ExposureSurface.INTERNAL_FUNCTION,
        is_network_exposed=False,
        input_sources=input_sources,
        auth_barriers=auth_barriers,
        validation_barriers=validation_barriers,
        trust_boundaries=trust_boundaries,
        tainted_initial_vars=tainted_params,
        missing_evidence=missing_evidence,
    )


def _classify_http_param(ann_str: str, default_str: str) -> str:
    if "Header(" in default_str:
        return "http_header"
    if "Cookie(" in default_str:
        return "http_cookie"
    if "Body(" in default_str:
        return "http_body"
    if "Form(" in default_str:
        return "http_form"
    if "File(" in default_str or "UploadFile" in ann_str:
        return "http_upload"
    if "Request" in ann_str:
        return "http_request_object"
    return "http_param_or_body"
