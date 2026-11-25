"""Entry-point configuration loading and conservative Python framework detectors."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from packages.core.analysis.python.imports import ImportTable
from packages.core.analysis.python.resolver import RepositoryModuleIndex
from packages.core.analysis.python.symbols import DecoratorInfo, FunctionSymbol, ModuleSymbols
from packages.core.models.reachability import (
    AnalysisDiagnostic,
    EntryPoint,
    EntryPointConfig,
)

HTTP_ROUTE_METHODS: frozenset[str] = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "options",
        "head",
        "api_route",
        "websocket",
    }
)


@dataclass
class EntryPointDetectionResult:
    """Detected and user-configured entry points plus diagnostics."""

    entry_points: list[EntryPoint] = field(default_factory=list)
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)

    @property
    def active_entry_point_ids(self) -> list[str]:
        """Return qualified names of resolved entry points ready for graph traversal."""
        return sorted(
            {
                ep.qualified_name
                for ep in self.entry_points
                if ep.confidence != "unresolved"
            }
        )


def load_entry_point_config(config_path: Path | str) -> EntryPointConfig:
    """Load and validate explicit entry points from JSON."""
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Entry-point config file not found: {path}")

    raw_text = path.read_text(encoding="utf-8")
    data = json.loads(raw_text)
    if isinstance(data, list):
        data = {"entry_points": data}
    return EntryPointConfig.model_validate(data, strict=False)


class EntryPointDetector:
    """Identifies Python application entry points conservatively."""

    def detect(
        self,
        index: RepositoryModuleIndex,
        config: EntryPointConfig | None = None,
    ) -> EntryPointDetectionResult:
        """Detect explicit user entry points, ``__main__`` blocks, and supported framework routes."""
        result = EntryPointDetectionResult()
        seen: set[tuple[str, str]] = set()

        def record(ep: EntryPoint) -> None:
            key = (ep.qualified_name, ep.source)
            if key not in seen:
                seen.add(key)
                result.entry_points.append(ep)

        # 1. Explicit user-declared entry points
        if config is not None:
            for rule in config.entry_points:
                matched_fn = self._match_configured_rule(
                    index, module=rule.module, qualified_name=rule.qualified_name
                )
                if matched_fn is not None:
                    record(
                        EntryPoint(
                            qualified_name=matched_fn.qualified_name,
                            module=matched_fn.module_name,
                            source=rule.source,
                            confidence="verified",
                            location=matched_fn.location,
                            metadata={"configured_rule": f"{rule.module}:{rule.qualified_name}"},
                        )
                    )
                else:
                    target_id = (
                        rule.qualified_name
                        if rule.qualified_name.startswith(f"{rule.module}.")
                        else f"{rule.module}.{rule.qualified_name}"
                    )
                    record(
                        EntryPoint(
                            qualified_name=target_id,
                            module=rule.module,
                            source=rule.source,
                            confidence="unresolved",
                            metadata={"configured_rule": f"{rule.module}:{rule.qualified_name}"},
                        )
                    )
                    result.diagnostics.append(
                        AnalysisDiagnostic(
                            code="CONFIGURED_ENTRY_POINT_NOT_FOUND",
                            severity="warning",
                            message=(
                                f"Configured entry point '{rule.qualified_name}' in module "
                                f"'{rule.module}' was not found in discovered Python AST symbols."
                            ),
                            construct_kind="entry_point_config",
                            affected_scope=target_id,
                        )
                    )

        # 2. Automatic detectors per module
        for mod_name in sorted(index.modules):
            mod_sym = index.modules[mod_name]
            imp_table = index.imports.get(mod_name, ImportTable(module_name=mod_name))

            for fn_qual in sorted(mod_sym.functions):
                fn_sym = mod_sym.functions[fn_qual]

                if fn_sym.node_type == "main_block":
                    record(
                        EntryPoint(
                            qualified_name=fn_qual,
                            module=mod_name,
                            source="python_main_block",
                            confidence="verified",
                            location=fn_sym.location,
                        )
                    )
                    continue

                for dec in fn_sym.decorators:
                    detected = self._detect_decorator_entry_point(
                        dec=dec,
                        fn_sym=fn_sym,
                        mod_sym=mod_sym,
                        imp_table=imp_table,
                        index=index,
                    )
                    if detected is not None:
                        record(detected)

        if not result.active_entry_point_ids:
            result.diagnostics.append(
                AnalysisDiagnostic(
                    code="NO_ENTRY_POINTS_DETECTED",
                    severity="warning",
                    message=(
                        "No application entry points were detected or resolved "
                        "(checked explicit config, __main__ blocks, FastAPI, Flask, Typer, Click)."
                    ),
                    construct_kind="entry_point_detection",
                )
            )

        result.entry_points.sort(key=lambda ep: (ep.qualified_name, ep.source))
        return result

    @staticmethod
    def _match_configured_rule(
        index: RepositoryModuleIndex, *, module: str, qualified_name: str
    ) -> FunctionSymbol | None:
        if qualified_name in index.functions:
            return index.functions[qualified_name]
        prefixed = f"{module}.{qualified_name}"
        if prefixed in index.functions:
            return index.functions[prefixed]
        return None

    def _detect_decorator_entry_point(
        self,
        *,
        dec: DecoratorInfo,
        fn_sym: FunctionSymbol,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        index: RepositoryModuleIndex,
    ) -> EntryPoint | None:
        attr = dec.attr_name
        base = dec.base_name
        raw_lower = dec.raw_name.lower()

        if attr is None or base is None:
            return None

        receiver_type = self._resolve_decorator_receiver_type(
            base_name=base,
            mod_sym=mod_sym,
            imp_table=imp_table,
            index=index,
        )

        # CLI frameworks: Typer and Click
        if attr in {"command", "callback"} or raw_lower.startswith("click."):
            if receiver_type and (
                "typer" in receiver_type.lower() or base == "click" or "click" in receiver_type.lower()
            ):
                source = "typer_command" if "typer" in receiver_type.lower() else "click_command"
                return EntryPoint(
                    qualified_name=fn_sym.qualified_name,
                    module=fn_sym.module_name,
                    source=source,
                    confidence="verified",
                    location=fn_sym.location,
                    metadata={"decorator": dec.raw_name},
                )
            if base == "click" and "click" in imp_table.module_bindings:
                return EntryPoint(
                    qualified_name=fn_sym.qualified_name,
                    module=fn_sym.module_name,
                    source="click_command",
                    confidence="verified",
                    location=fn_sym.location,
                    metadata={"decorator": dec.raw_name},
                )

        # Web routes: FastAPI / Flask / Blueprint
        if attr in HTTP_ROUTE_METHODS and receiver_type is not None:
            rt_lower = receiver_type.lower()
            meta: dict[str, str] = {"decorator": dec.raw_name}
            if dec.args_preview:
                meta["route"] = dec.args_preview[0]
            if "fastapi" in rt_lower or "apirouter" in rt_lower:
                return EntryPoint(
                    qualified_name=fn_sym.qualified_name,
                    module=fn_sym.module_name,
                    source="fastapi_route",
                    confidence="verified",
                    location=fn_sym.location,
                    metadata=meta,
                )
            if "flask" in rt_lower or "blueprint" in rt_lower:
                return EntryPoint(
                    qualified_name=fn_sym.qualified_name,
                    module=fn_sym.module_name,
                    source="flask_route",
                    confidence="verified",
                    location=fn_sym.location,
                    metadata=meta,
                )

        return None

    def _resolve_decorator_receiver_type(
        self,
        *,
        base_name: str,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        index: RepositoryModuleIndex,
    ) -> str | None:
        # 1. Local module assignment (e.g., app = FastAPI())
        if base_name in mod_sym.module_var_types:
            raw_type = mod_sym.module_var_types[base_name]
            imp_hit = imp_table.lookup_dotted(raw_type)
            if imp_hit is not None:
                binding, remainder = imp_hit
                return (
                    f"{binding.qualified_target}.{remainder}"
                    if remainder
                    else binding.qualified_target
                )
            return raw_type

        # 2. Direct import binding (e.g., import click or from app.main import app)
        binding = imp_table.lookup(base_name)
        if binding is not None:
            # Check if imported from another repository module that constructed FastAPI/Flask/Typer
            src_mod = index.modules.get(binding.target_module)
            if src_mod is not None and binding.target_symbol:
                src_type = src_mod.module_var_types.get(binding.target_symbol)
                if src_type:
                    src_imp = index.imports.get(binding.target_module)
                    if src_imp is not None:
                        src_hit = src_imp.lookup_dotted(src_type)
                        if src_hit is not None:
                            sb, rem = src_hit
                            return f"{sb.qualified_target}.{rem}" if rem else sb.qualified_target
                    return src_type
            return binding.qualified_target

        return None
