"""Static Python import extraction and scope-aware import binding table."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from packages.core.analysis.python.parser import ParsedPythonModule
from packages.core.analysis.python.symbols import ModuleSymbols, _iter_control_flow_bodies
from packages.core.models.reachability import AnalysisDiagnostic, CodeLocation


@dataclass(frozen=True)
class ImportBinding:
    """Single resolved import alias or module binding."""

    local_name: str
    target_module: str
    target_symbol: str | None
    is_relative: bool
    level: int
    location: CodeLocation
    raw_statement: str

    @property
    def qualified_target(self) -> str:
        """Canonical dotted path represented by this binding."""
        if self.target_symbol:
            return f"{self.target_module}.{self.target_symbol}"
        return self.target_module


@dataclass
class ImportTable:
    """Per-module and per-function import bindings with diagnostic tracking."""

    module_name: str
    module_bindings: dict[str, ImportBinding] = field(default_factory=dict)
    module_dotted_bindings: dict[str, ImportBinding] = field(default_factory=dict)
    scoped_bindings: dict[str, dict[str, ImportBinding]] = field(default_factory=dict)
    scoped_dotted_bindings: dict[str, dict[str, ImportBinding]] = field(default_factory=dict)
    wildcard_imports: list[tuple[str, CodeLocation]] = field(default_factory=list)
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)

    def lookup(self, name: str, scope: str | None = None) -> ImportBinding | None:
        """Look up a local symbol or imported module name in function scope, then module scope."""
        if scope is not None:
            scoped = self.scoped_bindings.get(scope, {})
            if name in scoped:
                return scoped[name]
        return self.module_bindings.get(name)

    def lookup_dotted(self, dotted_name: str, scope: str | None = None) -> tuple[ImportBinding, str] | None:
        """Longest-prefix match for expressions like ``urllib.request.urlopen``.

        Returns `(binding, remainder_attribute_path)` where `remainder_attribute_path`
        may be empty if the expression matches the binding target directly.
        """
        parts = dotted_name.split(".")
        for end in range(len(parts), 0, -1):
            prefix = ".".join(parts[:end])
            remainder = ".".join(parts[end:])
            if scope is not None:
                if prefix in self.scoped_dotted_bindings.get(scope, {}):
                    return self.scoped_dotted_bindings[scope][prefix], remainder
                if prefix in self.scoped_bindings.get(scope, {}):
                    return self.scoped_bindings[scope][prefix], remainder
            if prefix in self.module_dotted_bindings:
                return self.module_dotted_bindings[prefix], remainder
            if prefix in self.module_bindings:
                return self.module_bindings[prefix], remainder
        return None


def extract_import_table(
    parsed: ParsedPythonModule,
    module_symbols: ModuleSymbols | None = None,
) -> ImportTable:
    """Extract module-level and function-local imports from a parsed module."""
    table = ImportTable(module_name=parsed.file.module_name)
    if parsed.tree is None:
        return table

    rel_path = parsed.file.relative_path
    package_parts = parsed.file.package_parts

    def make_location(node: ast.AST) -> CodeLocation:
        return CodeLocation(
            file=rel_path,
            line=max(1, getattr(node, "lineno", 1)),
            column=max(0, getattr(node, "col_offset", 0)),
            end_line=getattr(node, "end_lineno", None),
        )

    def record_import_stmt(stmt: ast.stmt, scope: str | None) -> None:
        bindings = (
            table.module_bindings
            if scope is None
            else table.scoped_bindings.setdefault(scope, {})
        )
        dotted_bindings = (
            table.module_dotted_bindings
            if scope is None
            else table.scoped_dotted_bindings.setdefault(scope, {})
        )
        loc = make_location(stmt)

        if isinstance(stmt, ast.Import):
            raw = ast.unparse(stmt)
            for alias in stmt.names:
                full_mod = alias.name
                if alias.asname:
                    binding = ImportBinding(
                        local_name=alias.asname,
                        target_module=full_mod,
                        target_symbol=None,
                        is_relative=False,
                        level=0,
                        location=loc,
                        raw_statement=raw,
                    )
                    bindings[alias.asname] = binding
                    dotted_bindings[alias.asname] = binding
                else:
                    top_name = full_mod.split(".", 1)[0]
                    top_binding = ImportBinding(
                        local_name=top_name,
                        target_module=top_name,
                        target_symbol=None,
                        is_relative=False,
                        level=0,
                        location=loc,
                        raw_statement=raw,
                    )
                    bindings[top_name] = top_binding
                    dotted_binding = ImportBinding(
                        local_name=full_mod,
                        target_module=full_mod,
                        target_symbol=None,
                        is_relative=False,
                        level=0,
                        location=loc,
                        raw_statement=raw,
                    )
                    dotted_bindings[full_mod] = dotted_binding
            return

        if isinstance(stmt, ast.ImportFrom):
            raw = ast.unparse(stmt)
            level = stmt.level or 0
            if level > 0:
                pop_count = level - 1
                if pop_count > len(package_parts):
                    table.diagnostics.append(
                        AnalysisDiagnostic(
                            code="RELATIVE_IMPORT_BEYOND_TOP_LEVEL",
                            severity="warning",
                            message=(
                                f"Relative import '{raw}' exceeds package depth in "
                                f"module '{parsed.file.module_name}'."
                            ),
                            location=loc,
                            construct_kind="ImportFrom",
                            affected_scope=scope or parsed.file.module_name,
                        )
                    )
                    return
                base_parts = package_parts[: len(package_parts) - pop_count]
                if stmt.module:
                    target_module = ".".join((*base_parts, stmt.module))
                else:
                    target_module = ".".join(base_parts)
                if not target_module:
                    table.diagnostics.append(
                        AnalysisDiagnostic(
                            code="UNRESOLVED_RELATIVE_IMPORT",
                            severity="warning",
                            message=f"Could not resolve target module for '{raw}'.",
                            location=loc,
                            construct_kind="ImportFrom",
                            affected_scope=scope or parsed.file.module_name,
                        )
                    )
                    return
            else:
                target_module = stmt.module or ""

            for alias in stmt.names:
                if alias.name == "*":
                    table.wildcard_imports.append((target_module, loc))
                    table.diagnostics.append(
                        AnalysisDiagnostic(
                            code="WILDCARD_IMPORT",
                            severity="warning",
                            message=(
                                f"Wildcard import 'from {target_module} import *' "
                                "obscures statically identifiable symbol bindings."
                            ),
                            location=loc,
                            construct_kind="ImportFrom(*)",
                            affected_scope=scope or parsed.file.module_name,
                        )
                    )
                    continue
                local_name = alias.asname or alias.name
                binding = ImportBinding(
                    local_name=local_name,
                    target_module=target_module,
                    target_symbol=alias.name,
                    is_relative=level > 0,
                    level=level,
                    location=loc,
                    raw_statement=raw,
                )
                bindings[local_name] = binding
                dotted_bindings[local_name] = binding

    def scan_stmts(stmts: list[ast.stmt], scope: str | None) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                record_import_stmt(stmt, scope)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Function/class bodies are traversed via module_symbols below
                continue
            else:
                for body in _iter_control_flow_bodies(stmt):
                    scan_stmts(body, scope)

    scan_stmts(parsed.tree.body, None)

    if module_symbols is not None:
        for fn_qual, fn_sym in module_symbols.functions.items():
            scan_stmts(fn_sym.body_stmts, fn_qual)

    return table
