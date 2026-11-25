"""Conservative static Python call target resolver and dynamic-construct detector."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from packages.core.analysis.python.imports import ImportTable
from packages.core.analysis.python.symbols import (
    ClassSymbol,
    FunctionSymbol,
    ModuleSymbols,
    extract_dotted_name,
)
from packages.core.models.reachability import (
    AnalysisDiagnostic,
    CodeLocation,
    UnresolvedCall,
)

BUILTIN_TYPES: frozenset[str] = frozenset(
    {
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "bytearray",
        "list",
        "dict",
        "set",
        "frozenset",
        "tuple",
        "object",
        "type",
        "builtins.str",
        "builtins.int",
        "builtins.float",
        "builtins.bool",
        "builtins.bytes",
        "builtins.list",
        "builtins.dict",
        "builtins.set",
        "builtins.tuple",
    }
)

SAFE_BUILTIN_FUNCTIONS: frozenset[str] = frozenset(
    {
        "abs",
        "all",
        "any",
        "ascii",
        "bin",
        "bool",
        "bytearray",
        "bytes",
        "callable",
        "chr",
        "classmethod",
        "complex",
        "dict",
        "dir",
        "divmod",
        "enumerate",
        "filter",
        "float",
        "format",
        "frozenset",
        "hasattr",
        "hash",
        "hex",
        "id",
        "int",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "list",
        "map",
        "max",
        "min",
        "next",
        "object",
        "oct",
        "open",
        "ord",
        "pow",
        "print",
        "property",
        "range",
        "repr",
        "reversed",
        "round",
        "set",
        "slice",
        "sorted",
        "staticmethod",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
        "zip",
        "Exception",
        "BaseException",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "RuntimeError",
        "OSError",
        "FileNotFoundError",
        "NotImplementedError",
        "AssertionError",
        "AttributeError",
    }
)

DYNAMIC_BUILTIN_CALLS: dict[str, tuple[str, str, str]] = {
    "getattr": (
        "dynamic_attribute_lookup",
        "DYNAMIC_ATTRIBUTE_LOOKUP",
        "Dynamic getattr() lookup prevents static resolution of target attribute.",
    ),
    "setattr": (
        "dynamic_attribute_lookup",
        "DYNAMIC_ATTRIBUTE_MUTATION",
        "Dynamic setattr() mutation may alter attributes or dispatch targets dynamically.",
    ),
    "delattr": (
        "dynamic_attribute_lookup",
        "DYNAMIC_ATTRIBUTE_MUTATION",
        "Dynamic delattr() call cannot be modeled accurately in static call graph.",
    ),
    "eval": (
        "dynamic_code_execution",
        "DYNAMIC_CODE_EXECUTION",
        "Dynamic eval() executes runtime code outside static AST call graph.",
    ),
    "exec": (
        "dynamic_code_execution",
        "DYNAMIC_CODE_EXECUTION",
        "Dynamic exec() executes runtime code outside static AST call graph.",
    ),
    "compile": (
        "dynamic_code_execution",
        "DYNAMIC_CODE_EXECUTION",
        "Dynamic compile() constructs executable code dynamically.",
    ),
    "__import__": (
        "dynamic_import",
        "DYNAMIC_IMPORT",
        "Dynamic __import__() call hides imported target from static import resolution.",
    ),
    "globals": (
        "reflection_namespace_lookup",
        "REFLECTION_CALL",
        "Reflective globals() call enables dynamic symbol resolution.",
    ),
    "locals": (
        "reflection_namespace_lookup",
        "REFLECTION_CALL",
        "Reflective locals() call enables dynamic symbol resolution.",
    ),
}

DYNAMIC_DOTTED_IMPORTS: frozenset[str] = frozenset(
    {"importlib.import_module", "importlib.__import__"}
)


@dataclass(frozen=True)
class ResolvedCallRecord:
    """Resolved directed call edge candidate from a caller function to a callee."""

    caller: str
    callee: str
    resolution_method: str
    is_external: bool
    location: CodeLocation


@dataclass
class RepositoryModuleIndex:
    """Repository-wide index of extracted Python modules, symbols, and imports."""

    modules: dict[str, ModuleSymbols] = field(default_factory=dict)
    imports: dict[str, ImportTable] = field(default_factory=dict)
    functions: dict[str, FunctionSymbol] = field(default_factory=dict)
    classes: dict[str, ClassSymbol] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        module_symbols_list: list[ModuleSymbols],
        import_tables: list[ImportTable],
    ) -> "RepositoryModuleIndex":
        index = cls()
        for mod_sym in module_symbols_list:
            index.modules[mod_sym.module_name] = mod_sym
            index.functions.update(mod_sym.functions)
            index.classes.update(mod_sym.classes)
        for table in import_tables:
            index.imports[table.module_name] = table
        return index

    def resolve_method_on_class(
        self, class_qual: str, method_name: str, _visited: set[str] | None = None
    ) -> str | None:
        """Resolve a method qualified name on a class or its resolved base classes."""
        visited = _visited if _visited is not None else set()
        if class_qual in visited:
            return None
        visited.add(class_qual)

        cls_sym = self.classes.get(class_qual)
        if cls_sym is None:
            return None
        if method_name in cls_sym.methods:
            return cls_sym.methods[method_name]

        mod_sym = self.modules.get(cls_sym.module_name)
        imp_table = self.imports.get(cls_sym.module_name)
        for base_name in cls_sym.bases:
            resolved_base = self._resolve_symbol_in_module(
                base_name, mod_sym, imp_table
            )
            if resolved_base and resolved_base in self.classes:
                found = self.resolve_method_on_class(
                    resolved_base, method_name, visited
                )
                if found is not None:
                    return found
        return None

    def _resolve_symbol_in_module(
        self,
        name: str,
        mod_sym: ModuleSymbols | None,
        imp_table: ImportTable | None,
    ) -> str | None:
        if mod_sym and name in mod_sym.classes:
            return name
        if mod_sym and name in mod_sym.top_level_symbols:
            return mod_sym.top_level_symbols[name]
        if imp_table:
            hit = imp_table.lookup_dotted(name)
            if hit is not None:
                binding, remainder = hit
                base = binding.qualified_target
                return f"{base}.{remainder}" if remainder else base
        return None


@dataclass
class ResolutionOutcome:
    """Output of static call resolution across all indexed Python modules."""

    resolved_calls: list[ResolvedCallRecord] = field(default_factory=list)
    unresolved_calls: list[UnresolvedCall] = field(default_factory=list)
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)


class PythonCallResolver:
    """Resolves `ast.Call` nodes conservatively within supported Python AST semantics."""

    def resolve_repository(self, index: RepositoryModuleIndex) -> ResolutionOutcome:
        """Resolve all calls across all functions/methods/main blocks in ``index``."""
        outcome = ResolutionOutcome()
        for mod_name in sorted(index.modules):
            mod_sym = index.modules[mod_name]
            imp_table = index.imports.get(mod_name, ImportTable(module_name=mod_name))
            for fn_qual in sorted(mod_sym.functions):
                fn_sym = mod_sym.functions[fn_qual]
                self._resolve_function(
                    fn_sym=fn_sym,
                    mod_sym=mod_sym,
                    imp_table=imp_table,
                    index=index,
                    outcome=outcome,
                )
        return outcome

    def _resolve_function(
        self,
        *,
        fn_sym: FunctionSymbol,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        index: RepositoryModuleIndex,
        outcome: ResolutionOutcome,
    ) -> None:
        rel_path = mod_sym.file.relative_path
        calls = self._collect_calls_in_stmts(fn_sym.body_stmts)

        for call_node in calls:
            loc = CodeLocation(
                file=rel_path,
                line=max(1, getattr(call_node, "lineno", fn_sym.location.line)),
                column=max(0, getattr(call_node, "col_offset", 0)),
                end_line=getattr(call_node, "end_lineno", None),
            )
            self._resolve_single_call(
                call_node=call_node,
                loc=loc,
                fn_sym=fn_sym,
                mod_sym=mod_sym,
                imp_table=imp_table,
                index=index,
                outcome=outcome,
            )

    def _resolve_single_call(
        self,
        *,
        call_node: ast.Call,
        loc: CodeLocation,
        fn_sym: FunctionSymbol,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        index: RepositoryModuleIndex,
        outcome: ResolutionOutcome,
    ) -> None:
        func = call_node.func
        raw_expr = ast.unparse(call_node)
        scope = fn_sym.qualified_name

        if isinstance(func, ast.Name):
            name = func.id
            if (
                name in DYNAMIC_BUILTIN_CALLS
                and name not in fn_sym.local_aliases
                and name not in mod_sym.top_level_symbols
                and imp_table.lookup(name, scope=scope) is None
            ):
                category, diag_code, reason = DYNAMIC_BUILTIN_CALLS[name]
                outcome.unresolved_calls.append(
                    UnresolvedCall(
                        caller=scope,
                        raw_expression=raw_expr,
                        category=category,
                        reason=reason,
                        location=loc,
                    )
                )
                outcome.diagnostics.append(
                    AnalysisDiagnostic(
                        code=diag_code,
                        severity="warning",
                        message=reason,
                        location=loc,
                        construct_kind=name,
                        affected_scope=scope,
                    )
                )
                return

            resolved = self._resolve_simple_name(
                name=name,
                fn_sym=fn_sym,
                mod_sym=mod_sym,
                imp_table=imp_table,
                index=index,
            )
            if resolved is not None:
                target, method, is_external = resolved
                outcome.resolved_calls.append(
                    ResolvedCallRecord(
                        caller=scope,
                        callee=target,
                        resolution_method=method,
                        is_external=is_external,
                        location=loc,
                    )
                )
                return

            if name in SAFE_BUILTIN_FUNCTIONS:
                return

            reason = f"Could not statically resolve callable identifier '{name}' in scope '{scope}'."
            if imp_table.wildcard_imports:
                reason += " Module contains wildcard import(s) that obscure bindings."
            outcome.unresolved_calls.append(
                UnresolvedCall(
                    caller=scope,
                    raw_expression=raw_expr,
                    category="indirect_callback_call",
                    reason=reason,
                    location=loc,
                )
            )
            return

        if isinstance(func, ast.Attribute):
            dotted = extract_dotted_name(func)
            if dotted is None:
                outcome.unresolved_calls.append(
                    UnresolvedCall(
                        caller=scope,
                        raw_expression=raw_expr,
                        category="chained_dynamic_call",
                        reason="Receiver expression cannot be reduced to a static dotted name.",
                        location=loc,
                    )
                )
                return

            # Check dynamic dotted imports such as importlib.import_module(...)
            imp_hit = imp_table.lookup_dotted(dotted, scope=scope)
            if imp_hit is not None:
                binding, remainder = imp_hit
                full_target = (
                    f"{binding.qualified_target}.{remainder}"
                    if remainder
                    else binding.qualified_target
                )
                if full_target in DYNAMIC_DOTTED_IMPORTS:
                    reason = f"Dynamic import '{full_target}' cannot be resolved statically."
                    outcome.unresolved_calls.append(
                        UnresolvedCall(
                            caller=scope,
                            raw_expression=raw_expr,
                            category="dynamic_import",
                            reason=reason,
                            location=loc,
                        )
                    )
                    outcome.diagnostics.append(
                        AnalysisDiagnostic(
                            code="DYNAMIC_IMPORT",
                            severity="warning",
                            message=reason,
                            location=loc,
                            construct_kind=full_target,
                            affected_scope=scope,
                        )
                    )
                    return

            resolved_attr = self._resolve_attribute_call(
                dotted=dotted,
                fn_sym=fn_sym,
                mod_sym=mod_sym,
                imp_table=imp_table,
                index=index,
            )
            if resolved_attr is not None:
                target, method, is_external = resolved_attr
                if target.startswith("builtins."):
                    return
                outcome.resolved_calls.append(
                    ResolvedCallRecord(
                        caller=scope,
                        callee=target,
                        resolution_method=method,
                        is_external=is_external,
                        location=loc,
                    )
                )
                return

            outcome.unresolved_calls.append(
                UnresolvedCall(
                    caller=scope,
                    raw_expression=raw_expr,
                    category="ambiguous_receiver",
                    reason=(
                        f"Receiver type or binding for '{dotted}' could not be "
                        f"determined statically in scope '{scope}'."
                    ),
                    location=loc,
                )
            )
            return

        if isinstance(func, ast.Subscript):
            outcome.unresolved_calls.append(
                UnresolvedCall(
                    caller=scope,
                    raw_expression=raw_expr,
                    category="dynamic_subscript_call",
                    reason="Dynamic subscript dispatch (e.g., table[key]()) is outside supported static subset.",
                    location=loc,
                )
            )
            return

        if isinstance(func, ast.Call):
            outcome.unresolved_calls.append(
                UnresolvedCall(
                    caller=scope,
                    raw_expression=raw_expr,
                    category="chained_dynamic_call",
                    reason="Call through returned callable expression is outside supported static subset.",
                    location=loc,
                )
            )
            return

        category = (
            "inline_lambda_call"
            if isinstance(func, ast.Lambda)
            else "unsupported_call_expression"
        )
        outcome.unresolved_calls.append(
            UnresolvedCall(
                caller=scope,
                raw_expression=raw_expr,
                category=category,
                reason=f"Call expression AST type '{type(func).__name__}' is unsupported statically.",
                location=loc,
            )
        )

    def _resolve_simple_name(
        self,
        *,
        name: str,
        fn_sym: FunctionSymbol,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        index: RepositoryModuleIndex,
    ) -> tuple[str, str, bool] | None:
        scope = fn_sym.qualified_name

        # 1. Local nested function or local alias chain
        if name in fn_sym.local_aliases:
            target = self._follow_alias_chain(
                name, fn_sym.local_aliases, mod_sym, imp_table, scope
            )
            if target is not None:
                return self._finalize_internal_or_external(
                    target, "local_alias_or_nested_call", index
                )

        # 2. Same-module function/class definition
        if name in mod_sym.top_level_symbols:
            qual = mod_sym.top_level_symbols[name]
            return self._finalize_internal_or_external(qual, "same_module_call", index)

        # 3. Module-level alias (e.g. handler = actual_fn)
        if name in mod_sym.module_aliases:
            target = self._follow_alias_chain(
                name, mod_sym.module_aliases, mod_sym, imp_table, None
            )
            if target is not None:
                return self._finalize_internal_or_external(
                    target, "module_alias_call", index
                )

        # 4. Imported symbol
        binding = imp_table.lookup(name, scope=scope)
        if binding is not None:
            method = (
                "aliased_import_call"
                if binding.target_symbol and binding.target_symbol != name
                else "direct_import_call"
            )
            return self._finalize_internal_or_external(
                binding.qualified_target, method, index
            )

        return None

    def _resolve_attribute_call(
        self,
        *,
        dotted: str,
        fn_sym: FunctionSymbol,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        index: RepositoryModuleIndex,
    ) -> tuple[str, str, bool] | None:
        parts = dotted.split(".")
        receiver = parts[0]
        scope = fn_sym.qualified_name

        # 1. self.method() / cls.method() inside a class method
        if (
            receiver in {"self", "cls"}
            and fn_sym.parent_class is not None
            and len(parts) == 2
        ):
            method_name = parts[1]
            resolved_method = index.resolve_method_on_class(
                fn_sym.parent_class, method_name
            )
            if resolved_method is not None:
                return resolved_method, f"{receiver}_method_call", False

        # 2. Local variable / parameter annotation / module variable type inference
        inferred_type = (
            fn_sym.local_var_types.get(receiver)
            or fn_sym.param_annotations.get(receiver)
            or mod_sym.module_var_types.get(receiver)
        )
        if inferred_type is not None and len(parts) >= 2:
            if inferred_type in BUILTIN_TYPES:
                return f"builtins.{inferred_type.removeprefix('builtins.')}.{parts[1]}", "builtin_type_call", True
            resolved_type = self._resolve_type_target(
                inferred_type, mod_sym=mod_sym, imp_table=imp_table, scope=scope
            )
            if resolved_type is not None:
                if resolved_type in index.classes and len(parts) == 2:
                    method_qual = index.resolve_method_on_class(resolved_type, parts[1])
                    if method_qual is not None:
                        return method_qual, "typed_instance_method_call", False
                ext_target = ".".join([resolved_type, *parts[1:]])
                is_external = ext_target not in index.functions and resolved_type not in index.classes
                return ext_target, "typed_receiver_call", is_external

        # 3. Same-module class method / staticmethod / classmethod (MyClass.build())
        if receiver in mod_sym.top_level_symbols and len(parts) == 2:
            cls_qual = mod_sym.top_level_symbols[receiver]
            if cls_qual in index.classes:
                method_qual = index.resolve_method_on_class(cls_qual, parts[1])
                if method_qual is not None:
                    return method_qual, "class_attribute_call", False

        # 4. Imported module or symbol attribute chain (import pkg.mod as m; m.func())
        imp_hit = imp_table.lookup_dotted(dotted, scope=scope)
        if imp_hit is not None:
            binding, remainder = imp_hit
            target = (
                f"{binding.qualified_target}.{remainder}"
                if remainder
                else binding.qualified_target
            )
            method = (
                "aliased_module_attribute_call"
                if binding.local_name != binding.target_module
                and binding.target_symbol is None
                else "module_attribute_call"
            )
            return self._finalize_internal_or_external(target, method, index)

        return None

    def _resolve_type_target(
        self,
        type_expr: str,
        *,
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        scope: str,
    ) -> str | None:
        if type_expr in mod_sym.top_level_symbols:
            return mod_sym.top_level_symbols[type_expr]
        imp_hit = imp_table.lookup_dotted(type_expr, scope=scope)
        if imp_hit is not None:
            binding, remainder = imp_hit
            return (
                f"{binding.qualified_target}.{remainder}"
                if remainder
                else binding.qualified_target
            )
        return None

    def _follow_alias_chain(
        self,
        name: str,
        alias_map: dict[str, str],
        mod_sym: ModuleSymbols,
        imp_table: ImportTable,
        scope: str | None,
    ) -> str | None:
        current = name
        seen: set[str] = set()
        while current in alias_map and current not in seen:
            seen.add(current)
            nxt = alias_map[current]
            if nxt in mod_sym.functions or nxt in mod_sym.classes:
                return nxt
            if nxt in mod_sym.top_level_symbols:
                return mod_sym.top_level_symbols[nxt]
            imp_hit = imp_table.lookup_dotted(nxt, scope=scope)
            if imp_hit is not None:
                binding, remainder = imp_hit
                return (
                    f"{binding.qualified_target}.{remainder}"
                    if remainder
                    else binding.qualified_target
                )
            current = nxt
        return current if current != name else None

    @staticmethod
    def _finalize_internal_or_external(
        target: str,
        resolution_method: str,
        index: RepositoryModuleIndex,
    ) -> tuple[str, str, bool]:
        if target in index.functions:
            return target, resolution_method, False
        if target in index.classes:
            init_qual = f"{target}.__init__"
            if init_qual in index.functions:
                return init_qual, f"{resolution_method}_init", False
            return target, resolution_method, False
        return target, resolution_method, True

    def _collect_calls_in_stmts(self, stmts: list[ast.stmt]) -> list[ast.Call]:
        collected: list[ast.Call] = []

        def visit(node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Only evaluate decorator expressions/default args? Keep body isolated to its own FunctionSymbol.
                return
            if isinstance(node, ast.Call):
                collected.append(node)
            for child in ast.iter_child_nodes(node):
                visit(child)

        for stmt in stmts:
            visit(stmt)
        return collected
