"""Static Python symbol extraction (functions, methods, classes, types, aliases)."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Literal

from packages.core.analysis.python.discovery import DiscoveredPythonFile
from packages.core.analysis.python.parser import ParsedPythonModule
from packages.core.models.reachability import CodeLocation


@dataclass(frozen=True)
class DecoratorInfo:
    """Extracted decorator metadata for a function, method, or class."""

    raw_name: str
    base_name: str | None
    attr_name: str | None
    args_preview: list[str]
    location: CodeLocation


@dataclass
class FunctionSymbol:
    """Extracted static representation of a Python function, method, or main block."""

    qualified_name: str
    simple_name: str
    module_name: str
    node_type: Literal["function", "async_function", "method", "main_block"]
    location: CodeLocation
    ast_node: ast.AST
    body_stmts: list[ast.stmt] = field(default_factory=list)
    decorators: list[DecoratorInfo] = field(default_factory=list)
    parent_class: str | None = None
    is_staticmethod: bool = False
    is_classmethod: bool = False
    param_annotations: dict[str, str] = field(default_factory=dict)
    local_var_types: dict[str, str] = field(default_factory=dict)
    local_aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class ClassSymbol:
    """Extracted static representation of a Python class definition."""

    qualified_name: str
    simple_name: str
    module_name: str
    location: CodeLocation
    bases: list[str] = field(default_factory=list)
    decorators: list[DecoratorInfo] = field(default_factory=list)
    methods: dict[str, str] = field(default_factory=dict)
    class_var_types: dict[str, str] = field(default_factory=dict)


@dataclass
class ModuleSymbols:
    """All symbols extracted statically from a single parsed Python module."""

    file: DiscoveredPythonFile
    module_name: str
    functions: dict[str, FunctionSymbol] = field(default_factory=dict)
    classes: dict[str, ClassSymbol] = field(default_factory=dict)
    top_level_symbols: dict[str, str] = field(default_factory=dict)
    module_var_types: dict[str, str] = field(default_factory=dict)
    module_aliases: dict[str, str] = field(default_factory=dict)


def extract_dotted_name(node: ast.AST) -> str | None:
    """Return dotted name for pure `Name` / `Attribute` chains, else `None`."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = extract_dotted_name(node.value)
        if prefix is not None:
            return f"{prefix}.{node.attr}"
    return None


def _extract_annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, (ast.Name, ast.Attribute)):
        return extract_dotted_name(node)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip() or None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _extract_annotation_name(node.left)
        right = _extract_annotation_name(node.right)
        if left and left != "None":
            return left
        if right and right != "None":
            return right
    if isinstance(node, ast.Subscript):
        base = extract_dotted_name(node.value)
        if base in {"Optional", "typing.Optional", "Annotated", "typing.Annotated"}:
            if isinstance(node.slice, ast.Tuple) and node.slice.elts:
                return _extract_annotation_name(node.slice.elts[0])
            return _extract_annotation_name(node.slice)
        return base
    return None


def _extract_decorator(decorator: ast.expr, rel_path: str) -> DecoratorInfo:
    if isinstance(decorator, ast.Call):
        raw_expr = decorator.func
        args_preview = [
            arg.value
            for arg in decorator.args[:3]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        ]
    else:
        raw_expr = decorator
        args_preview = []

    raw_name = extract_dotted_name(raw_expr) or ast.unparse(raw_expr)
    parts = raw_name.split(".")
    base_name = parts[0] if parts else None
    attr_name = parts[-1] if len(parts) > 1 else None
    return DecoratorInfo(
        raw_name=raw_name,
        base_name=base_name,
        attr_name=attr_name,
        args_preview=args_preview,
        location=CodeLocation(
            file=rel_path,
            line=max(1, getattr(decorator, "lineno", 1)),
            column=max(0, getattr(decorator, "col_offset", 0)),
            end_line=getattr(decorator, "end_lineno", None),
        ),
    )


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    ) or (
        isinstance(right, ast.Name)
        and right.id == "__name__"
        and isinstance(left, ast.Constant)
        and left.value == "__main__"
    )


def _location_for_node(node: ast.AST, rel_path: str) -> CodeLocation:
    return CodeLocation(
        file=rel_path,
        line=max(1, getattr(node, "lineno", 1)),
        column=max(0, getattr(node, "col_offset", 0)),
        end_line=getattr(node, "end_lineno", None),
    )


def extract_module_symbols(parsed: ParsedPythonModule) -> ModuleSymbols:
    """Extract classes, functions, methods, nested functions, and main blocks."""
    module_name = parsed.file.module_name
    result = ModuleSymbols(file=parsed.file, module_name=module_name)
    if parsed.tree is None:
        return result

    rel_path = parsed.file.relative_path
    main_stmts: list[ast.stmt] = []
    main_first_node: ast.If | None = None

    def record_assignment(
        stmt: ast.stmt,
        *,
        var_types: dict[str, str],
        aliases: dict[str, str],
        scope_prefix: str,
    ) -> None:
        if isinstance(stmt, ast.Assign):
            value = stmt.value
            for target in stmt.targets:
                if not isinstance(target, ast.Name):
                    continue
                if isinstance(value, ast.Call):
                    callee = extract_dotted_name(value.func)
                    if callee:
                        var_types[target.id] = callee
                elif isinstance(value, (ast.Name, ast.Attribute)):
                    ref = extract_dotted_name(value)
                    if ref:
                        aliases[target.id] = ref
                        if ref in var_types and target.id not in var_types:
                            var_types[target.id] = var_types[ref]
                        elif scope_prefix and ref in aliases:
                            aliases[target.id] = aliases[ref]
                elif isinstance(value, ast.List):
                    var_types[target.id] = "builtins.list"
                elif isinstance(value, ast.Dict):
                    var_types[target.id] = "builtins.dict"
                elif isinstance(value, ast.Set):
                    var_types[target.id] = "builtins.set"
                elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                    var_types[target.id] = "builtins.str"
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            ann = _extract_annotation_name(stmt.annotation)
            if ann:
                var_types[stmt.target.id] = ann
            elif isinstance(stmt.value, ast.Call):
                callee = extract_dotted_name(stmt.value.func)
                if callee:
                    var_types[stmt.target.id] = callee

    def walk_function(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        qual_prefix: str,
        parent_class: str | None,
        is_nested_in_func: bool,
    ) -> FunctionSymbol:
        if is_nested_in_func:
            qual_name = f"{qual_prefix}.<locals>.{fn_node.name}"
        else:
            qual_name = f"{qual_prefix}.{fn_node.name}"

        decorators = [_extract_decorator(dec, rel_path) for dec in fn_node.decorator_list]
        decorator_names = {d.raw_name for d in decorators}
        is_staticmethod = "staticmethod" in decorator_names
        is_classmethod = "classmethod" in decorator_names

        if parent_class is not None:
            node_type: Literal["function", "async_function", "method", "main_block"] = "method"
        elif isinstance(fn_node, ast.AsyncFunctionDef):
            node_type = "async_function"
        else:
            node_type = "function"

        param_annotations: dict[str, str] = {}
        all_args = (
            list(fn_node.args.posonlyargs)
            + list(fn_node.args.args)
            + list(fn_node.args.kwonlyargs)
        )
        if fn_node.args.vararg is not None:
            all_args.append(fn_node.args.vararg)
        if fn_node.args.kwarg is not None:
            all_args.append(fn_node.args.kwarg)
        for arg in all_args:
            ann = _extract_annotation_name(arg.annotation)
            if ann:
                param_annotations[arg.arg] = ann

        local_var_types: dict[str, str] = {}
        local_aliases: dict[str, str] = {}

        fn_sym = FunctionSymbol(
            qualified_name=qual_name,
            simple_name=fn_node.name,
            module_name=module_name,
            node_type=node_type,
            location=_location_for_node(fn_node, rel_path),
            ast_node=fn_node,
            body_stmts=list(fn_node.body),
            decorators=decorators,
            parent_class=parent_class,
            is_staticmethod=is_staticmethod,
            is_classmethod=is_classmethod,
            param_annotations=param_annotations,
            local_var_types=local_var_types,
            local_aliases=local_aliases,
        )
        result.functions[qual_name] = fn_sym

        scan_nested_stmts(
            fn_node.body,
            qual_prefix=qual_name,
            in_function=True,
            enclosing_var_types=local_var_types,
            enclosing_aliases=local_aliases,
        )
        return fn_sym

    def walk_class(cls_node: ast.ClassDef, *, qual_prefix: str) -> ClassSymbol:
        qual_name = f"{qual_prefix}.{cls_node.name}"
        bases = [
            extract_dotted_name(base) or ast.unparse(base) for base in cls_node.bases
        ]
        decorators = [_extract_decorator(dec, rel_path) for dec in cls_node.decorator_list]
        cls_sym = ClassSymbol(
            qualified_name=qual_name,
            simple_name=cls_node.name,
            module_name=module_name,
            location=_location_for_node(cls_node, rel_path),
            bases=bases,
            decorators=decorators,
        )
        result.classes[qual_name] = cls_sym

        for stmt in cls_node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_sym = walk_function(
                    stmt,
                    qual_prefix=qual_name,
                    parent_class=qual_name,
                    is_nested_in_func=False,
                )
                cls_sym.methods[stmt.name] = method_sym.qualified_name
            elif isinstance(stmt, ast.ClassDef):
                walk_class(stmt, qual_prefix=qual_name)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                record_assignment(
                    stmt,
                    var_types=cls_sym.class_var_types,
                    aliases={},
                    scope_prefix=qual_name,
                )
        return cls_sym

    def scan_nested_stmts(
        stmts: list[ast.stmt],
        *,
        qual_prefix: str,
        in_function: bool,
        enclosing_var_types: dict[str, str],
        enclosing_aliases: dict[str, str],
    ) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nested = walk_function(
                    stmt,
                    qual_prefix=qual_prefix,
                    parent_class=None,
                    is_nested_in_func=in_function,
                )
                enclosing_aliases[stmt.name] = nested.qualified_name
            elif isinstance(stmt, ast.ClassDef):
                cls_sym = walk_class(stmt, qual_prefix=qual_prefix)
                enclosing_aliases[stmt.name] = cls_sym.qualified_name
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                record_assignment(
                    stmt,
                    var_types=enclosing_var_types,
                    aliases=enclosing_aliases,
                    scope_prefix=qual_prefix,
                )
            else:
                for child_body in _iter_control_flow_bodies(stmt):
                    scan_nested_stmts(
                        child_body,
                        qual_prefix=qual_prefix,
                        in_function=in_function,
                        enclosing_var_types=enclosing_var_types,
                        enclosing_aliases=enclosing_aliases,
                    )

    for stmt in parsed.tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_sym = walk_function(
                stmt,
                qual_prefix=module_name,
                parent_class=None,
                is_nested_in_func=False,
            )
            result.top_level_symbols[stmt.name] = fn_sym.qualified_name
        elif isinstance(stmt, ast.ClassDef):
            cls_sym = walk_class(stmt, qual_prefix=module_name)
            result.top_level_symbols[stmt.name] = cls_sym.qualified_name
        elif isinstance(stmt, ast.If) and _is_main_guard(stmt):
            if main_first_node is None:
                main_first_node = stmt
            main_stmts.extend(stmt.body)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            record_assignment(
                stmt,
                var_types=result.module_var_types,
                aliases=result.module_aliases,
                scope_prefix=module_name,
            )

    if main_first_node is not None and main_stmts:
        main_qual = f"{module_name}.__main__"
        main_var_types: dict[str, str] = {}
        main_aliases: dict[str, str] = {}
        main_sym = FunctionSymbol(
            qualified_name=main_qual,
            simple_name="__main__",
            module_name=module_name,
            node_type="main_block",
            location=_location_for_node(main_first_node, rel_path),
            ast_node=main_first_node,
            body_stmts=main_stmts,
            local_var_types=main_var_types,
            local_aliases=main_aliases,
        )
        result.functions[main_qual] = main_sym
        result.top_level_symbols["__main__"] = main_qual
        scan_nested_stmts(
            main_stmts,
            qual_prefix=main_qual,
            in_function=True,
            enclosing_var_types=main_var_types,
            enclosing_aliases=main_aliases,
        )

    return result


def _iter_control_flow_bodies(stmt: ast.stmt) -> list[list[ast.stmt]]:
    bodies: list[list[ast.stmt]] = []
    for attr in ("body", "orelse", "finalbody"):
        block = getattr(stmt, attr, None)
        if isinstance(block, list) and block:
            bodies.append(block)
    handlers = getattr(stmt, "handlers", None)
    if isinstance(handlers, list):
        for handler in handlers:
            if isinstance(handler, ast.ExceptHandler) and handler.body:
                bodies.append(handler.body)
    cases = getattr(stmt, "cases", None)
    if isinstance(cases, list):
        for case in cases:
            case_body = getattr(case, "body", None)
            if isinstance(case_body, list) and case_body:
                bodies.append(case_body)
    return bodies
