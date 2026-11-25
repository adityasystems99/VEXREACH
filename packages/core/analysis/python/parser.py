"""Python AST parser wrapper with structured diagnostics."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from packages.core.analysis.python.discovery import DiscoveredPythonFile
from packages.core.models.reachability import AnalysisDiagnostic, CodeLocation


@dataclass
class ParsedPythonModule:
    """Result of parsing a single discovered Python source file into an AST."""

    file: DiscoveredPythonFile
    source: str | None = None
    tree: ast.Module | None = None
    diagnostics: list[AnalysisDiagnostic] = field(default_factory=list)

    @property
    def parsed_successfully(self) -> bool:
        """Return whether an AST module was constructed."""
        return self.tree is not None


def parse_python_module(discovered_file: DiscoveredPythonFile) -> ParsedPythonModule:
    """Read and parse a Python file using standard-library ``ast`` without execution."""
    diagnostics: list[AnalysisDiagnostic] = []
    rel_path = discovered_file.relative_path

    try:
        source = discovered_file.absolute_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        diagnostics.append(
            AnalysisDiagnostic(
                code="UNICODE_DECODE_ERROR",
                severity="warning",
                message=f"Could not decode {rel_path} as UTF-8: {exc}",
                location=CodeLocation(file=rel_path, line=1),
                construct_kind="source_encoding",
                affected_scope=discovered_file.module_name,
            )
        )
        return ParsedPythonModule(file=discovered_file, diagnostics=diagnostics)
    except OSError as exc:
        diagnostics.append(
            AnalysisDiagnostic(
                code="FILE_READ_ERROR",
                severity="warning",
                message=f"Could not read {rel_path}: {exc}",
                location=CodeLocation(file=rel_path, line=1),
                construct_kind="filesystem",
                affected_scope=discovered_file.module_name,
            )
        )
        return ParsedPythonModule(file=discovered_file, diagnostics=diagnostics)

    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        diagnostics.append(
            AnalysisDiagnostic(
                code="SYNTAX_ERROR",
                severity="warning",
                message=f"Syntax error in {rel_path}: {exc.msg}",
                location=CodeLocation(
                    file=rel_path,
                    line=max(1, exc.lineno or 1),
                    column=max(0, (exc.offset or 1) - 1),
                ),
                construct_kind="python_ast_parse",
                affected_scope=discovered_file.module_name,
            )
        )
        return ParsedPythonModule(
            file=discovered_file, source=source, diagnostics=diagnostics
        )
    except RecursionError:
        diagnostics.append(
            AnalysisDiagnostic(
                code="AST_RECURSION_ERROR",
                severity="warning",
                message=f"AST nesting depth exceeded recursion limit in {rel_path}",
                location=CodeLocation(file=rel_path, line=1),
                construct_kind="python_ast_parse",
                affected_scope=discovered_file.module_name,
            )
        )
        return ParsedPythonModule(
            file=discovered_file, source=source, diagnostics=diagnostics
        )

    return ParsedPythonModule(
        file=discovered_file,
        source=source,
        tree=tree,
        diagnostics=diagnostics,
    )
