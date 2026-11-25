"""Unified diff parser and vulnerable-vs-fixed Python AST comparator."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from packages.core.analysis.python.discovery import derive_module_identity
from packages.core.models.ai_intelligence import (
    ModifiedSymbolDiff,
    ParsedPatchRecord,
    PatchFetchStatus,
)
from packages.core.utils.safe_path import PathTraversalError, safe_resolve_path

_HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+"
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?\s+@@(?P<context>.*)$"
)
_FUNC_OR_CLASS_LINE_RE = re.compile(
    r"^\s*(?P<kind>async\s+def|def|class)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)


@dataclass
class UnifiedDiffHunk:
    """Single diff hunk with old/new line spans and optional context header."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    context_header: str
    deleted_line_numbers: list[int] = field(default_factory=list)
    added_line_numbers: list[int] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    added_lines: list[str] = field(default_factory=list)


@dataclass
class UnifiedDiffFile:
    """Parsed unified diff entries for a single file."""

    old_path: str | None
    new_path: str | None
    hunks: list[UnifiedDiffHunk] = field(default_factory=list)

    @property
    def target_path(self) -> str:
        """Return canonical POSIX path prioritizing post-patch path cleanly."""
        raw = self.new_path if self.new_path and self.new_path != "/dev/null" else self.old_path
        cleaned = (raw or "unknown").replace("\\", "/").lstrip("/")
        if cleaned.startswith(("a/", "b/")):
            cleaned = cleaned[2:]
        return cleaned


def parse_unified_diff(diff_text: str) -> list[UnifiedDiffFile]:
    """Parse standard git/unified diff text into file hunks cleanly."""
    files: list[UnifiedDiffFile] = []
    current_file: UnifiedDiffFile | None = None
    current_hunk: UnifiedDiffHunk | None = None
    old_line = 0
    new_line = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            old_p = parts[2][2:] if len(parts) >= 4 and parts[2].startswith("a/") else None
            new_p = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else None
            current_file = UnifiedDiffFile(old_path=old_p, new_path=new_p)
            files.append(current_file)
            current_hunk = None
            continue

        if line.startswith("--- "):
            path_val = line[4:].strip().split("\t", 1)[0]
            if current_file is None or (current_file.old_path is not None and current_file.hunks):
                current_file = UnifiedDiffFile(old_path=path_val, new_path=None)
                files.append(current_file)
                current_hunk = None
            else:
                current_file.old_path = path_val
            continue

        if line.startswith("+++ "):
            path_val = line[4:].strip().split("\t", 1)[0]
            if current_file is None:
                current_file = UnifiedDiffFile(old_path=None, new_path=path_val)
                files.append(current_file)
            else:
                current_file.new_path = path_val
            continue

        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match:
            if current_file is None:
                current_file = UnifiedDiffFile(old_path=None, new_path="unknown")
                files.append(current_file)
            old_start = int(hunk_match.group("old_start"))
            old_count = int(hunk_match.group("old_count") or "1")
            new_start = int(hunk_match.group("new_start"))
            new_count = int(hunk_match.group("new_count") or "1")
            current_hunk = UnifiedDiffHunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                context_header=hunk_match.group("context").strip(),
            )
            current_file.hunks.append(current_hunk)
            old_line = old_start
            new_line = new_start
            continue

        if current_hunk is None:
            continue

        if line.startswith("-"):
            current_hunk.deleted_line_numbers.append(old_line)
            current_hunk.removed_lines.append(line[1:])
            old_line += 1
        elif line.startswith("+"):
            current_hunk.added_line_numbers.append(new_line)
            current_hunk.added_lines.append(line[1:])
            new_line += 1
        elif line.startswith(" ") or line == "":
            old_line += 1
            new_line += 1

    return files


@dataclass(frozen=True)
class _ASTSymbolSpan:
    qualified_name: str
    symbol_type: str  # "function" | "method" | "class"
    start_line: int
    end_line: int
    structural_dump: str


def _index_python_ast_symbols(
    source_text: str, module_name: str
) -> dict[str, _ASTSymbolSpan]:
    """Parse Python source statically to extract function/method/class AST signatures and spans."""
    try:
        tree = ast.parse(source_text)
    except (SyntaxError, RecursionError, ValueError):
        return {}

    symbols: dict[str, _ASTSymbolSpan] = {}

    def walk_body(
        stmts: list[ast.stmt], *, qual_prefix: str, in_class: bool, in_func: bool
    ) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qname = (
                    f"{qual_prefix}.<locals>.{stmt.name}"
                    if in_func
                    else f"{qual_prefix}.{stmt.name}"
                )
                sym_type = "method" if in_class else "function"
                start = max(1, getattr(stmt, "lineno", 1))
                end = max(start, getattr(stmt, "end_lineno", start) or start)
                symbols[qname] = _ASTSymbolSpan(
                    qualified_name=qname,
                    symbol_type=sym_type,
                    start_line=start,
                    end_line=end,
                    structural_dump=ast.dump(stmt, include_attributes=False),
                )
                walk_body(stmt.body, qual_prefix=qname, in_class=False, in_func=True)
            elif isinstance(stmt, ast.ClassDef):
                qname = f"{qual_prefix}.{stmt.name}"
                start = max(1, getattr(stmt, "lineno", 1))
                end = max(start, getattr(stmt, "end_lineno", start) or start)
                symbols[qname] = _ASTSymbolSpan(
                    qualified_name=qname,
                    symbol_type="class",
                    start_line=start,
                    end_line=end,
                    structural_dump=ast.dump(stmt, include_attributes=False),
                )
                walk_body(stmt.body, qual_prefix=qname, in_class=True, in_func=False)

    walk_body(tree.body, qual_prefix=module_name, in_class=False, in_func=False)
    return symbols


def compare_python_ast_versions(
    *,
    file_path: str,
    before_source: str | None,
    after_source: str | None,
    strip_src_root: bool = True,
) -> list[ModifiedSymbolDiff]:
    """Compare pre-patch and post-patch Python ASTs to identify changed functions/methods/classes."""
    module_name, _, _ = derive_module_identity(
        file_path.replace("\\", "/"), strip_src_root=strip_src_root
    )
    before_map = _index_python_ast_symbols(before_source, module_name) if before_source else {}
    after_map = _index_python_ast_symbols(after_source, module_name) if after_source else {}

    all_qnames = sorted(set(before_map) | set(after_map))
    diffs: list[ModifiedSymbolDiff] = []
    for qname in all_qnames:
        b = before_map.get(qname)
        a = after_map.get(qname)
        if b is not None and a is not None:
            if b.structural_dump != a.structural_dump:
                diffs.append(
                    ModifiedSymbolDiff(
                        file_path=file_path,
                        module_name=module_name,
                        qualified_name=qname,
                        symbol_type=a.symbol_type,  # type: ignore[arg-type]
                        change_type="modified",
                        before_lines=(b.start_line, b.end_line),
                        after_lines=(a.start_line, a.end_line),
                        ast_verified_from_source=True,
                    )
                )
        elif b is not None:
            diffs.append(
                ModifiedSymbolDiff(
                    file_path=file_path,
                    module_name=module_name,
                    qualified_name=qname,
                    symbol_type=b.symbol_type,  # type: ignore[arg-type]
                    change_type="deleted",
                    before_lines=(b.start_line, b.end_line),
                    after_lines=None,
                    ast_verified_from_source=True,
                )
            )
        elif a is not None:
            diffs.append(
                ModifiedSymbolDiff(
                    file_path=file_path,
                    module_name=module_name,
                    qualified_name=qname,
                    symbol_type=a.symbol_type,  # type: ignore[arg-type]
                    change_type="added",
                    before_lines=None,
                    after_lines=(a.start_line, a.end_line),
                    ast_verified_from_source=True,
                )
            )
    return diffs


def extract_patch_record(
    *,
    vulnerability_id: str,
    source_ref: str,
    diff_text: str,
    fetch_status: PatchFetchStatus,
    patch_sha256: str | None = None,
    before_after_sources: dict[str, tuple[str | None, str | None]] | None = None,
    dependency_source_dirs: list[Path] | None = None,
) -> ParsedPatchRecord:
    """Parse a unified diff into modified Python symbols using AST comparison or hunk alignment."""
    parsed_files = parse_unified_diff(diff_text)
    changed_files = [f.target_path for f in parsed_files]
    modified_symbols: list[ModifiedSymbolDiff] = []
    seen_qnames: set[str] = set()
    warnings: list[str] = []

    if before_after_sources:
        for file_path in sorted(before_after_sources):
            before_src, after_src = before_after_sources[file_path]
            for item in compare_python_ast_versions(
                file_path=file_path,
                before_source=before_src,
                after_source=after_src,
            ):
                if item.qualified_name not in seen_qnames:
                    seen_qnames.add(item.qualified_name)
                    modified_symbols.append(item)

    for diff_file in parsed_files:
        rel_path = diff_file.target_path
        if not rel_path.endswith(".py"):
            continue
        strip_src = rel_path.startswith("src/")
        module_name, _, _ = derive_module_identity(rel_path, strip_src_root=strip_src)

        # Try local dependency source AST line alignment if before_after wasn't already supplied
        local_spans: dict[str, _ASTSymbolSpan] = {}
        if dependency_source_dirs:
            local_text = _read_matching_dep_file(rel_path, dependency_source_dirs)
            if local_text is not None:
                local_spans = _index_python_ast_symbols(local_text, module_name)

        for hunk in diff_file.hunks:
            touched_lines = set(hunk.deleted_line_numbers) | set(hunk.added_line_numbers)
            if not touched_lines and hunk.new_start > 0:
                touched_lines = {hunk.new_start}

            matched_ast = False
            if local_spans:
                # Choose most specific enclosing AST symbol spans (prefer methods/functions over outer classes)
                matching = [
                    span
                    for span in local_spans.values()
                    if any(span.start_line <= ln <= span.end_line for ln in touched_lines)
                ]
                matching.sort(key=lambda s: (s.end_line - s.start_line, s.qualified_name))
                for span in matching:
                    if span.symbol_type == "class" and any(
                        m.symbol_type != "class" for m in matching
                    ):
                        continue
                    if span.qualified_name not in seen_qnames:
                        seen_qnames.add(span.qualified_name)
                        modified_symbols.append(
                            ModifiedSymbolDiff(
                                file_path=rel_path,
                                module_name=module_name,
                                qualified_name=span.qualified_name,
                                symbol_type=span.symbol_type,  # type: ignore[arg-type]
                                change_type="modified",
                                after_lines=(span.start_line, span.end_line),
                                ast_verified_from_source=True,
                            )
                        )
                    matched_ast = True

            if matched_ast:
                continue

            # Fallback: inspect unified diff hunk header `@@ ... @@ def/class ...`
            header_sym = _symbol_from_code_line(hunk.context_header, module_name)
            if header_sym is not None:
                qname, sym_type = header_sym
                if qname not in seen_qnames:
                    seen_qnames.add(qname)
                    modified_symbols.append(
                        ModifiedSymbolDiff(
                            file_path=rel_path,
                            module_name=module_name,
                            qualified_name=qname,
                            symbol_type=sym_type,  # type: ignore[arg-type]
                            change_type="context_hunk",
                            ast_verified_from_source=False,
                        )
                    )

            # Also inspect removed/added `def `/`class ` headers directly visible in the hunk
            for code_line, chg_type in [
                *((ln, "modified") for ln in hunk.removed_lines),
                *((ln, "added") for ln in hunk.added_lines),
            ]:
                line_sym = _symbol_from_code_line(code_line, module_name)
                if line_sym is not None:
                    qname, sym_type = line_sym
                    if qname not in seen_qnames:
                        seen_qnames.add(qname)
                        modified_symbols.append(
                            ModifiedSymbolDiff(
                                file_path=rel_path,
                                module_name=module_name,
                                qualified_name=qname,
                                symbol_type=sym_type,  # type: ignore[arg-type]
                                change_type=chg_type,  # type: ignore[arg-type]
                                ast_verified_from_source=False,
                            )
                        )

    if not parsed_files and diff_text.strip():
        warnings.append("Diff text did not contain standard unified diff headers.")

    excerpt = diff_text[:4000]
    return ParsedPatchRecord(
        vulnerability_id=vulnerability_id,
        source_ref=source_ref,
        fetch_status=fetch_status,
        patch_sha256=patch_sha256,
        changed_files=changed_files,
        modified_symbols=modified_symbols,
        diff_excerpt=excerpt,
        warnings=warnings,
    )


def _symbol_from_code_line(line: str, module_name: str) -> tuple[str, str] | None:
    m = _FUNC_OR_CLASS_LINE_RE.match(line)
    if not m:
        return None
    kind_raw = m.group("kind")
    sym_name = m.group("name")
    sym_type = "class" if kind_raw == "class" else "function"
    return f"{module_name}.{sym_name}", sym_type


def _read_matching_dep_file(rel_path: str, dep_dirs: list[Path]) -> str | None:
    rel_clean = rel_path.removeprefix("src/").lstrip("/")
    for src_dir in dep_dirs:
        resolved_root = src_dir.resolve()
        for candidate_rel in (rel_path, rel_clean):
            try:
                candidate = safe_resolve_path(resolved_root, candidate_rel)
            except PathTraversalError:
                continue
            if candidate.is_file() and not candidate.is_symlink():
                return candidate.read_text(encoding="utf-8", errors="replace")
    return None
