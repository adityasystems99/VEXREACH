# VEXReach Python Static Reachability Engine (Phase 5)

## Overview

The VEXReach Python Static Reachability Engine evaluates whether a Python repository contains a **statically identifiable call path** from an application entry point to a candidate vulnerable symbol in a dependency.

It executes purely statically using Python's standard-library `ast` module and `networkx.DiGraph`. **It never imports, executes, loads, or installs target repository code or third-party dependencies.**

---

## Core Security Guarantees & Limitations

1. **Static reachability ≠ runtime execution:** Finding a call path (`reachable`) shows a statically plausible execution chain within the supported AST subset, not that inputs or runtime conditions execute that code in production.
2. **Static reachability ≠ exploitability:** Reachability analysis does not prove taint propagation, missing sanitization, or practical exploitability.
3. **Absence of a static path ≠ unreachability:** When no path is found cleanly in static code, VEXReach reports `no_path_within_supported_subset` — **never** `"unreachable"` or OpenVEX `"not_affected"`.
4. **Dynamic uncertainty stays explicit:** Constructs outside the static subset (`getattr`, `eval`, `exec`, `__import__`, `importlib.import_module`, wildcard imports `from x import *`, subscript dispatch, untyped callbacks/receivers) are captured as `UnresolvedCall` and `AnalysisDiagnostic` records. When no static path is found alongside entry-reachable dynamic constructs, the result state is `unresolved` (`reachable=None`).
5. **AI candidate symbols cannot self-verify:** `CandidateVulnerableSymbol` enforces via Pydantic validation that `source="ai_assisted_unverified"` cannot hold `confidence="verified"` without explicit `verified_by_deterministic_check=True`.
6. **Repository containment & portability:** Walks local files with `followlinks=False`, checks root containment via `safe_resolve_path`, skips symlinks and virtualenvs/caches, enforces file size and graph bounds, and stores repository-relative POSIX file paths in `CodeLocation`.

---

## Architecture & Modules (`packages/core/analysis/python/`)

- `discovery.py`: Discovers `.py` files deterministically (`PythonSourceDiscovery`), derives module names (handling `src/` layouts cleanly when no `src/__init__.py` exists), computes aggregate `source_snapshot_hash`, and enforces `max_file_size_bytes` and `max_python_files`.
- `parser.py`: Parses Python files via `ast.parse` (`parse_python_module`), capturing `SyntaxError`, `UnicodeDecodeError`, `OSError`, and `RecursionError` as `AnalysisDiagnostic` items without halting analysis of other files.
- `symbols.py`: Extracts top-level functions, async functions, classes, methods, nested `<locals>` functions, `if __name__ == "__main__":` blocks, parameter annotations, decorators, and simple constructor/literal type hints (`extract_module_symbols`).
- `imports.py`: Resolves absolute imports, dotted imports, module/symbol aliases, PEP 328 relative imports (`.` / `..`), and function-local imports while flagging wildcard imports and out-of-bounds relative imports (`extract_import_table`).
- `resolver.py`: Resolves local calls, cross-module calls, `self`/`cls` calls, inherited class methods, typed variable/parameter calls, and records dynamic constructs as `UnresolvedCall` (`PythonCallResolver`).
- `call_graph.py`: Builds a bounded `networkx.DiGraph` (`PythonCallGraphBuilder`, `PythonCallGraph`), merges duplicate call-site lines into sorted `CallGraphEdge.source_locations`, and enumerates simple bounded paths (`find_paths`) with `nx.has_path` deep-path checks so paths beyond `max_graph_depth` report `analysis_incomplete`.
- `entry_points.py`: Combines explicit `EntryPointConfig` rules with modular detectors for Python `__main__` blocks, FastAPI (`FastAPI`, `APIRouter`), Flask (`Flask`, `Blueprint`), Typer, and Click decorators (`EntryPointDetector`).
- `dependency_symbols.py`: Validates candidate symbol manifests (`load_symbol_manifest`), maps PyPI distributions conservatively to Python import roots, and optionally verifies candidate symbols against local dependency AST directories without executing dependency code (`DependencySymbolResolver`).
- `reachability.py`: End-to-end orchestrator (`PythonReachabilityAnalyzer`) supporting standalone repository + manifest analysis (`analyze_repository`) and full `DiscoveryResult` enrichment (`analyze_discovery_result`).

---

## Reachability States (`ReachabilityState`)

| State | `reachable` Field | Meaning |
| --- | --- | --- |
| `reachable` | `True` | At least one bounded directed static call path from an active entry point reaches the target symbol. |
| `no_path_within_supported_subset` | `False` | Analysis finished cleanly within graph bounds with resolved entry points and zero obscuring entry-reachable unresolved calls, and no path was found. |
| `unresolved` | `None` | Dynamic dispatch/imports/wildcards or ambiguous symbol mappings prevent ruling out reachability statically. |
| `analysis_incomplete` | `None` | Analysis hit bounds (`max_depth`, `max_python_files`, `max_graph_nodes`/`edges`), failed source parsing, or detected zero active entry points. |
| `missing_candidate_symbols` | `None` | No candidate vulnerable symbols were provided in the manifest for this vulnerability/package. |
| `target_symbol_not_found` | `None` | Dependency source AST was supplied and inspected, and the candidate symbol did not exist in that dependency source. |

---

## CLI Usage

Standalone repository reachability analysis:

```bash
vexreach analyze ./my-python-app \
  --symbols ./symbols.json \
  --entry-points ./entry_points.json \
  --dependency-source ./vendor_src \
  --output ./out
```

Integrated Discovery -> OSV Intelligence -> Python Static Reachability pipeline:

```bash
vexreach scan ./my-python-app \
  --enrich \
  --analyze \
  --symbols ./symbols.json \
  --output ./out
```

When `--output` is supplied, VEXReach persists and SHA-256 hashes:
- `reachability-analysis.json` (`StaticReachabilityReport`)
- `call-graph.json` (deterministic serialized `nodes` and `edges`)
- `candidate-symbols.json` (input manifest snapshot when provided)
- `provenance.json` (updated with reachability hashes and `source_snapshot_hash`)

---

## Known Supported Subset Boundaries (v1)

Unsupported Python patterns intentionally left outside static resolution (flagged rather than guessed):
- Runtime `eval`, `exec`, `compile`, `getattr`, `setattr`, `delattr`, `globals`, `locals`
- Dynamic `__import__` and `importlib.import_module`
- Dynamic subscript tables (`handlers[key]()`) and unannotated higher-order callback parameters
- Monkey-patching, metaclasses, runtime descriptor generation, and unannotated cross-file return-value propagation
- Non-Python ecosystems (Go, npm, OS packages remain out of scope for this analyzer)
