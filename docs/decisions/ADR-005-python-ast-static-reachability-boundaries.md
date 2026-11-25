# ADR-005: Python AST Static Call-Graph Reachability Boundaries

- **Status:** Accepted
- **Date:** 2026-11-25
- **Milestone:** Phase 5 — Python Static Reachability Engine

## Context

VEXReach must determine whether a Python application contains a static execution path from an application entry point to candidate vulnerable symbols in third-party dependencies, as a prerequisite evidence layer before runtime analysis (later phases) and deterministic OpenVEX policy evaluation.

Running or importing target application code (or executing `pip install` / `inspect` in-process) introduces severe remote code execution risk when analyzing untrusted repositories, violates VEXReach security principle #10, and creates environment fragility across target Python versions.

Furthermore, naive static analyzers often overclaim certainty by labeling missing static paths as `"unreachable"` or silently ignoring dynamic Python features (`getattr`, `eval`, `importlib.import_module`, wildcard imports).

## Decision

1. **Pure Standard-Library `ast` + `networkx.DiGraph` Architecture:**
   - Parse target Python source files and optional local dependency sources exclusively via Python's built-in `ast` module.
   - Never import, execute, or dynamically evaluate analyzed source files or dependencies.
   - Build directed call graphs using `networkx.DiGraph` with configurable node, edge, depth, and path bounds (`max_python_files`, `max_graph_nodes`, `max_graph_edges`, `max_graph_depth`, `max_call_paths`).

2. **Six-State Explicit Conservative Taxonomy:**
   - Represent static outcomes explicitly using `ReachabilityState`:
     `reachable`, `no_path_within_supported_subset`, `unresolved`, `analysis_incomplete`, `missing_candidate_symbols`, and `target_symbol_not_found`.
   - Prohibit emitting `"unreachable"` or `"not_affected"` from static analysis alone.
   - Check `nx.has_path` when bounded simple-path traversal (`cutoff=max_graph_depth`) returns zero paths so paths exceeding the depth cap are reported as `analysis_incomplete` rather than `no_path_within_supported_subset`.
   - Downgrade `no_path_within_supported_subset` to `unresolved` when entry-reachable code contains dynamic/unresolved calls or wildcard imports.

3. **Strict Separation of Candidate Symbol Evidence:**
   - Candidate vulnerable symbols enter via validated `VulnerabilitySymbolManifest` contracts carrying `SymbolSource`, `SymbolConfidence`, and evidence references.
   - Pydantic validation rejects `source="ai_assisted_unverified"` entries claiming `confidence="verified"` unless `verified_by_deterministic_check=True`.
   - Missing local dependency source produces `dependency_symbol_status="dependency_source_unavailable"` cleanly without silently rewriting results to `target_symbol_not_found`.

4. **Portable Repository-Relative Locations:**
   - Record all source locations in `CodeLocation` using forward-slash repository-relative paths, avoiding leaking host filesystem paths into persisted artifacts.

## Consequences

- **Positive:** Safe against untrusted target code execution, zero dependency on target virtualenvs at scan time, deterministic reproducible graph artifacts (`call-graph.json`, `reachability-analysis.json`), and explicit separation of missing knowledge vs. negative static results.
- **Negative / Trade-offs:** Higher-order callbacks, duck-typed unannotated attributes, monkey-patching, and reflection remain unresolved (`unresolved`) rather than resolved optimistically, reducing false negatives at the cost of requiring human triage or future runtime evidence to resolve dynamic paths.
- **Deferred Scope:** Non-Python ecosystems (Go), LLM patch-diff symbol extraction, runtime trace correlation, and OpenVEX emission are explicitly deferred to their designated milestones.
