# Go Static Reachability Engine (`packages/core/analysis/go/` & `go_worker/`)

VEXReach analyzes Go applications conservatively via standard-library Go AST parsing (`go/ast`, `go/parser`, `go/token`) with **zero compilation or execution of untrusted target repositories**.

---

## 1. Architecture & Cross-Language Contract
- **Go Worker (`packages/core/analysis/go_worker/`)**: Standalone Go module compiled via `go build ./cmd/vexreach-go-analyze` exposing CLI analysis that emits JSON matching [`contracts/analysis_contract.json`](../../contracts/analysis_contract.json).
- **Python Bridge (`packages/core/analysis/go/reachability.py`)**: `GoReachabilityAnalyzer` locates Go (`VEXREACH_GO_PATH` or precompiled `VEXREACH_GO_ANALYZER_BINARY_PATH`), runs the worker with `shell=False` and bounded output/timeouts, and validates results into canonical `StaticReachabilityReport`.
- **Hybrid Orchestrator (`packages/core/analysis/__init__.py`)**: `run_hybrid_reachability_repository` and `run_hybrid_reachability_discovery` run Python, Go, or combined multi-language reachability cleanly.

---

## 2. Supported Subset & Conservative Failure Rules
- **Supported constructs**: `go.mod` module path resolution, same-package calls, cross-package imports & aliases, receiver methods (`*T` / `T`), local variable type inference, inline closures (`func(){...}()`), goroutines (`go func(){...}()`), explicit `entry_points.json`, `package main func main()`, HTTP route registrations (`http.HandleFunc`, `.GET`/`.POST`/etc.), Cobra commands, and dependency AST symbol verification in `vendor/` or `--dependency-source`.
- **Never-false-negative uncertainty rules**: `reflect.*` calls, `plugin.Open`, dot imports (`import . "..."`), dynamic function variables, and unresolved interface dispatch record explicit `UnresolvedCall` evidence and classify non-reachable findings as `unresolved` rather than `no_path_within_supported_subset`. Exceeded `max_depth` or file/graph limits report `analysis_incomplete`.
