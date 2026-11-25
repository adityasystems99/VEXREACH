# VEXReach Reproducible Benchmark Suite

VEXReach tracks static reachability precision, fail-closed uncertainty classification, and execution speed with deterministic, reproducible benchmarks under [`benchmarks/run_python_benchmark.py`](../../benchmarks/run_python_benchmark.py).

## Running Locally

```bash
python benchmarks/run_python_benchmark.py --output-json .vexreach/benchmark-report.json
```

## Measured Baseline (Python Static Reachability Fixtures A–M)

Observed run on the local fixture corpus (`tests/fixtures/reachability/`) via `PythonReachabilityAnalyzer`:

- **Suite:** `vexreach-python-reachability-fixtures-a-to-m`
- **Total cases evaluated:** `15`
- **Exact ground-truth classification matches:** `15 / 15` (`100.0%`)
- **False-safe regressions (`no_path_within_supported_subset` when reachable or incomplete):** `0`
- **Total measured analyzer wall-clock duration:** `317.57 ms` across all 15 fixture runs (run on Windows / Python 3.14 `.venv`)

| Case ID | Expected States | Observed States | Duration (ms) | Files Parsed |
| :--- | :--- | :--- | ---: | ---: |
| `fixture_a_direct` | `reachable` | `reachable` | 51.24 | 1 |
| `fixture_b_multilevel` | `reachable` | `reachable` | 36.89 | 4 |
| `fixture_c_aliased_module` | `reachable` | `reachable` | 11.42 | 1 |
| `fixture_d_aliased_function` | `reachable` | `reachable` | 25.46 | 2 |
| `fixture_e_no_path` | `no_path_within_supported_subset` | `no_path_within_supported_subset` | 22.94 | 2 |
| `fixture_f_dynamic_getattr` | `unresolved` | `unresolved` | 12.97 | 1 |
| `fixture_g_recursive` | `reachable` | `reachable` | 12.58 | 1 |
| `fixture_h_cyclic_imports` | `reachable` | `reachable` | 33.69 | 3 |
| `fixture_i_nested_and_methods` | `reachable` | `reachable` | 13.38 | 1 |
| `fixture_j_verified_dep_source` | `reachable` | `reachable` | 25.37 | 1 |
| `fixture_j_absent_symbol` | `target_symbol_not_found` | `target_symbol_not_found` | 22.13 | 1 |
| `fixture_k_missing_manifest` | `missing_candidate_symbols` | `missing_candidate_symbols` | 11.25 | 1 |
| `fixture_l_multiple_symbols` | `no_path_within_supported_subset`, `reachable` | `no_path_within_supported_subset`, `reachable` | 12.56 | 1 |
| `fixture_m_depth_bounded` | `analysis_incomplete` | `analysis_incomplete` | 12.26 | 1 |
| `fixture_m_deep_resolved` | `reachable` | `reachable` | 13.43 | 1 |

> **Scope Caveat:** Python fixture measurements cover the local corpus cleanly without external network I/O. Below is the companion Go AST static reachability benchmark suite (`benchmarks/run_go_benchmark.py`):

---

## Measured Baseline (Go Static Reachability Suite)

```bash
python benchmarks/run_go_benchmark.py --output-json .vexreach/go-benchmark-report.json
```

Observed run via `GoReachabilityAnalyzer` (`vexreach-go-ast`, Go `1.27.4` windows/amd64):
- **Suite:** `vexreach-go-static-reachability`
- **Total cases evaluated:** `6`
- **Exact ground-truth classification matches:** `6 / 6` (`100.0%`)
- **False-safe regressions (`no_path_within_supported_subset` when reachable or incomplete):** `0`
- **Total measured duration (subprocess + compiled Go worker):** `1784.63 ms` across 6 benchmark scenarios

| Case ID | Expected State | Observed State | Duration (ms) |
| :--- | :--- | :--- | ---: |
| `go_http_goroutine_reachable` | `reachable` | `reachable` | 286.65 |
| `go_no_path_unused_helper` | `no_path_within_supported_subset` | `no_path_within_supported_subset` | 284.90 |
| `go_reflect_unresolved` | `unresolved` | `unresolved` | 293.45 |
| `go_depth_limit_incomplete` | `analysis_incomplete` | `analysis_incomplete` | 304.68 |
| `go_absent_symbol_fail_closed` | `target_symbol_not_found` | `target_symbol_not_found` | 325.27 |
| `go_missing_manifest_symbols` | `missing_candidate_symbols` | `missing_candidate_symbols` | 289.68 |
