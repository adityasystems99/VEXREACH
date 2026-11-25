"""Reproducible Python Static Reachability Benchmark Suite across Fixtures A–M."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packages.core.analysis.python import (  # noqa: E402
    PythonReachabilityAnalyzer,
    load_entry_point_config,
    load_symbol_manifest,
)
from packages.core.models.reachability import ReachabilityState  # noqa: E402

FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures" / "reachability"
FAKE_DEP_SOURCES = FIXTURES_ROOT / "fake_dep_sources"


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    fixture_dir: str
    manifest_file: str = "symbols.json"
    entry_points_file: str | None = None
    use_dep_sources: bool = False
    max_depth: int | None = None
    expected_states: tuple[ReachabilityState, ...] = (ReachabilityState.REACHABLE,)


BENCHMARK_CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase("fixture_a_direct", "fixture_a_direct"),
    BenchmarkCase("fixture_b_multilevel", "fixture_b_multilevel"),
    BenchmarkCase("fixture_c_aliased_module", "fixture_c_aliased_module"),
    BenchmarkCase("fixture_d_aliased_function", "fixture_d_aliased_function"),
    BenchmarkCase(
        "fixture_e_no_path",
        "fixture_e_no_path",
        expected_states=(ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,),
    ),
    BenchmarkCase(
        "fixture_f_dynamic_getattr",
        "fixture_f_dynamic_getattr",
        expected_states=(ReachabilityState.UNRESOLVED,),
    ),
    BenchmarkCase("fixture_g_recursive", "fixture_g_recursive"),
    BenchmarkCase(
        "fixture_h_cyclic_imports",
        "fixture_h_cyclic_imports",
        entry_points_file="entry_points.json",
    ),
    BenchmarkCase("fixture_i_nested_and_methods", "fixture_i_nested_and_methods"),
    BenchmarkCase(
        "fixture_j_verified_dep_source",
        "fixture_a_direct",
        use_dep_sources=True,
    ),
    BenchmarkCase(
        "fixture_j_absent_symbol",
        "fixture_a_direct",
        manifest_file="symbols_absent.json",
        use_dep_sources=True,
        expected_states=(ReachabilityState.TARGET_SYMBOL_NOT_FOUND,),
    ),
    BenchmarkCase(
        "fixture_k_missing_manifest",
        "fixture_k_missing_manifest",
        manifest_file="empty_symbols.json",
        expected_states=(ReachabilityState.MISSING_CANDIDATE_SYMBOLS,),
    ),
    BenchmarkCase(
        "fixture_l_multiple_symbols",
        "fixture_l_multiple_symbols",
        expected_states=(
            ReachabilityState.REACHABLE,
            ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET,
        ),
    ),
    BenchmarkCase(
        "fixture_m_depth_bounded",
        "fixture_m_deep_chain",
        max_depth=3,
        expected_states=(ReachabilityState.ANALYSIS_INCOMPLETE,),
    ),
    BenchmarkCase(
        "fixture_m_deep_resolved",
        "fixture_m_deep_chain",
        max_depth=10,
        expected_states=(ReachabilityState.REACHABLE,),
    ),
)


def run_benchmark() -> dict[str, Any]:
    """Execute all Python reachability benchmark cases and measure actual timing & classification."""
    analyzer = PythonReachabilityAnalyzer()
    results_rows: list[dict[str, Any]] = []
    exact_matches = 0
    false_safe_regressions = 0
    total_duration_ms = 0.0

    for case in BENCHMARK_CASES:
        repo_dir = FIXTURES_ROOT / case.fixture_dir
        manifest, sha = load_symbol_manifest(repo_dir / case.manifest_file)
        ep_cfg = (
            load_entry_point_config(repo_dir / case.entry_points_file)
            if case.entry_points_file
            else None
        )
        dep_dirs = [FAKE_DEP_SOURCES] if case.use_dep_sources else None

        t0 = time.perf_counter()
        bundle = analyzer.analyze_repository(
            repo_dir,
            manifest=manifest,
            manifest_sha256=sha,
            entry_point_config=ep_cfg,
            dependency_source_dirs=dep_dirs,
            max_depth=case.max_depth,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        total_duration_ms += elapsed_ms

        observed = tuple(sorted(r.state.value for r in bundle.report.results))
        expected = tuple(sorted(s.value for s in case.expected_states))
        matched = observed == expected
        if matched:
            exact_matches += 1

        # False-safe check: claiming NO_PATH when expected state is REACHABLE or uncertain/unresolved
        if (
            ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET.value in observed
            and ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET.value not in expected
        ):
            false_safe_regressions += 1

        results_rows.append(
            {
                "case_id": case.case_id,
                "fixture": case.fixture_dir,
                "expected_states": list(expected),
                "observed_states": list(observed),
                "matched": matched,
                "duration_ms": elapsed_ms,
                "files_parsed": bundle.report.files_parsed,
            }
        )

    total = len(BENCHMARK_CASES)
    return {
        "benchmark_suite": "vexreach-python-reachability-fixtures-a-to-m",
        "total_cases": total,
        "exact_matches": exact_matches,
        "accuracy_percent": round((exact_matches / total) * 100.0, 2) if total else 0.0,
        "false_safe_regressions": false_safe_regressions,
        "total_duration_ms": round(total_duration_ms, 2),
        "cases": results_rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run reproducible VEXReach Python reachability benchmark.")
    parser.add_argument("--output-json", type=Path, default=None, help="Optional output file for JSON report.")
    args = parser.parse_args(argv)
    summary = run_benchmark()
    rendered = json.dumps(summary, indent=2)
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0 if summary["false_safe_regressions"] == 0 and summary["exact_matches"] == summary["total_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
