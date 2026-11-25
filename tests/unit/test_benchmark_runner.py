"""Unit verification for reproducible Python and Go benchmark suites."""

from __future__ import annotations

import pytest

from benchmarks.run_go_benchmark import run_go_benchmark
from benchmarks.run_python_benchmark import BENCHMARK_CASES, run_benchmark


@pytest.mark.unit
def test_python_reachability_benchmark_matches_ground_truth_zero_false_safe() -> None:
    report = run_benchmark()
    assert report["total_cases"] == len(BENCHMARK_CASES)
    assert report["exact_matches"] == len(BENCHMARK_CASES)
    assert report["false_safe_regressions"] == 0
    assert report["total_duration_ms"] >= 0.0


@pytest.mark.unit
def test_go_reachability_benchmark_matches_ground_truth_zero_false_safe() -> None:
    report = run_go_benchmark()
    assert report["total_cases"] == 6
    assert report["exact_matches"] == 6
    assert report["false_safe_regressions"] == 0
    assert report["total_duration_ms"] >= 0.0
