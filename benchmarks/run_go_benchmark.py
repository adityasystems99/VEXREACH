"""Reproducible Go Static Reachability Benchmark Suite powered by GoReachabilityAnalyzer."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packages.core.analysis.go import GoReachabilityAnalyzer  # noqa: E402
from packages.core.models.reachability import (  # noqa: E402
    CandidateVulnerableSymbol,
    ReachabilityState,
    SymbolConfidence,
    SymbolPackageTarget,
    SymbolSource,
    VulnerabilitySymbolEntry,
    VulnerabilitySymbolManifest,
)

GO_SAMPLE_APP = REPO_ROOT / "tests" / "fixtures" / "go_reachability" / "sample_web_app"
GO_FAKE_DEPS = REPO_ROOT / "tests" / "fixtures" / "go_reachability" / "fake_dep_sources"


def _manifest_for(qualified_name: str | None) -> VulnerabilitySymbolManifest:
    symbols = (
        [
            CandidateVulnerableSymbol(
                module="gopkg.in/yaml.v2",
                qualified_name=qualified_name,
                source=SymbolSource.CURATED_ADVISORY_ANALYSIS,
                confidence=SymbolConfidence.VERIFIED,
            )
        ]
        if qualified_name
        else []
    )
    return VulnerabilitySymbolManifest(
        entries=[
            VulnerabilitySymbolEntry(
                vulnerability_id="CVE-2022-28948",
                package=SymbolPackageTarget(ecosystem="golang", name="gopkg.in/yaml.v2"),
                symbols=symbols,
            )
        ]
    )


def run_go_benchmark() -> dict[str, Any]:
    """Execute reproducible Go static reachability scenarios and capture real timings."""
    analyzer = GoReachabilityAnalyzer()
    cases: list[dict[str, Any]] = []
    exact = 0
    false_safe = 0
    total_ms = 0.0

    with tempfile.TemporaryDirectory(prefix="vexreach-go-bench-") as tmp_raw:
        tmp = Path(tmp_raw)

        # Case 1: Sample HTTP web app (goroutine wrapper -> yaml.Unmarshal)
        no_path_repo = tmp / "no_path"
        no_path_repo.mkdir()
        (no_path_repo / "go.mod").write_text("module example.com/nopath\n\ngo 1.22\n", encoding="utf-8")
        (no_path_repo / "main.go").write_text(
            'package main\nimport "net/http"\nfunc Health(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }\nfunc main() { http.HandleFunc("/h", Health) }\n',
            encoding="utf-8",
        )
        (no_path_repo / "unused.go").write_text(
            'package main\nimport "gopkg.in/yaml.v2"\nfunc dead() { _ = yaml.Unmarshal(nil, nil) }\n',
            encoding="utf-8",
        )

        # Case 3: Reflection uncertainty
        reflect_repo = tmp / "reflect_app"
        reflect_repo.mkdir()
        (reflect_repo / "go.mod").write_text("module example.com/refl\n\ngo 1.22\n", encoding="utf-8")
        (reflect_repo / "main.go").write_text(
            'package main\nimport "reflect"\nfunc main() { reflect.ValueOf(nil).MethodByName("Call").Call(nil) }\n',
            encoding="utf-8",
        )

        # Case 4: Deep chain depth limit
        deep_repo = tmp / "deep_app"
        deep_repo.mkdir()
        (deep_repo / "go.mod").write_text("module example.com/deep\n\ngo 1.22\n", encoding="utf-8")
        (deep_repo / "main.go").write_text(
            'package main\nimport "gopkg.in/yaml.v2"\nfunc a(){b()}\nfunc b(){c()}\nfunc c(){_ = yaml.Unmarshal(nil,nil)}\nfunc main(){a()}\n',
            encoding="utf-8",
        )

        specs = [
            ("go_http_goroutine_reachable", GO_SAMPLE_APP, _manifest_for("gopkg.in/yaml.v2.Unmarshal"), [GO_FAKE_DEPS], 15, ReachabilityState.REACHABLE),
            ("go_no_path_unused_helper", no_path_repo, _manifest_for("gopkg.in/yaml.v2.Unmarshal"), None, 15, ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET),
            ("go_reflect_unresolved", reflect_repo, _manifest_for("gopkg.in/yaml.v2.Unmarshal"), None, 15, ReachabilityState.UNRESOLVED),
            ("go_depth_limit_incomplete", deep_repo, _manifest_for("gopkg.in/yaml.v2.Unmarshal"), None, 2, ReachabilityState.ANALYSIS_INCOMPLETE),
            ("go_absent_symbol_fail_closed", GO_SAMPLE_APP, _manifest_for("gopkg.in/yaml.v2.Absent"), [GO_FAKE_DEPS], 15, ReachabilityState.TARGET_SYMBOL_NOT_FOUND),
            ("go_missing_manifest_symbols", GO_SAMPLE_APP, _manifest_for(None), None, 15, ReachabilityState.MISSING_CANDIDATE_SYMBOLS),
        ]

        for cid, repo, man, deps, depth, expected in specs:
            t0 = time.perf_counter()
            bundle = analyzer.analyze_repository(
                repo, manifest=man, dependency_source_dirs=deps, max_depth=depth
            )
            ms = round((time.perf_counter() - t0) * 1000.0, 2)
            total_ms += ms
            observed = bundle.report.results[0].state
            matched = observed == expected
            if matched:
                exact += 1
            if observed == ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET and expected != ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET:
                false_safe += 1
            cases.append(
                {
                    "case_id": cid,
                    "expected_state": expected.value,
                    "observed_state": observed.value,
                    "matched": matched,
                    "duration_ms": ms,
                }
            )

    total = len(cases)
    return {
        "benchmark_suite": "vexreach-go-static-reachability",
        "total_cases": total,
        "exact_matches": exact,
        "accuracy_percent": round((exact / total) * 100.0, 2) if total else 0.0,
        "false_safe_regressions": false_safe,
        "total_duration_ms": round(total_ms, 2),
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible VEXReach Go reachability benchmark.")
    parser.add_argument("--output-json", type=Path, default=None)
    args = parser.parse_args()
    summary = run_go_benchmark()
    rendered = json.dumps(summary, indent=2)
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0 if summary["false_safe_regressions"] == 0 and summary["exact_matches"] == summary["total_cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
