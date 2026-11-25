"""Safe subprocess bridge executing VEXReach's Go AST static reachability worker."""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from packages.core.analysis.python.reachability import ReachabilityAnalysisBundle
from packages.core.config.settings import Settings, get_settings
from packages.core.models.discovery import (
    DiscoveryResult,
    PackageRecord,
    VulnerabilityRecord,
)
from packages.core.models.reachability import (
    AnalysisDiagnostic,
    EntryPointConfig,
    StaticReachabilityReport,
    SymbolPackageTarget,
    VulnerabilitySymbolEntry,
    VulnerabilitySymbolManifest,
)
from packages.core.utils.logging import get_logger

logger = get_logger("analysis.go")

_GO_WORKER_DIR = Path(__file__).resolve().parent.parent / "go_worker"
_GO_ECOSYSTEMS = {"golang", "go", "gomod", "gobinary"}
_PYTHON_ECOSYSTEMS = {"pypi", "python"}


class GoAnalyzerError(Exception):
    """Base error raised by the Go static reachability integration."""


class GoToolchainNotFoundError(GoAnalyzerError):
    """Raised when neither a Go compiler nor a prebuilt vexreach-go-analyze binary is found."""


class GoAnalyzerExecutionError(GoAnalyzerError):
    """Raised when the Go static analyzer fails, times out, or returns invalid output."""


def resolve_go_executable(settings: Settings) -> str:
    """Locate a Go compiler executable cleanly, checking PATH and standard Windows install paths."""
    candidate = settings.go_path.strip()
    if candidate:
        has_sep = os.path.sep in candidate or (os.path.altsep and os.path.altsep in candidate)
        if has_sep:
            p = Path(candidate)
            if p.is_file():
                return str(p.resolve())
        else:
            found = shutil.which(candidate)
            if found:
                return found

    if os.name == "nt":
        for win_cand in (
            Path(r"C:\Program Files\Go\bin\go.exe"),
            Path(r"C:\Go\bin\go.exe"),
        ):
            if win_cand.is_file():
                return str(win_cand)

    raise GoToolchainNotFoundError(
        f"Go binary '{settings.go_path}' not found on PATH and no precompiled go_analyzer_binary_path provided."
    )


@functools.lru_cache(maxsize=4)
def _compile_cached_worker(go_exe: str) -> str:
    """Compile packages/core/analysis/go_worker once per process into temp cache without target code execution."""
    if not _GO_WORKER_DIR.is_dir():
        raise GoAnalyzerExecutionError(f"Go worker module directory missing: {_GO_WORKER_DIR}")

    suffix = ".exe" if os.name == "nt" else ""
    cache_root = Path(tempfile.gettempdir()) / "vexreach-go-cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    out_bin = cache_root / f"vexreach-go-analyze{suffix}"

    # Rebuild if missing or any Go source file is newer than cached binary
    needs_build = not out_bin.is_file()
    if not needs_build:
        bin_mtime = out_bin.stat().st_mtime
        for src in _GO_WORKER_DIR.rglob("*.go"):
            if src.stat().st_mtime > bin_mtime:
                needs_build = True
                break

    if needs_build:
        env = dict(os.environ)
        env["GOCACHE"] = str(cache_root / "go-build")
        env["GOTMPDIR"] = str(cache_root / "go-tmp")
        (cache_root / "go-build").mkdir(parents=True, exist_ok=True)
        (cache_root / "go-tmp").mkdir(parents=True, exist_ok=True)

        proc = subprocess.run(
            [go_exe, "build", "-o", str(out_bin), "./cmd/vexreach-go-analyze"],
            cwd=str(_GO_WORKER_DIR),
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise GoAnalyzerExecutionError(
                f"Failed to compile Go static analyzer worker (rc={proc.returncode}): {proc.stderr.strip()}"
            )
    return str(out_bin)


def repository_contains_go(target_path: Path | str) -> bool:
    """Safely check whether target_path contains Go modules/files without executing code."""
    root = Path(target_path)
    if root.is_file():
        return root.suffix.lower() == ".go"
    if not root.is_dir():
        return False
    if (root / "go.mod").is_file():
        return True
    for cur_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules", "vendor"}]
        if any(f.endswith(".go") and not f.endswith("_test.go") for f in files):
            return True
    return False


def repository_contains_python(target_path: Path | str) -> bool:
    """Safely check whether target_path contains Python sources or manifests."""
    root = Path(target_path)
    if root.is_file():
        return root.suffix.lower() == ".py"
    if not root.is_dir():
        return False
    for name in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "poetry.lock"):
        if (root / name).is_file():
            return True
    for cur_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules"}]
        if any(f.endswith(".py") for f in files):
            return True
    return False


def merge_reachability_bundles(bundles: list[ReachabilityAnalysisBundle]) -> ReachabilityAnalysisBundle:
    """Merge multi-language (e.g. Python + Go) ReachabilityAnalysisBundles deterministically."""
    if not bundles:
        raise ValueError("Cannot merge empty reachability bundle list.")
    if len(bundles) == 1:
        return bundles[0]

    langs = "+".join(dict.fromkeys(b.report.language for b in bundles))
    first = bundles[0].report
    merged_report = StaticReachabilityReport(
        analyzer_name="vexreach-hybrid-ast",
        analyzer_version=first.analyzer_version,
        language=langs,
        source_snapshot_hash=first.source_snapshot_hash,
        manifest_sha256=first.manifest_sha256,
        files_discovered=sum(b.report.files_discovered for b in bundles),
        files_parsed=sum(b.report.files_parsed for b in bundles),
        files_failed=sum(b.report.files_failed for b in bundles),
        graph_node_count=sum(b.report.graph_node_count for b in bundles),
        graph_edge_count=sum(b.report.graph_edge_count for b in bundles),
        max_graph_depth=max(b.report.max_graph_depth for b in bundles),
        max_call_paths=max(b.report.max_call_paths for b in bundles),
        truncated=any(b.report.truncated for b in bundles),
        vulnerabilities_analyzed=sum(b.report.vulnerabilities_analyzed for b in bundles),
        candidate_symbols_evaluated=sum(b.report.candidate_symbols_evaluated for b in bundles),
        entry_points=[ep for b in bundles for ep in b.report.entry_points],
        results=[r for b in bundles for r in b.report.results],
        unresolved_calls=[u for b in bundles for u in b.report.unresolved_calls],
        diagnostics=[d for b in bundles for d in b.report.diagnostics],
        supported_subset_notes=list(
            dict.fromkeys(note for b in bundles for note in b.report.supported_subset_notes)
        ),
    )

    merged_nodes = []
    merged_edges = []
    for b in bundles:
        cg = b.call_graph_artifact
        merged_nodes.extend(cg.get("nodes", []))
        merged_edges.extend(cg.get("edges", []))

    return ReachabilityAnalysisBundle(
        report=merged_report,
        call_graph_artifact={"language": langs, "nodes": merged_nodes, "edges": merged_edges},
        manifest=bundles[0].manifest,
    )


class GoReachabilityAnalyzer:
    """Executes VEXReach's standalone Go AST worker cleanly with schema validation."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def _resolve_worker_binary(self) -> str:
        explicit = self._settings.go_analyzer_binary_path
        if explicit and explicit.strip():
            p = Path(explicit.strip())
            if p.is_file():
                return str(p.resolve())
            raise GoToolchainNotFoundError(f"Configured Go analyzer binary not found: {explicit}")
        go_exe = resolve_go_executable(self._settings)
        return _compile_cached_worker(go_exe)

    def analyze_repository(
        self,
        target_path: Path | str,
        *,
        manifest: VulnerabilitySymbolManifest | None = None,
        manifest_sha256: str | None = None,
        entry_point_config: EntryPointConfig | None = None,
        dependency_source_dirs: list[Path] | None = None,
        vulnerabilities: list[VulnerabilityRecord] | None = None,
        packages: list[PackageRecord] | None = None,
        vulnerability_aliases: dict[str, list[str]] | None = None,
        max_depth: int | None = None,
        max_paths: int | None = None,
    ) -> ReachabilityAnalysisBundle:
        """Analyze a Go repository directory or `.go` file via bounded subprocess invocation."""
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Go target path does not exist: {target}")

        effective_manifest = self._prepare_manifest(
            manifest=manifest,
            vulnerabilities=vulnerabilities,
            packages=packages,
            vulnerability_aliases=vulnerability_aliases,
        )

        worker_bin = self._resolve_worker_binary()

        with tempfile.TemporaryDirectory(prefix="vexreach-go-") as tmp_dir_raw:
            tmp_dir = Path(tmp_dir_raw)
            out_file = tmp_dir / "go-bundle.json"

            cmd = [
                worker_bin,
                "--target",
                str(target.resolve()),
                "--max-depth",
                str(max_depth or self._settings.max_graph_depth),
                "--max-paths",
                str(max_paths or self._settings.max_call_paths),
                "--max-files",
                str(self._settings.max_go_files),
                "--max-nodes",
                str(self._settings.max_graph_nodes),
                "--max-edges",
                str(self._settings.max_graph_edges),
                "--out",
                str(out_file),
            ]

            if effective_manifest is not None:
                sym_file = tmp_dir / "symbols.json"
                sym_file.write_text(effective_manifest.model_dump_json(indent=2), encoding="utf-8")
                cmd.extend(["--symbols", str(sym_file)])

            if entry_point_config is not None:
                ep_file = tmp_dir / "entry_points.json"
                ep_file.write_text(entry_point_config.model_dump_json(indent=2), encoding="utf-8")
                cmd.extend(["--entry-points", str(ep_file)])

            if dependency_source_dirs:
                dep_joined = ",".join(str(Path(d).resolve()) for d in dependency_source_dirs)
                cmd.extend(["--dependency-source", dep_joined])

            try:
                proc = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=self._settings.go_timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise GoAnalyzerExecutionError(
                    f"Go analyzer exceeded timeout of {self._settings.go_timeout_seconds}s"
                ) from exc

            if proc.returncode != 0:
                raise GoAnalyzerExecutionError(
                    f"Go analyzer exited with code {proc.returncode}: {proc.stderr.strip()}"
                )

            if not out_file.is_file():
                raise GoAnalyzerExecutionError("Go analyzer exited zero without creating output file.")

            raw_bytes = out_file.read_bytes()
            if len(raw_bytes) > self._settings.max_go_output_bytes:
                raise GoAnalyzerExecutionError(
                    f"Go analyzer JSON ({len(raw_bytes)} bytes) exceeds max_go_output_bytes limit."
                )

            parsed: dict[str, Any] = json.loads(raw_bytes.decode("utf-8"))
            if "report" not in parsed or "call_graph" not in parsed:
                raise GoAnalyzerExecutionError("Go analyzer output missing 'report' or 'call_graph'.")

            report_dict = dict(parsed["report"])
            if manifest_sha256:
                report_dict["manifest_sha256"] = manifest_sha256

            report = StaticReachabilityReport.model_validate(report_dict, strict=False)
            logger.info(
                "Go static reachability analyzed %d files, nodes=%d edges=%d results=%d",
                report.files_parsed,
                report.graph_node_count,
                report.graph_edge_count,
                len(report.results),
            )
            return ReachabilityAnalysisBundle(
                report=report,
                call_graph_artifact=parsed["call_graph"],
                manifest=effective_manifest,
            )

    def analyze_discovery_result(
        self,
        discovery_result: DiscoveryResult,
        *,
        target_path: Path | str | None = None,
        manifest: VulnerabilitySymbolManifest | None = None,
        manifest_sha256: str | None = None,
        entry_point_config: EntryPointConfig | None = None,
        dependency_source_dirs: list[Path] | None = None,
        max_depth: int | None = None,
        max_paths: int | None = None,
    ) -> tuple[DiscoveryResult, ReachabilityAnalysisBundle]:
        """Run Go static reachability analysis over Go findings in a DiscoveryResult."""
        resolved_target = Path(target_path or discovery_result.target.target_path)
        alias_map: dict[str, list[str]] = {}
        if discovery_result.intelligence is not None:
            for intel in discovery_result.intelligence.vulnerabilities:
                alias_map[intel.vulnerability_id] = list(
                    dict.fromkeys([intel.canonical_id, *intel.aliases])
                )

        bundle = self.analyze_repository(
            target_path=resolved_target,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            entry_point_config=entry_point_config,
            dependency_source_dirs=dependency_source_dirs,
            vulnerabilities=discovery_result.vulnerabilities,
            packages=discovery_result.packages,
            vulnerability_aliases=alias_map,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        updated = discovery_result.model_copy(update={"reachability": bundle.report})
        return updated, bundle

    @staticmethod
    def _prepare_manifest(
        *,
        manifest: VulnerabilitySymbolManifest | None,
        vulnerabilities: list[VulnerabilityRecord] | None,
        packages: list[PackageRecord] | None,
        vulnerability_aliases: dict[str, list[str]] | None,
    ) -> VulnerabilitySymbolManifest | None:
        if not vulnerabilities:
            return manifest

        pkg_by_id = {p.package_id: p for p in (packages or [])}
        entry_lookup: dict[str, VulnerabilitySymbolEntry] = {}
        if manifest is not None:
            for e in manifest.entries:
                entry_lookup[e.vulnerability_id.upper()] = e

        alias_lookup = vulnerability_aliases or {}
        go_entries: list[VulnerabilitySymbolEntry] = []

        for vuln in vulnerabilities:
            pkg = pkg_by_id.get(vuln.package_id)
            eco = (pkg.ecosystem if pkg else "unknown").lower()
            if eco not in _GO_ECOSYSTEMS:
                continue

            matched_entry = None
            for cid in [vuln.vulnerability_id, *alias_lookup.get(vuln.vulnerability_id, [])]:
                if cid.upper() in entry_lookup:
                    matched_entry = entry_lookup[cid.upper()]
                    break

            if matched_entry is not None:
                go_entries.append(
                    matched_entry.model_copy(
                        update={
                            "vulnerability_id": vuln.vulnerability_id,
                            "package": matched_entry.package.model_copy(
                                update={"purl": pkg.purl if pkg else matched_entry.package.purl}
                            ),
                        }
                    )
                )
            else:
                go_entries.append(
                    VulnerabilitySymbolEntry(
                        vulnerability_id=vuln.vulnerability_id,
                        package=SymbolPackageTarget(
                            ecosystem=pkg.ecosystem if pkg else "golang",
                            name=pkg.name if pkg else vuln.package_id,
                            version=pkg.version if pkg else None,
                            purl=pkg.purl if pkg else None,
                        ),
                        symbols=[],
                    )
                )

        if not go_entries and manifest is not None:
            return manifest
        return VulnerabilitySymbolManifest(entries=go_entries)
