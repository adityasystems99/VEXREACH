"""VEXReach CLI main entry point powered by Typer and Rich."""

import platform
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from packages.core import __version__
from packages.core.analysis import (
    run_hybrid_reachability_discovery,
    run_hybrid_reachability_repository,
)
from packages.core.analysis.go.reachability import (
    GoAnalyzerError,
    GoToolchainNotFoundError,
    resolve_go_executable,
)
from packages.core.analysis.python import (
    load_entry_point_config,
    load_symbol_manifest,
)
from packages.core.config.settings import get_settings
from packages.core.engines.ai_intelligence import AISecurityIntelligenceOrchestrator
from packages.core.engines.attack_path import AttackPathOrchestrator
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.engines.openvex import OpenVEXOrchestrator
from packages.core.engines.risk import RiskIntelligenceOrchestrator
from packages.core.integrations.threat_feeds import ThreatFeedClient
from packages.core.integrations.trivy.client import TrivyClient, TrivyError
from packages.core.models.ai_intelligence import AIAdvisoryIntelligenceReport
from packages.core.models.attack_path import AttackPathReport
from packages.core.models.discovery import DiscoveryResult, ScanStatus, SeverityLevel
from packages.core.models.intelligence import IntelligenceStatus, VulnerabilityIntelligenceReport
from packages.core.models.openvex import OpenVEXPolicyReport
from packages.core.models.reachability import ReachabilityState, StaticReachabilityReport
from packages.core.models.risk import RiskIntelligenceReport, WorkloadContext
from packages.core.storage.evidence_store import EvidenceStore
from packages.core.storage.vex_history import SQLiteVEXStore
from packages.core.utils.logging import get_logger, setup_logging

app = typer.Typer(
    name="vexreach",
    help="AI-Assisted, Kubernetes-Native Vulnerability Intelligence Platform",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)
logger = get_logger("cli")


@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose debug logging"),
    ] = False,
    json_logs: Annotated[
        bool,
        typer.Option("--json-logs", help="Emit logs in JSON format for automated pipelines"),
    ] = False,
) -> None:
    """Configure global logging and runtime execution parameters."""
    settings = get_settings()
    log_level = "DEBUG" if verbose else settings.log_level
    log_format = "json" if json_logs else settings.log_format
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["log_format"] = log_format
    setup_logging(level=log_level, log_format=log_format)


@app.command("version")
def version_command() -> None:
    """Display the VEXReach version and environment details."""
    settings = get_settings()
    table = Table(title="VEXReach Runtime Environment", show_header=False, border_style="cyan")
    table.add_column("Property", style="bold white")
    table.add_column("Value", style="green")

    table.add_row("VEXReach Version", __version__)
    table.add_row("Python Version", sys.version.split()[0])
    table.add_row(
        "Operating System",
        f"{platform.system()} {platform.release()} ({platform.machine()})",
    )
    table.add_row("Environment Mode", settings.environment)
    table.add_row("Storage Target", str(settings.storage_path))

    console.print(table)


@app.command("check-config")
def check_config_command() -> None:
    """Validate active configuration and verify external tool dependencies."""
    settings = get_settings()

    console.print(Panel(f"[bold cyan]Validating Configuration: {settings.app_name}[/bold cyan]"))

    table = Table(title="Toolchain & Prerequisites", border_style="blue")
    table.add_column("Component", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="dim")

    # Python version check
    py_ver = sys.version_info
    if py_ver >= (3, 12):
        table.add_row(
            "Python Runtime",
            "[green]OK[/green]",
            f"{py_ver.major}.{py_ver.minor}.{py_ver.micro} (>= 3.12)",
        )
    else:
        table.add_row(
            "Python Runtime",
            "[red]UNSUPPORTED[/red]",
            f"Found {py_ver.major}.{py_ver.minor}, requires >= 3.12",
        )

    # Git check
    git_bin = shutil.which("git")
    if git_bin:
        table.add_row("Git CLI", "[green]FOUND[/green]", git_bin)
    else:
        table.add_row("Git CLI", "[yellow]MISSING[/yellow]", "Recommended for repository tracking")

    # Docker check
    docker_bin = shutil.which("docker")
    if docker_bin:
        table.add_row("Docker Engine", "[green]FOUND[/green]", docker_bin)
    else:
        table.add_row(
            "Docker Engine",
            "[yellow]NOT FOUND[/yellow]",
            "Required later for containerized scans & sandbox tests",
        )

    # Trivy check (respects VEXREACH_TRIVY_PATH)
    trivy_client = TrivyClient(
        binary_path=settings.trivy_path,
        max_output_bytes=settings.max_scanner_output_bytes,
    )
    if trivy_client.is_available():
        try:
            ver_info = trivy_client.get_version()
            table.add_row(
                "Trivy Scanner",
                "[green]FOUND[/green]",
                f"{trivy_client.resolve_binary()} (v{ver_info.version})",
            )
        except TrivyError as err:
            table.add_row("Trivy Scanner", "[yellow]ERROR[/yellow]", str(err))
    else:
        table.add_row(
            "Trivy Scanner",
            "[yellow]NOT FOUND[/yellow]",
            "Install Trivy or set VEXREACH_TRIVY_PATH for Discovery Engine scans",
        )

    try:
        go_bin = resolve_go_executable(settings)
        table.add_row("Go Toolchain", "[green]FOUND[/green]", go_bin)
    except GoToolchainNotFoundError:
        table.add_row(
            "Go Toolchain",
            "[yellow]NOT FOUND[/yellow]",
            "Install Go (>=1.22) or set VEXREACH_GO_PATH for Go static reachability & operator builds",
        )

    table.add_row("Database Path", "[green]CONFIGURED[/green]", str(settings.storage_path))
    table.add_row(
        "Assessments Dir",
        "[green]CONFIGURED[/green]",
        str(settings.default_output_dir),
    )

    console.print(table)
    console.print("\n[bold green]Configuration validation complete.[/bold green]")


def _render_discovery_summary(result: DiscoveryResult, output_dir: Path | None) -> None:
    """Render a deterministic, human-readable Discovery Engine assessment summary."""
    counts = result.severity_counts()
    target_display = Path(result.target.target_path).name or result.target.target_path
    scanner_ver = (
        f"v{result.scan_metadata.scanner_version}"
        if result.scan_metadata.scanner_version
        else "unavailable"
    )
    sbom_fmt = (
        f"CycloneDX ({result.sbom.format_version})"
        if result.sbom.format_version
        else "CycloneDX (unavailable)"
    )

    console.print("\n[bold cyan]VEXReach Discovery Assessment[/bold cyan]\n")
    console.print(f"Target: {target_display} ({result.target.target_path})")
    console.print(f"Scanner: Trivy ({scanner_ver})")
    console.print(f"SBOM Format: {sbom_fmt}")
    console.print(f"SBOM Completeness: {result.sbom.completeness_status.value.upper()}\n")

    console.print(f"Packages discovered: {len(result.packages)}")
    console.print(f"Vulnerabilities discovered: {len(result.vulnerabilities)}\n")

    console.print(f"Critical: {counts[SeverityLevel.CRITICAL.value]}")
    console.print(f"High: {counts[SeverityLevel.HIGH.value]}")
    console.print(f"Medium: {counts[SeverityLevel.MEDIUM.value]}")
    console.print(f"Low: {counts[SeverityLevel.LOW.value]}")
    if counts[SeverityLevel.NEGLIGIBLE.value] > 0:
        console.print(f"Negligible: {counts[SeverityLevel.NEGLIGIBLE.value]}")
    if counts[SeverityLevel.UNKNOWN.value] > 0:
        console.print(f"Unknown: {counts[SeverityLevel.UNKNOWN.value]}")

    status = result.scan_metadata.scan_status
    status_style = {
        ScanStatus.COMPLETED: "green",
        ScanStatus.PARTIAL: "yellow",
        ScanStatus.FAILED: "red",
    }[status]
    console.print(
        f"\nAssessment status: [{status_style}]{status.value.upper()}[/{status_style}]"
    )
    if output_dir is not None:
        console.print(f"Evidence directory: {output_dir}")

    if result.warnings:
        console.print("\n[yellow]Warnings:[/yellow]")
        for warning in result.warnings:
            console.print(f"  - {warning}")

    if result.errors:
        console.print("\n[red]Errors:[/red]")
        for error in result.errors:
            console.print(f"  - {error}")


def _render_intelligence_summary(report: VulnerabilityIntelligenceReport) -> None:
    """Render a deterministic, human-readable Vulnerability Intelligence summary."""
    console.print("\n[bold cyan]VEXReach Vulnerability Intelligence[/bold cyan]\n")
    console.print(f"Findings discovered: {report.findings_discovered}")
    console.print(f"Advisories retrieved: {report.advisories_retrieved}")
    console.print(f"Identifier correlations: {report.identifier_correlations}")
    console.print(f"Affected version ranges evaluated: {report.affected_ranges_evaluated}")
    console.print(f"Conflicting records: {report.conflicting_records}")
    console.print(f"Incomplete intelligence records: {report.incomplete_intelligence_records}")
    if report.withdrawn_advisories > 0:
        console.print(f"Withdrawn advisories: {report.withdrawn_advisories}")
    console.print(
        f"Queries: batch={report.batch_queries_executed}, "
        f"individual={report.individual_queries_executed}, cache_hits={report.cache_hits}"
    )

    status = report.intelligence_status
    status_style = {
        IntelligenceStatus.ENRICHED: "green",
        IntelligenceStatus.PARTIALLY_ENRICHED: "yellow",
        IntelligenceStatus.NO_FINDINGS: "cyan",
        IntelligenceStatus.FAILED: "red",
    }[status]
    console.print(
        f"\nIntelligence status: [{status_style}]{status.value.upper()}[/{status_style}]"
    )
    if report.raw_osv_evidence_path:
        console.print(f"Raw OSV evidence: {report.raw_osv_evidence_path}")

    if report.warnings:
        console.print("\n[yellow]Intelligence Warnings:[/yellow]")
        for warning in report.warnings:
            console.print(f"  - {warning}")

    if report.errors:
        console.print("\n[red]Intelligence Errors:[/red]")
        for error in report.errors:
            console.print(f"  - {error}")


def _render_reachability_summary(
    report: StaticReachabilityReport, output_dir: Path | None = None
) -> None:
    """Render a conservative Python static reachability summary."""
    console.print("\n[bold cyan]VEXReach Python Static Reachability[/bold cyan]\n")
    console.print(
        f"Python files: discovered={report.files_discovered}, "
        f"parsed={report.files_parsed}, failed={report.files_failed}"
    )
    console.print(
        f"Call graph: nodes={report.graph_node_count}, "
        f"edges={report.graph_edge_count}, truncated={report.truncated}"
    )
    console.print(f"Entry points detected: {len(report.entry_points)}")
    console.print(
        f"Evaluated: vulnerabilities={report.vulnerabilities_analyzed}, "
        f"candidate_symbols={report.candidate_symbols_evaluated}"
    )

    counts = report.state_counts()
    console.print(
        "State counts: "
        + ", ".join(f"{state}={count}" for state, count in counts.items() if count > 0 or state == ReachabilityState.REACHABLE.value)
    )

    if report.results:
        table = Table(title="Static Reachability Findings")
        table.add_column("Vulnerability", style="bold")
        table.add_column("Package")
        table.add_column("Candidate Symbol")
        table.add_column("State")
        table.add_column("Dep Symbol Check")
        table.add_column("Path / Detail")

        state_styles = {
            ReachabilityState.REACHABLE: "red",
            ReachabilityState.NO_PATH_WITHIN_SUPPORTED_SUBSET: "green",
            ReachabilityState.UNRESOLVED: "yellow",
            ReachabilityState.ANALYSIS_INCOMPLETE: "yellow",
            ReachabilityState.MISSING_CANDIDATE_SYMBOLS: "cyan",
            ReachabilityState.TARGET_SYMBOL_NOT_FOUND: "magenta",
        }
        for res in report.results:
            style = state_styles.get(res.state, "white")
            sym_str = res.candidate_symbol.qualified_name if res.candidate_symbol else "-"
            detail = (
                " -> ".join(res.path)
                if res.path
                else (
                    f"{len(res.unresolved_calls)} unresolved call(s)"
                    if res.unresolved_calls
                    else (res.diagnostics[0].code if res.diagnostics else "-")
                )
            )
            table.add_row(
                res.vulnerability_id,
                res.package_name,
                sym_str,
                f"[{style}]{res.state.value}[/{style}]",
                res.dependency_symbol_status.value,
                detail,
            )
        console.print(table)

    console.print(
        "\n[dim]Scope note: Static reachability indicates a possible call path within the "
        "supported Python AST subset; 'no_path_within_supported_subset' does not prove unreachability, "
        "and static paths do not establish runtime execution or exploitability.[/dim]"
    )
    if output_dir is not None:
        console.print(f"Reachability artifacts: {output_dir}")


def _render_ai_intelligence_summary(report: AIAdvisoryIntelligenceReport) -> None:
    """Render AI Security Intelligence candidate symbol extraction summary."""
    console.print("\n[bold cyan]VEXReach AI & Patch Symbol Intelligence[/bold cyan]\n")
    console.print(f"Provider: {report.llm_provider} (model={report.llm_model or 'none'})")
    console.print(
        f"Processed: {report.vulnerabilities_processed} Python vulns, "
        f"patches_retrieved={report.patches_retrieved}"
    )
    console.print(
        f"Candidates: accepted={report.candidates_accepted}, "
        f"rejected={report.candidates_rejected}, "
        f"prompt_injection_signals={report.prompt_injections_detected}"
    )
    if report.prompt_injections_detected > 0:
        console.print(
            "[yellow]Security notice: Indirect prompt-injection pattern(s) detected and quarantined.[/yellow]"
        )
    if report.analyses:
        table = Table(title="Candidate Vulnerable Symbols Extracted")
        table.add_column("Vulnerability", style="bold")
        table.add_column("Package")
        table.add_column("Symbol")
        table.add_column("Source")
        table.add_column("Confidence")
        for item in report.analyses:
            if not item.accepted_symbols:
                table.add_row(item.vulnerability_id, item.package_name, "-", "-", "none")
                continue
            for sym in item.accepted_symbols:
                table.add_row(
                    item.vulnerability_id,
                    item.package_name,
                    sym.qualified_name,
                    sym.source.value,
                    sym.confidence.value,
                )
        console.print(table)


def _render_attack_path_summary(report: AttackPathReport) -> None:
    """Render Attack Path Intelligence summary cleanly."""
    console.print("\n[bold cyan]VEXReach Attack Path Intelligence[/bold cyan]\n")
    console.print(
        f"Paths evaluated={report.paths_evaluated}, "
        f"network_exposed={report.network_exposed_paths}, "
        f"taint_observed={report.taint_observed_paths}, "
        f"call_path_only={report.call_path_only_paths}"
    )
    if report.paths:
        table = Table(title="Conservative Attack Paths")
        table.add_column("Vulnerability", style="bold")
        table.add_column("Entry Point")
        table.add_column("Surface")
        table.add_column("Data Flow Status")
        table.add_column("Target Symbol")
        for item in report.paths:
            table.add_row(
                item.vulnerability_id,
                item.entry_point,
                item.exposure_surface.value,
                item.data_flow_status.value,
                item.target_symbol,
            )
        console.print(table)


def _render_vex_summary(report: OpenVEXPolicyReport) -> None:
    """Render deterministic OpenVEX 0.2.0 policy summary cleanly."""
    doc = report.openvex_document
    console.print("\n[bold cyan]VEXReach OpenVEX 0.2.0 Policy Assessment[/bold cyan]\n")
    console.print(
        f"Document: {doc.id} (v{doc.version}, schema_valid={report.schema_valid})"
    )
    console.print(
        "Status counts: "
        + ", ".join(f"{status}={count}" for status, count in report.status_counts.items())
    )
    if report.completeness.blocking_gaps:
        console.print(
            "[yellow]Completeness blockers preserving conservative uncertainty:[/yellow]"
        )
        for gap in report.completeness.blocking_gaps:
            console.print(f"  - {gap}")

    if report.decisions:
        table = Table(title="Deterministic VEX Decisions")
        table.add_column("Vulnerability", style="bold")
        table.add_column("Package")
        table.add_column("Status")
        table.add_column("Rule")
        table.add_column("Confidence")
        for dec in report.decisions:
            table.add_row(
                dec.vulnerability_id,
                dec.package_name,
                dec.decided_status.value,
                dec.decision_rule,
                dec.confidence,
            )
        console.print(table)
    if report.openvex_file_path:
        console.print(f"OpenVEX artifact: {report.openvex_file_path}")


def _render_risk_summary(report: RiskIntelligenceReport) -> None:
    """Render explainable Risk Intelligence summary without fabricating exploitability."""
    console.print("\n[bold cyan]VEXReach Contextual Risk Intelligence[/bold cyan]\n")
    console.print(
        f"Findings scored={report.findings_scored}, KEV matches={report.kev_matches}, "
        f"workload={report.workload_context.workload_name} ({report.workload_context.criticality})"
    )
    console.print(
        "Priority counts: "
        + ", ".join(f"{tier}={cnt}" for tier, cnt in report.priority_counts.items())
    )
    if report.assessments:
        table = Table(title="Risk Prioritization")
        table.add_column("Vulnerability", style="bold")
        table.add_column("Package")
        table.add_column("Score")
        table.add_column("Tier")
        table.add_column("Static Path")
        table.add_column("KEV")
        for item in report.assessments:
            table.add_row(
                item.vulnerability_id,
                item.package_name,
                f"{item.contextual_score:.1f}",
                item.priority_tier.value,
                str(item.static_path_identified),
                str(item.threat_signals.in_cisa_kev),
            )
        console.print(table)
    console.print(
        "\n[dim]Note: Contextual risk scores rank remediation priority; exploitability_established remains False unless verified separately.[/dim]"
    )


@app.command("scan")
def scan_command(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="Local repository or directory path to scan"),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory in which to store raw scanner evidence, SBOM, and normalized JSON",
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format for terminal output: table or json",
        ),
    ] = "table",
    timeout: Annotated[
        int | None,
        typer.Option(
            "--timeout",
            "-t",
            min=1,
            max=3600,
            help="Scanner execution timeout in seconds",
        ),
    ] = None,
    enrich: Annotated[
        bool,
        typer.Option(
            "--enrich",
            help="Enrich discovered findings and packages using OSV.dev Vulnerability Intelligence",
        ),
    ] = False,
    refresh_cache: Annotated[
        bool,
        typer.Option(
            "--refresh-cache",
            help="Bypass and refresh local SQLite OSV advisory cache during enrichment",
        ),
    ] = False,
    extract_symbols: Annotated[
        bool,
        typer.Option(
            "--extract-symbols",
            help="Extract & validate candidate vulnerable symbols from patches and configured LLM",
        ),
    ] = False,
    patch_dir: Annotated[
        Path | None,
        typer.Option(
            "--patch-dir",
            help="Directory containing local <vuln-id>.diff/.patch files for symbol extraction",
        ),
    ] = None,
    fetch_patches: Annotated[
        bool,
        typer.Option(
            "--fetch-patches",
            help="Allow fetching upstream commit/PR diffs from allowlisted GitHub HTTPS URLs",
        ),
    ] = False,
    analyze: Annotated[
        bool,
        typer.Option(
            "--analyze",
            help="Run Python AST static call-graph reachability analysis after discovery",
        ),
    ] = False,
    attack_paths: Annotated[
        bool,
        typer.Option(
            "--attack-paths",
            help="Run Attack Path Intelligence over reachable Python paths (implies --analyze)",
        ),
    ] = False,
    emit_vex: Annotated[
        bool,
        typer.Option(
            "--emit-vex",
            help="Evaluate deterministic policies and emit OpenVEX 0.2.0 statements",
        ),
    ] = False,
    compute_risk: Annotated[
        bool,
        typer.Option(
            "--risk",
            help="Evaluate explainable contextual Risk Intelligence (CVSS, EPSS/KEV, reachability)",
        ),
    ] = False,
    epss_file: Annotated[
        Path | None,
        typer.Option("--epss-file", help="Optional local EPSS JSON snapshot file"),
    ] = None,
    kev_file: Annotated[
        Path | None,
        typer.Option("--kev-file", help="Optional local CISA KEV catalog JSON file"),
    ] = None,
    symbols: Annotated[
        Path | None,
        typer.Option(
            "--symbols",
            help="Path to candidate vulnerable symbol manifest JSON file",
        ),
    ] = None,
    entry_points: Annotated[
        Path | None,
        typer.Option(
            "--entry-points",
            help="Path to explicit entry-point configuration JSON file",
        ),
    ] = None,
    dependency_source: Annotated[
        list[Path] | None,
        typer.Option(
            "--dependency-source",
            help="Optional directory containing dependency Python sources for AST verification",
        ),
    ] = None,
    max_depth: Annotated[
        int | None,
        typer.Option(
            "--max-depth",
            min=1,
            help="Maximum simple call path traversal depth",
        ),
    ] = None,
    max_paths: Annotated[
        int | None,
        typer.Option(
            "--max-paths",
            min=1,
            help="Maximum call paths to enumerate per target symbol",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose debug logging"),
    ] = False,
) -> None:
    """Run Discovery Engine against a local directory/repository to generate SBOM and CVE report."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json"}:
        raise typer.BadParameter("Format must be 'table', 'text', or 'json'.", param_hint="--format")

    settings = get_settings()
    ctx_obj = ctx.obj or {}
    effective_verbose = verbose or bool(ctx_obj.get("verbose", False))
    log_level = "DEBUG" if effective_verbose else settings.log_level
    log_format = str(ctx_obj.get("log_format", settings.log_format))

    # Keep stdout strictly machine-readable when --format json is requested
    setup_logging(
        level=log_level,
        log_format=log_format,
        stream=sys.stderr if fmt == "json" else sys.stdout,
    )

    if output is not None and output.exists() and not output.is_dir():
        err_console.print(f"[red]Error:[/red] Output path exists and is not a directory: {output}")
        raise typer.Exit(code=1)

    orchestrator = DiscoveryOrchestrator(settings=settings)
    try:
        result, artifacts = orchestrator.run_discovery(
            target_path=target,
            output_dir=output,
            timeout=timeout,
        )
    except OSError as err:
        err_console.print(f"[red]Filesystem error during assessment:[/red] {err}")
        raise typer.Exit(code=1) from err

    if enrich:
        with IntelligenceOrchestrator(settings=settings) as intel_orchestrator:
            result = intel_orchestrator.enrich(
                discovery_result=result,
                artifacts=artifacts,
                refresh_cache=refresh_cache,
            )

    ai_generated_manifest = None
    if extract_symbols:
        with AISecurityIntelligenceOrchestrator(
            settings=settings,
            dependency_source_dirs=dependency_source,
        ) as ai_orch:
            result, ai_report, raw_patch_payloads = ai_orch.analyze_discovery_result(
                result,
                patch_dir=patch_dir,
                fetch_remote_patches=fetch_patches,
            )
            ai_generated_manifest = ai_report.generated_manifest
            if artifacts is not None:
                ai_store = EvidenceStore(artifacts.assessment_dir.parent)
                ai_store.persist_ai_intelligence_artifacts(
                    artifacts,
                    ai_report,
                    raw_patch_payloads=raw_patch_payloads,
                )
                ai_store.persist_assessment(artifacts=artifacts, result=result)

    if analyze or attack_paths:
        loaded_manifest = None
        manifest_sha = None
        loaded_ep_config = None
        try:
            if symbols is not None:
                loaded_manifest, manifest_sha = load_symbol_manifest(symbols)
            elif ai_generated_manifest is not None:
                loaded_manifest = ai_generated_manifest
                if (
                    artifacts is not None
                    and artifacts.candidate_symbols_path is not None
                    and artifacts.candidate_symbols_path.is_file()
                ):
                    from packages.core.utils.safe_path import calculate_file_sha256

                    manifest_sha = calculate_file_sha256(artifacts.candidate_symbols_path)
            if entry_points is not None:
                loaded_ep_config = load_entry_point_config(entry_points)
        except (FileNotFoundError, ValueError) as err:
            err_console.print(f"[red]Reachability configuration error:[/red] {err}")
            raise typer.Exit(code=1) from err

        result, reach_bundle = run_hybrid_reachability_discovery(
            result,
            target_path=target,
            settings=settings,
            manifest=loaded_manifest,
            manifest_sha256=manifest_sha,
            entry_point_config=loaded_ep_config,
            dependency_source_dirs=dependency_source,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        if artifacts is not None:
            reach_store = EvidenceStore(artifacts.assessment_dir.parent)
            reach_store.persist_reachability_artifacts(
                artifacts,
                reach_bundle.report,
                call_graph_artifact=reach_bundle.call_graph_artifact,
                manifest=reach_bundle.manifest,
            )
            reach_store.persist_assessment(artifacts=artifacts, result=result)

    if attack_paths:
        result, ap_report = AttackPathOrchestrator(
            settings=settings
        ).analyze_discovery_result(result, target_path=target)
        if artifacts is not None:
            ap_store = EvidenceStore(artifacts.assessment_dir.parent)
            ap_store.persist_attack_path_artifacts(artifacts, ap_report)
            ap_store.persist_assessment(artifacts=artifacts, result=result)

    if compute_risk:
        with ThreatFeedClient(settings=settings) as feed_client:
            snap = feed_client.load_snapshot(
                [v.vulnerability_id for v in result.vulnerabilities],
                epss_file=epss_file,
                kev_file=kev_file,
                fetch_remote=False,
            )
        result, risk_report = RiskIntelligenceOrchestrator().evaluate(
            result, threat_snapshot=snap
        )
        if artifacts is not None:
            risk_store = EvidenceStore(artifacts.assessment_dir.parent)
            risk_store.persist_risk_artifacts(artifacts, risk_report)
            risk_store.persist_assessment(artifacts=artifacts, result=result)

    if emit_vex:
        vex_store = (
            EvidenceStore(artifacts.assessment_dir.parent)
            if artifacts is not None
            else None
        )
        result, _ = OpenVEXOrchestrator(
            settings=settings,
            evidence_store=vex_store,
        ).generate(result, artifacts=artifacts)

    if fmt == "json":
        typer.echo(result.model_dump_json(indent=2))
    else:
        _render_discovery_summary(result, artifacts.assessment_dir if artifacts else None)
        if result.intelligence is not None:
            _render_intelligence_summary(result.intelligence)
        if result.ai_intelligence is not None:
            _render_ai_intelligence_summary(result.ai_intelligence)
        if result.reachability is not None:
            _render_reachability_summary(
                result.reachability, artifacts.assessment_dir if artifacts else None
            )
        if result.attack_paths is not None:
            _render_attack_path_summary(result.attack_paths)
        if result.risk_assessment is not None:
            _render_risk_summary(result.risk_assessment)
        if result.policy_evaluation is not None:
            _render_vex_summary(result.policy_evaluation)

    if result.scan_metadata.scan_status == ScanStatus.FAILED:
        raise typer.Exit(code=1)
    if result.scan_metadata.scan_status == ScanStatus.PARTIAL:
        raise typer.Exit(code=2)
    if result.intelligence is not None and (
        result.intelligence.intelligence_status == IntelligenceStatus.FAILED
    ):
        raise typer.Exit(code=1)


@app.command("intelligence")
def intelligence_command(
    assessment_id: Annotated[
        str,
        typer.Argument(help="Assessment ID or directory path containing discovery-assessment.json"),
    ],
    assessments_dir: Annotated[
        Path | None,
        typer.Option(
            "--assessments-dir",
            "-d",
            help="Base directory where assessments are stored",
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format for terminal output: table or json",
        ),
    ] = "table",
    enrich: Annotated[
        bool,
        typer.Option(
            "--enrich",
            help="Run or refresh OSV intelligence enrichment on this stored assessment",
        ),
    ] = False,
    refresh_cache: Annotated[
        bool,
        typer.Option(
            "--refresh-cache",
            help="Bypass and refresh local SQLite advisory cache when --enrich is used",
        ),
    ] = False,
) -> None:
    """Inspect or enrich vulnerability intelligence for a stored Discovery assessment."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json"}:
        raise typer.BadParameter("Format must be 'table', 'text', or 'json'.", param_hint="--format")

    settings = get_settings()
    if fmt == "json":
        setup_logging(level=settings.log_level, log_format=settings.log_format, stream=sys.stderr)

    store = EvidenceStore(assessments_dir or settings.default_output_dir)
    try:
        result, artifacts = store.load_assessment(assessment_id)
    except (FileNotFoundError, ValueError) as err:
        err_console.print(f"[red]Error loading assessment:[/red] {err}")
        raise typer.Exit(code=1) from err

    if enrich:
        with IntelligenceOrchestrator(settings=settings, evidence_store=store) as intel_orch:
            result = intel_orch.enrich(
                discovery_result=result,
                artifacts=artifacts,
                refresh_cache=refresh_cache,
            )

    if fmt == "json":
        typer.echo(result.model_dump_json(indent=2))
        return

    console.print(f"[bold]Assessment ID:[/bold] {result.assessment_id}")
    console.print(f"[bold]Target:[/bold] {result.target.target_path}")
    if result.intelligence is None:
        console.print(
            "\n[yellow]No vulnerability intelligence attached to this assessment yet.[/yellow] "
            "Run with `--enrich` to query OSV.dev."
        )
        return

    _render_intelligence_summary(result.intelligence)
    if result.intelligence.intelligence_status == IntelligenceStatus.FAILED:
        raise typer.Exit(code=1)


@app.command("analyze")
def analyze_command(
    ctx: typer.Context,
    target: Annotated[
        str,
        typer.Argument(help="Path to local Python application directory or .py file"),
    ],
    symbols: Annotated[
        Path | None,
        typer.Option(
            "--symbols",
            "-s",
            help="Path to candidate vulnerable symbol manifest JSON file",
        ),
    ] = None,
    entry_points: Annotated[
        Path | None,
        typer.Option(
            "--entry-points",
            "-e",
            help="Path to explicit entry-point configuration JSON file",
        ),
    ] = None,
    dependency_source: Annotated[
        list[Path] | None,
        typer.Option(
            "--dependency-source",
            help="Optional directory containing dependency Python sources for AST verification",
        ),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Directory to write reachability-analysis.json, call-graph.json, and provenance.json",
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format for terminal output: table, text, or json",
        ),
    ] = "table",
    max_depth: Annotated[
        int | None,
        typer.Option(
            "--max-depth",
            min=1,
            help="Maximum simple call path traversal depth",
        ),
    ] = None,
    max_paths: Annotated[
        int | None,
        typer.Option(
            "--max-paths",
            min=1,
            help="Maximum call paths to enumerate per target symbol",
        ),
    ] = None,
    language: Annotated[
        str,
        typer.Option(
            "--language",
            "-l",
            help="Target static analyzer language: auto, python, or go",
        ),
    ] = "auto",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose debug logging"),
    ] = False,
) -> None:
    """Run conservative static AST call-graph reachability analysis (Python & Go)."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json"}:
        raise typer.BadParameter(
            "Format must be 'table', 'text', or 'json'.", param_hint="--format"
        )

    settings = get_settings()
    if verbose or fmt == "json":
        log_level = "DEBUG" if verbose else settings.log_level
        stream = sys.stderr if fmt == "json" else None
        setup_logging(level=log_level, log_format=settings.log_format, stream=stream)

    loaded_manifest = None
    manifest_sha = None
    loaded_ep_config = None
    try:
        if symbols is not None:
            loaded_manifest, manifest_sha = load_symbol_manifest(symbols)
        if entry_points is not None:
            loaded_ep_config = load_entry_point_config(entry_points)
    except (FileNotFoundError, ValueError) as err:
        err_console.print(f"[red]Invalid input manifest or entry-point config:[/red] {err}")
        raise typer.Exit(code=1) from err

    try:
        bundle = run_hybrid_reachability_repository(
            target_path=target,
            language=language,
            settings=settings,
            manifest=loaded_manifest,
            manifest_sha256=manifest_sha,
            entry_point_config=loaded_ep_config,
            dependency_source_dirs=dependency_source,
            max_depth=max_depth,
            max_paths=max_paths,
        )
    except (FileNotFoundError, ValueError, GoAnalyzerError) as err:
        err_console.print(f"[red]Target analysis error:[/red] {err}")
        raise typer.Exit(code=1) from err

    if output_dir is not None:
        resolved_out = output_dir.resolve()
        store = EvidenceStore(resolved_out.parent)
        artifacts = store._build_artifacts(resolved_out)
        store.persist_reachability_artifacts(
            artifacts,
            bundle.report,
            call_graph_artifact=bundle.call_graph_artifact,
            manifest=bundle.manifest,
            write_standalone_provenance=True,
        )

    if fmt == "json":
        typer.echo(bundle.report.model_dump_json(indent=2))
    else:
        _render_reachability_summary(
            bundle.report, output_dir.resolve() if output_dir else None
        )


@app.command("extract-symbols")
def extract_symbols_command(
    assessment_id: Annotated[
        str,
        typer.Argument(help="Assessment ID or directory path containing discovery-assessment.json"),
    ],
    assessments_dir: Annotated[
        Path | None,
        typer.Option("--assessments-dir", "-d", help="Base directory where assessments are stored"),
    ] = None,
    patch_dir: Annotated[
        Path | None,
        typer.Option("--patch-dir", help="Optional directory containing local .diff/.patch files"),
    ] = None,
    dependency_source: Annotated[
        list[Path] | None,
        typer.Option("--dependency-source", help="Directory containing dependency Python sources"),
    ] = None,
    fetch_patches: Annotated[
        bool,
        typer.Option("--fetch-patches", help="Allow fetching allowlisted GitHub HTTPS commit diffs"),
    ] = False,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, text, or json"),
    ] = "table",
) -> None:
    """Extract and deterministically validate candidate vulnerable symbols for an assessment."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json"}:
        raise typer.BadParameter("Format must be 'table', 'text', or 'json'.", param_hint="--format")

    settings = get_settings()
    if fmt == "json":
        setup_logging(level=settings.log_level, log_format=settings.log_format, stream=sys.stderr)

    store = EvidenceStore(assessments_dir or settings.default_output_dir)
    try:
        result, artifacts = store.load_assessment(assessment_id)
    except (FileNotFoundError, ValueError) as err:
        err_console.print(f"[red]Error loading assessment:[/red] {err}")
        raise typer.Exit(code=1) from err

    with AISecurityIntelligenceOrchestrator(
        settings=settings,
        dependency_source_dirs=dependency_source,
    ) as ai_orch:
        result, report, raw_patch_payloads = ai_orch.analyze_discovery_result(
            result,
            patch_dir=patch_dir,
            fetch_remote_patches=fetch_patches,
        )
        store.persist_ai_intelligence_artifacts(
            artifacts, report, raw_patch_payloads=raw_patch_payloads
        )
        store.persist_assessment(artifacts=artifacts, result=result)

    if fmt == "json":
        typer.echo(report.model_dump_json(indent=2))
    else:
        _render_ai_intelligence_summary(report)


@app.command("attack-paths")
def attack_paths_command(
    assessment_id: Annotated[
        str,
        typer.Argument(help="Assessment ID or directory path containing discovery-assessment.json"),
    ],
    assessments_dir: Annotated[
        Path | None,
        typer.Option("--assessments-dir", "-d", help="Base directory where assessments are stored"),
    ] = None,
    target_path: Annotated[
        Path | None,
        typer.Option("--target", "-t", help="Override target repository source path"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, text, or json"),
    ] = "table",
) -> None:
    """Analyze ingress exposure, barriers, and conservative taint along reachable Python paths."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json"}:
        raise typer.BadParameter("Format must be 'table', 'text', or 'json'.", param_hint="--format")

    settings = get_settings()
    if fmt == "json":
        setup_logging(level=settings.log_level, log_format=settings.log_format, stream=sys.stderr)

    store = EvidenceStore(assessments_dir or settings.default_output_dir)
    try:
        result, artifacts = store.load_assessment(assessment_id)
    except (FileNotFoundError, ValueError) as err:
        err_console.print(f"[red]Error loading assessment:[/red] {err}")
        raise typer.Exit(code=1) from err

    result, ap_report = AttackPathOrchestrator(settings=settings).analyze_discovery_result(
        result, target_path=target_path
    )
    store.persist_attack_path_artifacts(artifacts, ap_report)
    store.persist_assessment(artifacts=artifacts, result=result)

    if fmt == "json":
        typer.echo(ap_report.model_dump_json(indent=2))
    else:
        _render_attack_path_summary(ap_report)


@app.command("vex")
def vex_command(
    assessment_id: Annotated[
        str,
        typer.Argument(help="Assessment ID or directory path containing discovery-assessment.json"),
    ],
    assessments_dir: Annotated[
        Path | None,
        typer.Option("--assessments-dir", "-d", help="Base directory where assessments are stored"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, text, json (pure OpenVEX), or policy-json"),
    ] = "table",
    history: Annotated[
        bool,
        typer.Option("--history", help="Display historical OpenVEX document revisions for this target"),
    ] = False,
) -> None:
    """Evaluate deterministic policies and emit or inspect OpenVEX 0.2.0 statements."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json", "policy-json"}:
        raise typer.BadParameter(
            "Format must be 'table', 'text', 'json', or 'policy-json'.",
            param_hint="--format",
        )

    settings = get_settings()
    if fmt in {"json", "policy-json"}:
        setup_logging(level=settings.log_level, log_format=settings.log_format, stream=sys.stderr)

    store = EvidenceStore(assessments_dir or settings.default_output_dir)
    try:
        result, artifacts = store.load_assessment(assessment_id)
    except (FileNotFoundError, ValueError) as err:
        err_console.print(f"[red]Error loading assessment:[/red] {err}")
        raise typer.Exit(code=1) from err

    history_store = SQLiteVEXStore(settings.storage_path)
    if history:
        revisions = history_store.list_history(result.target.target_path)
        if fmt in {"json", "policy-json"}:
            import json as _json

            typer.echo(_json.dumps(revisions, indent=2))
            return
        console.print(f"[bold]OpenVEX History for:[/bold] {result.target.target_path}")
        for rev in revisions:
            console.print(
                f"  v{rev['version']} | {rev['document_id']} | sha256={rev['content_sha256'][:12]} | counts={rev['status_counts']}"
            )
        return

    _, policy_report = OpenVEXOrchestrator(
        settings=settings,
        vex_history_store=history_store,
        evidence_store=store,
    ).generate(result, artifacts=artifacts)

    if fmt == "json":
        typer.echo(policy_report.openvex_document.to_openvex_json())
    elif fmt == "policy-json":
        typer.echo(policy_report.model_dump_json(indent=2))
    else:
        _render_vex_summary(policy_report)


@app.command("risk")
def risk_command(
    assessment_id: Annotated[
        str,
        typer.Argument(help="Assessment ID or directory path containing discovery-assessment.json"),
    ],
    assessments_dir: Annotated[
        Path | None,
        typer.Option("--assessments-dir", "-d", help="Base directory where assessments are stored"),
    ] = None,
    epss_file: Annotated[
        Path | None,
        typer.Option("--epss-file", help="Optional local EPSS JSON snapshot file"),
    ] = None,
    kev_file: Annotated[
        Path | None,
        typer.Option("--kev-file", help="Optional local CISA KEV catalog JSON file"),
    ] = None,
    fetch_feeds: Annotated[
        bool,
        typer.Option("--fetch-feeds", help="Fetch live FIRST EPSS & CISA KEV feeds over HTTPS"),
    ] = False,
    internet_facing: Annotated[
        bool,
        typer.Option("--internet-facing", help="Mark workload as internet-facing"),
    ] = False,
    criticality: Annotated[
        str,
        typer.Option("--criticality", help="Workload criticality: critical, high, medium, low"),
    ] = "medium",
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, text, or json"),
    ] = "table",
) -> None:
    """Compute explainable contextual Risk Intelligence for a stored assessment."""
    fmt = output_format.strip().lower()
    if fmt not in {"table", "text", "json"}:
        raise typer.BadParameter("Format must be 'table', 'text', or 'json'.", param_hint="--format")
    crit = criticality.strip().lower()
    if crit not in {"critical", "high", "medium", "low"}:
        raise typer.BadParameter("criticality must be critical, high, medium, or low.")

    settings = get_settings()
    if fmt == "json":
        setup_logging(level=settings.log_level, log_format=settings.log_format, stream=sys.stderr)

    store = EvidenceStore(assessments_dir or settings.default_output_dir)
    try:
        result, artifacts = store.load_assessment(assessment_id)
    except (FileNotFoundError, ValueError) as err:
        err_console.print(f"[red]Error loading assessment:[/red] {err}")
        raise typer.Exit(code=1) from err

    with ThreatFeedClient(settings=settings) as feed_client:
        snap = feed_client.load_snapshot(
            [v.vulnerability_id for v in result.vulnerabilities],
            epss_file=epss_file,
            kev_file=kev_file,
            fetch_remote=fetch_feeds,
        )
    result, report = RiskIntelligenceOrchestrator().evaluate(
        result,
        threat_snapshot=snap,
        workload_context=WorkloadContext(
            internet_facing=internet_facing,
            criticality=crit,  # type: ignore[arg-type]
        ),
    )
    store.persist_risk_artifacts(artifacts, report)
    store.persist_assessment(artifacts=artifacts, result=result)

    if fmt == "json":
        typer.echo(report.model_dump_json(indent=2))
    else:
        _render_risk_summary(report)


if __name__ == "__main__":
    app()
