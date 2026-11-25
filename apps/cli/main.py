"""VEXReach CLI main entry point powered by Typer and Rich."""

import platform
import shutil
import sys
from typing import Annotated, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from packages.core import __version__
from packages.core.config.settings import get_settings
from packages.core.utils.logging import get_logger, setup_logging

app = typer.Typer(
    name="vexreach",
    help="AI-Assisted, Kubernetes-Native Vulnerability Intelligence Platform",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
logger = get_logger("cli")


@app.callback()
def main_callback(
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
    log_level = "DEBUG" if verbose else get_settings().log_level
    log_format = "json" if json_logs else get_settings().log_format
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
    table.add_row("Operating System", f"{platform.system()} {platform.release()} ({platform.machine()})")
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
        table.add_row("Python Runtime", "[green]OK[/green]", f"{py_ver.major}.{py_ver.minor}.{py_ver.micro} (>= 3.12)")
    else:
        table.add_row("Python Runtime", "[red]UNSUPPORTED[/red]", f"Found {py_ver.major}.{py_ver.minor}, requires >= 3.12")

    # Git check
    git_bin = shutil.which("git")
    if git_bin:
        table.add_row("Git CLI", "[green]FOUND[/green]", git_bin)
    else:
        table.add_row("Git CLI", "[yellow]MISSING[/yellow]", "Recommended for repository and patch tracking")

    # Docker check
    docker_bin = shutil.which("docker")
    if docker_bin:
        table.add_row("Docker Engine", "[green]FOUND[/green]", docker_bin)
    else:
        table.add_row("Docker Engine", "[yellow]NOT FOUND[/yellow]", "Required later for containerized scans & sandbox tests")

    # Trivy check
    trivy_bin = shutil.which("trivy")
    if trivy_bin:
        table.add_row("Trivy Scanner", "[green]FOUND[/green]", trivy_bin)
    else:
        table.add_row("Trivy Scanner", "[yellow]NOT FOUND[/yellow]", "Can be installed via choco/docker for Discovery Engine (Phase 3)")

    # Storage directory validation
    storage_dir = settings.storage_path.parent
    table.add_row("Database Path", "[green]CONFIGURED[/green]", str(settings.storage_path))

    console.print(table)
    console.print("\n[bold green]Configuration validation complete.[/bold green]")


if __name__ == "__main__":
    app()
