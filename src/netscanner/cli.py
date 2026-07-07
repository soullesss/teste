from __future__ import annotations

from pathlib import Path

import click
from loguru import logger
from pydantic import ValidationError

from netscanner.errors import AuthorizationError, DependencyError, NetScannerError
from netscanner.exporters import render_report, write_report
from netscanner.logging import setup_logging
from netscanner.models import ScanMode, ScanRequest
from netscanner.scanner import NmapScanner, build_nmap_plan
from netscanner.security import authorization_note


SCAN_MODES = [mode.value for mode in ScanMode]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option()
def cli() -> None:
    """Defensive network audit CLI powered by Nmap."""


@cli.command()
def check() -> None:
    """Check local dependencies without scanning anything."""
    status = NmapScanner.dependency_status()
    click.echo("NetScanner environment")
    click.echo(f"- nmap binary: {'ok' if status['nmap_binary'] else 'missing'}")
    click.echo(f"- python-nmap: {'ok' if status['python_nmap'] else 'missing'}")
    click.echo(f"- safety: {authorization_note()}")

    if not all(status.values()):
        raise click.ClickException("Environment is not ready for real scans.")


@cli.command()
@click.option("--target", required=True, help="IP, CIDR or hostname inside your authorized scope.")
@click.option("--ports", default="22,80,443", show_default=True, help="Ports or ranges, for example 22,80,8000-8005.")
@click.option("--mode", type=click.Choice(SCAN_MODES), default="tcp", show_default=True)
@click.option("--timing", type=click.IntRange(0, 5), default=3, show_default=True)
def plan(target: str, ports: str, mode: str, timing: int) -> None:
    """Build the Nmap command plan without running it."""
    request = _build_request(target, ports, mode, timing, authorized=True)
    scan_plan = build_nmap_plan(request)

    click.echo("NetScanner plan")
    click.echo(f"- target: {scan_plan.target}")
    click.echo(f"- ports: {','.join(str(port) for port in scan_plan.ports)}")
    click.echo(f"- mode: {scan_plan.mode.value}")
    click.echo(f"- privileged: {'yes' if scan_plan.privileged else 'no'}")
    click.echo(f"- command: {scan_plan.command_preview}")
    for warning in scan_plan.warnings:
        click.echo(f"- warning: {warning}")


@cli.command()
@click.option("--target", required=True, help="IP, CIDR or hostname inside your authorized scope.")
@click.option("--ports", default="22,80,443", show_default=True, help="Ports or ranges, for example 22,80,8000-8005.")
@click.option("--mode", type=click.Choice(SCAN_MODES), default="tcp", show_default=True)
@click.option("--timing", type=click.IntRange(0, 5), default=3, show_default=True)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "csv"]), default="text", show_default=True)
@click.option("--output", type=click.Path(path_type=Path), help="Optional output file.")
@click.option("--log-dir", type=click.Path(path_type=Path), default=Path("logs"), show_default=True)
@click.option("--log-level", default="INFO", show_default=True)
@click.option("--i-have-authorization", is_flag=True, help="Required for real scan execution.")
def scan(
    target: str,
    ports: str,
    mode: str,
    timing: int,
    output_format: str,
    output: Path | None,
    log_dir: Path,
    log_level: str,
    i_have_authorization: bool,
) -> None:
    """Run an authorized Nmap scan and export the result."""
    setup_logging(level=log_level, log_dir=str(log_dir))
    request = _build_request(target, ports, mode, timing, authorized=i_have_authorization)

    try:
        report = NmapScanner().scan(request)
    except AuthorizationError as exc:
        raise click.ClickException(str(exc)) from exc
    except DependencyError as exc:
        raise click.ClickException(str(exc)) from exc
    except NetScannerError as exc:
        logger.error("Scan failed: {}", exc)
        raise click.ClickException(str(exc)) from exc

    if output:
        path = write_report(report, output_format, output)
        click.echo(f"Wrote {output_format} report to {path}")
    else:
        click.echo(render_report(report, output_format), nl=False)


def _build_request(target: str, ports: str, mode: str, timing: int, authorized: bool) -> ScanRequest:
    try:
        return ScanRequest(
            target=target,
            ports=ports,
            mode=ScanMode(mode),
            timing=timing,
            authorized=authorized,
        )
    except (ValidationError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
