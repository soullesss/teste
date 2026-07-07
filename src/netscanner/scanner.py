from __future__ import annotations

import shutil
from typing import Any

from loguru import logger

from netscanner.errors import AuthorizationError, DependencyError, ScanExecutionError
from netscanner.models import NmapPlan, ScanFinding, ScanMode, ScanReport, ScanRequest
from netscanner.security import has_admin_privileges
from netscanner.validation import ports_to_nmap


def build_nmap_plan(request: ScanRequest, privileged: bool | None = None) -> NmapPlan:
    is_privileged = has_admin_privileges() if privileged is None else privileged
    warnings: list[str] = []
    timing = f"-T{request.timing}"

    if request.mode == ScanMode.syn:
        if is_privileged:
            arguments = f"-sS -sV {timing} --reason"
        else:
            arguments = f"-sT -sV {timing} --reason"
            warnings.append("SYN scan requires elevated privileges. Falling back to TCP connect.")
    elif request.mode == ScanMode.service:
        arguments = f"-sT -sV --version-light {timing} --reason"
    else:
        arguments = f"-sT {timing} --reason"

    port_text = ports_to_nmap(request.ports)

    return NmapPlan(
        target=request.target,
        ports=request.ports,
        mode=request.mode,
        nmap_arguments=arguments,
        command_preview=f"nmap {arguments} -p {port_text} {request.target}",
        privileged=is_privileged,
        warnings=warnings,
    )


class NmapScanner:
    def __init__(self, scanner: Any | None = None) -> None:
        self._scanner = scanner

    @staticmethod
    def dependency_status() -> dict[str, bool]:
        python_nmap_available = True
        try:
            import nmap  # noqa: F401
        except ImportError:
            python_nmap_available = False

        return {
            "nmap_binary": shutil.which("nmap") is not None,
            "python_nmap": python_nmap_available,
        }

    def scan(self, request: ScanRequest) -> ScanReport:
        if not request.authorized:
            raise AuthorizationError("Real scan blocked. Add --i-have-authorization after confirming scope.")

        status = self.dependency_status()
        if not status["nmap_binary"]:
            raise DependencyError("Nmap binary not found in PATH. Install it with brew or apt.")
        if not status["python_nmap"]:
            raise DependencyError("python-nmap is not installed. Run: python -m pip install -e .")

        plan = build_nmap_plan(request)
        report = ScanReport(
            target=request.target,
            mode=request.mode,
            nmap_arguments=plan.nmap_arguments,
            warnings=plan.warnings,
        )

        for warning in plan.warnings:
            logger.warning(warning)

        logger.info("Starting scan: {}", plan.command_preview)

        try:
            scanner = self._scanner or _new_port_scanner()
            scanner.scan(
                hosts=request.target,
                ports=ports_to_nmap(request.ports),
                arguments=plan.nmap_arguments,
            )
        except Exception as exc:
            raise ScanExecutionError(f"Nmap execution failed: {exc}") from exc

        report.findings = _parse_nmap_results(scanner)
        report.complete()
        logger.info("Scan finished: {} findings, {} open", len(report.findings), len(report.open_findings))
        return report


def _new_port_scanner() -> Any:
    import nmap

    return nmap.PortScanner()


def _parse_nmap_results(scanner: Any) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    for host in scanner.all_hosts():
        hostnames = scanner[host].hostnames() if hasattr(scanner[host], "hostnames") else []
        hostname = hostnames[0]["name"] if hostnames else None

        for protocol in scanner[host].all_protocols():
            for port in sorted(scanner[host][protocol].keys()):
                port_info = scanner[host][protocol][port]
                findings.append(
                    ScanFinding(
                        host=host,
                        hostname=hostname,
                        protocol=protocol,
                        port=int(port),
                        state=port_info.get("state", "unknown"),
                        service=port_info.get("name"),
                        product=port_info.get("product") or None,
                        version=port_info.get("version") or None,
                        reason=port_info.get("reason") or None,
                    )
                )

    return findings
