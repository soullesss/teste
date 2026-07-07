from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

from netscanner.models import ScanReport


def render_text_report(report: ScanReport) -> str:
    lines = [
        "NetScanner report",
        f"target: {report.target}",
        f"mode: {report.mode.value}",
        f"arguments: {report.nmap_arguments}",
        f"started_at: {report.started_at.isoformat()}",
        f"finished_at: {report.finished_at.isoformat() if report.finished_at else 'running'}",
        f"findings: {len(report.findings)}",
        f"open: {len(report.open_findings)}",
    ]

    if report.warnings:
        lines.append("")
        lines.append("warnings:")
        lines.extend(f"- {warning}" for warning in report.warnings)

    if report.findings:
        lines.append("")
        lines.append("ports:")
        for finding in report.findings:
            service = finding.service or "unknown"
            version = " ".join(part for part in (finding.product, finding.version) if part)
            detail = f" ({version})" if version else ""
            lines.append(
                f"- {finding.host}:{finding.port}/{finding.protocol} {finding.state} {service}{detail}"
            )

    return "\n".join(lines) + "\n"


def render_json_report(report: ScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def render_csv_report(report: ScanReport) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "host",
            "hostname",
            "protocol",
            "port",
            "state",
            "service",
            "product",
            "version",
            "reason",
        ],
    )
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(finding.model_dump())
    return buffer.getvalue()


def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return render_json_report(report)
    if output_format == "csv":
        return render_csv_report(report)
    return render_text_report(report)


def write_report(report: ScanReport, output_format: str, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_report(report, output_format), encoding="utf-8")
    return output_path
