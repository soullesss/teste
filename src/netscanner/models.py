from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from netscanner.validation import parse_ports, validate_target


class ScanMode(str, Enum):
    tcp = "tcp"
    service = "service"
    syn = "syn"


class OutputFormat(str, Enum):
    text = "text"
    json = "json"
    csv = "csv"


class ScanRequest(BaseModel):
    target: str
    ports: list[int]
    mode: ScanMode = ScanMode.tcp
    timing: int = Field(default=3, ge=0, le=5)
    authorized: bool = False

    @field_validator("target")
    @classmethod
    def target_must_be_safe(cls, value: str) -> str:
        return validate_target(value)

    @field_validator("ports", mode="before")
    @classmethod
    def ports_must_be_valid(cls, value: str | list[int]) -> list[int]:
        if isinstance(value, str):
            return parse_ports(value)
        return parse_ports(",".join(str(port) for port in value))


class NmapPlan(BaseModel):
    target: str
    ports: list[int]
    mode: ScanMode
    nmap_arguments: str
    command_preview: str
    privileged: bool
    warnings: list[str] = Field(default_factory=list)


class ScanFinding(BaseModel):
    host: str
    hostname: str | None = None
    protocol: str
    port: int
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    reason: str | None = None


class ScanReport(BaseModel):
    target: str
    mode: ScanMode
    nmap_arguments: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    findings: list[ScanFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def complete(self) -> "ScanReport":
        self.finished_at = datetime.now(timezone.utc)
        return self

    @property
    def open_findings(self) -> list[ScanFinding]:
        return [finding for finding in self.findings if finding.state == "open"]


class ExportRequest(BaseModel):
    output_format: OutputFormat
    output_path: Path | None = None
