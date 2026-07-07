from __future__ import annotations

import re
from ipaddress import ip_address, ip_network


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def parse_ports(raw_ports: str) -> list[int]:
    """Parse comma separated ports and ranges such as 22,80,8000-8002."""
    ports: set[int] = set()

    for chunk in raw_ports.split(","):
        token = chunk.strip()
        if not token:
            continue

        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            start = _parse_single_port(start_raw)
            end = _parse_single_port(end_raw)
            if start > end:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(start, end + 1))
            continue

        ports.add(_parse_single_port(token))

    if not ports:
        raise ValueError("At least one port is required.")

    return sorted(ports)


def ports_to_nmap(ports: list[int]) -> str:
    return ",".join(str(port) for port in ports)


def validate_target(target: str) -> str:
    clean_target = target.strip()

    if not clean_target:
        raise ValueError("Target is required.")

    if any(part in clean_target for part in ("://", "*", " ", ",")):
        raise ValueError("Target must be a single IP, CIDR or hostname.")

    try:
        if "/" in clean_target:
            ip_network(clean_target, strict=False)
        else:
            ip_address(clean_target)
        return clean_target
    except ValueError:
        pass

    if not HOSTNAME_RE.match(clean_target):
        raise ValueError("Target must be a valid IP, CIDR or hostname.")

    return clean_target


def _parse_single_port(raw_port: str) -> int:
    try:
        port = int(raw_port.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid port: {raw_port}") from exc

    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range: {port}")

    return port
