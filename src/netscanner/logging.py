from __future__ import annotations

import re
import sys
from pathlib import Path

from loguru import logger


SECRET_RE = re.compile(
    r"(?i)(token|secret|password|passwd|api[_-]?key|authorization)=([^\s]+)"
)


def redact(value: str) -> str:
    return SECRET_RE.sub(r"\1=[redacted]", value)


def setup_logging(level: str = "INFO", log_dir: str = "logs") -> None:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        colorize=True,
    )
    logger.add(
        log_path / "netscanner_{time:YYYY-MM-DD}.jsonl",
        level="DEBUG",
        serialize=True,
        rotation="10 MB",
        retention="7 days",
        enqueue=True,
    )

    logger.debug("Logging configured", log_dir=str(log_path), level=level.upper())
