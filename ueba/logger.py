"""JSON-lines logger with rotation for UEBA events."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_LOGGER_NAME = "ueba"


def setup_logger(path: str, max_size_mb: int, backups: int) -> logging.Logger:
    """Configure JSON logger with file rotation."""
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backups,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def log_event(logger: logging.Logger, event_type: str, data: dict[str, Any]) -> None:
    """Emit a single structured event as JSON-lines."""
    payload = {
        "@timestamp": datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds"),
        "event_type": event_type,
        **data,
    }
    logger.info(json.dumps(payload, separators=(",", ":"), default=str))
