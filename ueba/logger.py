"""
UEBA event logger: JSON lines to a file with rotation (RotatingFileHandler).
Thread-safe; one log_event() call = one JSON line.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

_lock = threading.Lock()
_handler: Optional[RotatingFileHandler] = None
_logger: Optional[logging.Logger] = None


def init_logger(
    log_path: str,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> str:
    """
    Initialize the UEBA logger. Creates parent dirs and RotatingFileHandler.
    Returns the path actually used (may fallback to current dir if log_path not writable).
    """
    global _handler, _logger

    log_path = os.path.abspath(log_path)
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        _handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    except (PermissionError, OSError) as e:
        # Fallback to current directory
        fallback = Path(__file__).resolve().parent / "ueba_events.log"
        log_path = str(fallback)
        _handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )

    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger = logging.getLogger("ueba")
    _logger.setLevel(logging.INFO)
    _logger.handlers.clear()
    _logger.addHandler(_handler)
    _logger.propagate = False
    return log_path


def log_event(event: Dict[str, Any]) -> None:
    """Append one JSON line (one event) to the log file. Thread-safe."""
    with _lock:
        if _logger is None:
            return
        try:
            line = json.dumps(event, ensure_ascii=False)
            _logger.info(line)
        except (TypeError, ValueError) as e:
            _logger.info(json.dumps({"error": "log_event_serialize", "message": str(e)}))


def close_logger() -> None:
    """Close the file handler."""
    global _handler, _logger
    with _lock:
        if _handler:
            try:
                _handler.close()
            except Exception:
                pass
            _handler = None
        if _logger:
            _logger.handlers.clear()
            _logger = None
