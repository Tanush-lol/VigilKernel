"""
Shared logging utilities: thread-safe file writer and config loader.
"""
from __future__ import annotations

import os
import threading
import yaml
from pathlib import Path
from typing import Optional

# Default config path
CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"
_lock = threading.Lock()
_log_file_handle: Optional[object] = None
_log_path: Optional[str] = None
_max_line_length: int = 0


def load_config(path: Optional[Path] = None) -> dict:
    path = path or CONFIG_PATH
    with open(path, "r") as f:
        return yaml.safe_load(f)


def init_log_file(log_path: str, max_line_length: int = 0) -> None:
    global _log_file_handle, _log_path, _max_line_length
    with _lock:
        _log_path = log_path
        _max_line_length = max_line_length or 0
        try:
            if _log_file_handle is not None:
                try:
                    _log_file_handle.close()
                except Exception:
                    pass
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            _log_file_handle = open(log_path, "a", encoding="utf-8")
        except PermissionError:
            # Fallback to current directory if no write access to /var/log
            fallback = Path(__file__).resolve().parent / "kernelshark_activity.log"
            _log_path = str(fallback)
            _log_file_handle = open(_log_path, "a", encoding="utf-8")


def write_log(category: str, message: str) -> None:
    """Thread-safe write of a single line with timestamp and category."""
    import time
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{category}] {message}\n"
    if _max_line_length and len(line) > _max_line_length:
        line = line[: _max_line_length - 1] + "\n"
    with _lock:
        if _log_file_handle is not None:
            try:
                _log_file_handle.write(line)
                _log_file_handle.flush()
            except (OSError, ValueError):
                pass


def close_log() -> None:
    global _log_file_handle
    with _lock:
        if _log_file_handle is not None:
            try:
                _log_file_handle.close()
            except Exception:
                pass
            _log_file_handle = None
