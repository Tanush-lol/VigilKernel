"""Configuration loading for the UEBA daemon."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "monitors": {
        "process_exec": True,
        "file_open": True,
        "network": True,
        "user_activity": True,
        "privilege_events": True,
    },
    "logging": {
        "path": "/var/log/ueba/events.log",
        "max_size_mb": 50,
        "backups": 5,
    },
    "filters": {"exclude_comm": []},
}


def load_config(config_path: str) -> dict[str, Any]:
    """Load YAML config and merge with defaults."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    merged = DEFAULT_CONFIG.copy()
    for section, value in loaded.items():
        if isinstance(value, dict) and isinstance(merged.get(section), dict):
            merged[section] = {**merged[section], **value}
        else:
            merged[section] = value

    return merged
