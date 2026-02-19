"""
Load and validate UEBA config from YAML.
Returns a dictionary; handles missing file and basic schema.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

# Default config path
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "config.yaml"


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config.yaml and return a dictionary. Raises FileNotFoundError if missing."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Config not found: {path}")

    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML required: pip install PyYAML")

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        config = {}

    # Ensure expected top-level keys exist with defaults
    config.setdefault("logging", {})
    config["logging"].setdefault("path", "/var/log/ueba/events.log")
    config["logging"].setdefault("max_bytes", 10 * 1024 * 1024)
    config["logging"].setdefault("backup_count", 5)

    config.setdefault("monitors", {})
    for key in ["exec", "file", "network", "user_session", "block", "audit"]:
        config["monitors"].setdefault(key, True)

    config.setdefault("exec_filter", {}).setdefault("path_prefix", [])
    config.setdefault("file_filter", {}).setdefault("path_prefix", [])
    config["file_filter"].setdefault("log_libraries", True)
    config.setdefault("network_filter", {})
    for k in ["include_listen", "include_connect", "include_accept", "include_bind"]:
        config["network_filter"].setdefault(k, True)
    config.setdefault("user_session", {}).setdefault("wtmp", "/var/log/wtmp")
    config["user_session"].setdefault("utmp", "/var/run/utmp")
    config["user_session"].setdefault("btmp", "/var/log/btmp")
    config["user_session"].setdefault("poll_interval_sec", 3)
    config.setdefault("audit", {}).setdefault("log_path", "/var/log/audit/audit.log")
    config["audit"].setdefault("poll_interval_sec", 2)
    config.setdefault("block", {}).setdefault("udev_subsystems", ["block", "usb"])
    config["block"].setdefault("trace_block_io", False)

    return config
