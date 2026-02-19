"""
Tail audit log and emit critical events (privilege escalation, module load, etc.) as JSON.
"""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Callable

from utils import iso_timestamp


def _parse_audit_to_dict(line: str) -> dict:
    """Parse a single audit line into key=value dict."""
    out = {}
    for part in line.split():
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v.strip('"')
    return out


def start_audit_tail_source(
    audit_log_path: str,
    poll_interval_sec: float,
    on_event: Callable[[dict], None],
    stop: threading.Event,
) -> None:
    """Background thread: tail audit log and emit events."""
    if not os.path.isfile(audit_log_path):
        return

    def run() -> None:
        try:
            with open(audit_log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                while not stop.is_set():
                    line = f.readline()
                    if line:
                        line = line.rstrip()
                        if not line:
                            continue
                        d = _parse_audit_to_dict(line)
                        typ = d.get("type", "")
                        # Emit notable types
                        if typ in ("USER_AUTH", "USER_LOGIN", "USER_START", "CRED_ACQ", "SYSCALL", "EXECVE", "MODULE_LOAD", "KERNEL_OTHER"):
                            on_event({
                                "@timestamp": iso_timestamp(),
                                "event_type": "audit",
                                "audit_type": typ,
                                "pid": d.get("pid"),
                                "uid": d.get("uid"),
                                "auid": d.get("auid"),
                                "comm": d.get("comm"),
                                "exe": d.get("exe"),
                                "msg": d.get("msg"),
                                "raw": line[:1000],
                            })
                    else:
                        time.sleep(poll_interval_sec)
        except (PermissionError, FileNotFoundError, OSError):
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
