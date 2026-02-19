"""
User activity logger: audit log tailing and login/failure events.
Requires read access to /var/log/audit/audit.log and /var/log/wtmp (often root).
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from logger_utils import write_log


def _tail_file(path: str, interval: float, callback: Callable[[str], None], stop: threading.Event) -> None:
    """Tail a file and call callback for each new line."""
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            while not stop.is_set():
                line = f.readline()
                if line:
                    callback(line.rstrip())
                else:
                    time.sleep(interval)
    except (PermissionError, FileNotFoundError, OSError):
        pass


def _parse_audit_line(line: str) -> Optional[str]:
    """Reduce audit line to a short human-readable message."""
    if not line.strip():
        return None
    # type=... msg=... key=...
    out = []
    for part in line.split():
        if part.startswith("type="):
            out.append(part.replace("type=", ""))
        elif part.startswith("msg="):
            out.append(part[4:].strip("()"))
        elif part.startswith("key="):
            out.append("key=" + part[4:])
        elif part.startswith("comm="):
            out.append("comm=" + part[5:].strip('"'))
        elif part.startswith("exe="):
            out.append("exe=" + part[4:].strip('"'))
        elif part.startswith("uid=") or part.startswith("auid="):
            out.append(part)
    return " ".join(out) if out else line[:500]


def _run_last(path: str, num: int) -> list[str]:
    """Run 'last -f <path> -n <num>' and return lines (for wtmp/btmp)."""
    try:
        r = subprocess.run(
            ["last", "-f", path, "-n", str(num)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout:
            return [l for l in r.stdout.strip().split("\n") if l]
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass
    return []


def start_user_logger(
    audit_log: str,
    wtmp_path: str,
    btmp_path: str,
    poll_interval_sec: float,
    stop: threading.Event,
) -> None:
    """Start background thread that tails audit log and optionally logs recent logins/failures."""
    def on_audit_line(line: str) -> None:
        msg = _parse_audit_line(line)
        if msg:
            write_log("USER", msg)

    def run() -> None:
        # Initial dump of recent logins and failures (once)
        for label, p in [("login", wtmp_path), ("failed_login", btmp_path)]:
            if os.path.isfile(p):
                for l in _run_last(p, 5):
                    write_log("USER", f"{label}: {l[:400]}")

        # Tail audit log
        _tail_file(audit_log, poll_interval_sec, on_audit_line, stop)

    t = threading.Thread(target=run, daemon=True)
    t.start()
