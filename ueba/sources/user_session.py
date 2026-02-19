"""
User session and login events: tail wtmp, btmp, utmp (user-space).
Emits JSON events for logins, logouts, failed logins.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from typing import Callable, Optional

from utils import iso_timestamp


def _run_last(path: str, num: int) -> list:
    try:
        r = subprocess.run(
            ["last", "-f", path, "-n", str(num)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout:
            lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
            # Filter out footer lines like "wtmp begins ..." / "btmp begins ..."
            return [l for l in lines if not l.startswith("wtmp begins") and not l.startswith("btmp begins")]
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        pass
    return []


def start_user_session_source(
    wtmp_path: str,
    btmp_path: str,
    poll_interval_sec: float,
    on_event: Callable[[dict], None],
    stop: threading.Event,
) -> None:
    """Background thread: periodically run 'last' on wtmp/btmp and emit login events."""
    last_wtmp: list = []
    last_btmp: list = []

    def run() -> None:
        nonlocal last_wtmp, last_btmp
        # Initial dump
        if os.path.isfile(wtmp_path):
            for line in _run_last(wtmp_path, 20):
                on_event({
                    "@timestamp": iso_timestamp(),
                    "event_type": "login",
                    "source": "wtmp",
                    "message": line[:500],
                })
                last_wtmp.append(line)
        if os.path.isfile(btmp_path):
            for line in _run_last(btmp_path, 20):
                on_event({
                    "@timestamp": iso_timestamp(),
                    "event_type": "failed_login",
                    "source": "btmp",
                    "message": line[:500],
                })
                last_btmp.append(line)

        while not stop.is_set():
            time.sleep(poll_interval_sec)
            if stop.is_set():
                break
            if os.path.isfile(wtmp_path):
                current = _run_last(wtmp_path, 10)
                for line in current:
                    if line not in last_wtmp:
                        on_event({
                            "@timestamp": iso_timestamp(),
                            "event_type": "login",
                            "source": "wtmp",
                            "message": line[:500],
                        })
                last_wtmp = current[:30]
            if os.path.isfile(btmp_path):
                current = _run_last(btmp_path, 10)
                for line in current:
                    if line not in last_btmp:
                        on_event({
                            "@timestamp": iso_timestamp(),
                            "event_type": "failed_login",
                            "source": "btmp",
                            "message": line[:500],
                        })
                last_btmp = current[:30]

    t = threading.Thread(target=run, daemon=True)
    t.start()
