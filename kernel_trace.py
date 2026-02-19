"""
Kernel activity logger: read from trace_pipe (ftrace) or run trace-cmd and report.
Requires root and tracefs at /sys/kernel/tracing.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional

from logger_utils import write_log


def _enable_events(tracefs: str, events: List[str]) -> bool:
    set_event = Path(tracefs) / "set_event"
    if not set_event.exists():
        return False
    try:
        with open(set_event, "w") as f:
            for e in events:
                f.write(e + "\n")
        return True
    except (PermissionError, OSError):
        return False


def _disable_events(tracefs: str) -> None:
    try:
        set_event = Path(tracefs) / "set_event"
        with open(set_event, "w") as f:
            f.write("disable_all\n")
    except (PermissionError, OSError):
        pass


def start_trace_pipe_logger(
    tracefs: str = "/sys/kernel/tracing",
    events: Optional[List[str]] = None,
    stop: threading.Event = None,
) -> None:
    """Read trace_pipe and write lines to log. Requires root."""
    events = events or ["sched:sched_switch", "block:block_rq_issue"]
    stop = stop or threading.Event()
    trace_pipe = Path(tracefs) / "trace_pipe"
    if not trace_pipe.exists():
        write_log("KERNEL", f"trace_pipe not found at {trace_pipe}; kernel trace disabled")
        return

    def run() -> None:
        if not _enable_events(tracefs, events):
            write_log("KERNEL", "Could not enable trace events (need root?); kernel trace disabled")
            return
        try:
            with open(trace_pipe, "r", encoding="utf-8", errors="replace") as f:
                while not stop.is_set():
                    line = f.readline()
                    if line:
                        write_log("KERNEL", line.rstrip()[:1024])
        except (PermissionError, OSError) as e:
            write_log("KERNEL", f"trace_pipe error: {e}")
        finally:
            _disable_events(tracefs)

    t = threading.Thread(target=run, daemon=True)
    t.start()


def run_trace_cmd_report(
    interval_sec: int = 60,
    events: Optional[List[str]] = None,
    stop: threading.Event = None,
) -> None:
    """
    Periodically run 'trace-cmd record' for interval_sec, then 'trace-cmd report'
    and log a summary. Alternative when trace_pipe is not desired.
    """
    events = events or ["sched:sched_switch", "block:block_rq_issue", "block:block_rq_complete"]
    stop = stop or threading.Event()
    out_dat = "/tmp/kernelshark_trace.dat"

    def run() -> None:
        while not stop.is_set():
            try:
                # trace-cmd record without a command runs until killed; run with sleep to limit duration
                proc = subprocess.Popen(
                    ["trace-cmd", "record", "-e", ",".join(events), "-o", out_dat],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    proc.wait(timeout=interval_sec)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
            except FileNotFoundError:
                if not stop.is_set():
                    write_log("KERNEL", "trace-cmd not found; install trace-cmd")
                break
            except Exception as e:
                if not stop.is_set():
                    write_log("KERNEL", f"trace-cmd record error: {e}")
                continue
            if stop.is_set():
                break
            try:
                r = subprocess.run(
                    ["trace-cmd", "report", "-i", out_dat],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if r.returncode == 0 and r.stdout:
                    for line in r.stdout.strip().split("\n")[:100]:
                        write_log("KERNEL", line[:1024])
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            try:
                os.remove(out_dat)
            except OSError:
                pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
