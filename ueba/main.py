#!/usr/bin/env python3
"""
UEBA daemon: User and Entity Behavior Analytics at kernel level.
Monitors exec, file open, network (connect/bind/listen), user sessions, audit, block devices.
Writes JSON lines to a rotating log file. Requires root. Uses BCC for eBPF.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

# Run from ueba/ so that imports work
UEBA_ROOT = Path(__file__).resolve().parent
if str(UEBA_ROOT) not in sys.path:
    sys.path.insert(0, str(UEBA_ROOT))

from config_parser import load_config, DEFAULT_CONFIG_PATH
from logger import init_logger, log_event, close_logger
from utils import iso_timestamp

# Optional BCC loaders
try:
    from ebpf.load_bpf import load_exec_monitor, load_file_monitor, load_net_monitor
except ImportError:
    load_exec_monitor = load_file_monitor = load_net_monitor = None  # type: ignore

from sources.user_session import start_user_session_source
from sources.audit_tail import start_audit_tail_source
from sources.block_udev import start_block_udev_source


def _check_root() -> None:
    if os.geteuid() != 0:
        print("This daemon must run as root (e.g. sudo) for eBPF and log access.", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="UEBA kernel-level activity logger")
    parser.add_argument("--config", "-c", type=Path, default=DEFAULT_CONFIG_PATH, help="Config YAML path")
    parser.add_argument("--no-ebpf", action="store_true", help="Disable eBPF monitors (exec, file, net)")
    args = parser.parse_args()

    _check_root()

    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("Config error:", e, file=sys.stderr)
        sys.exit(1)

    log_cfg = config["logging"]
    log_path = init_logger(
        log_path=log_cfg["path"],
        max_bytes=log_cfg.get("max_bytes", 10 * 1024 * 1024),
        backup_count=log_cfg.get("backup_count", 5),
    )
    print(f"UEBA logging to {log_path}", file=sys.stderr)

    log_event({
        "@timestamp": iso_timestamp(),
        "event_type": "ueba_start",
        "message": "UEBA daemon started",
        "log_path": log_path,
    })

    stop = threading.Event()
    bpf_instances = []

    def shutdown(signum=None, frame=None) -> None:
        stop.set()
        log_event({"@timestamp": iso_timestamp(), "event_type": "ueba_stop", "message": "UEBA daemon stopped"})
        close_logger()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    monitors = config.get("monitors", {})
    net_cfg = config.get("network_filter", {})

    # --- eBPF monitors ---
    if not args.no_ebpf and load_exec_monitor and monitors.get("exec", True):
        try:
            bpf_exec, _ = load_exec_monitor(on_event=log_event)
            if bpf_exec:
                bpf_instances.append(bpf_exec)
        except Exception as e:
            log_event({"@timestamp": iso_timestamp(), "event_type": "error", "message": f"exec_monitor: {e}"})

    if not args.no_ebpf and load_file_monitor and monitors.get("file", True):
        try:
            bpf_file, _ = load_file_monitor(on_event=log_event)
            if bpf_file:
                bpf_instances.append(bpf_file)
        except Exception as e:
            log_event({"@timestamp": iso_timestamp(), "event_type": "error", "message": f"file_monitor: {e}"})

    if not args.no_ebpf and load_net_monitor and monitors.get("network", True):
        try:
            bpf_net, _ = load_net_monitor(
                on_event=log_event,
                include_connect=net_cfg.get("include_connect", True),
                include_bind=net_cfg.get("include_bind", True),
                include_listen=net_cfg.get("include_listen", True),
            )
            if bpf_net:
                bpf_instances.append(bpf_net)
        except Exception as e:
            log_event({"@timestamp": iso_timestamp(), "event_type": "error", "message": f"net_monitor: {e}"})

    # --- User-space sources ---
    if monitors.get("user_session", True):
        us = config.get("user_session", {})
        start_user_session_source(
            wtmp_path=us.get("wtmp", "/var/log/wtmp"),
            btmp_path=us.get("btmp", "/var/log/btmp"),
            poll_interval_sec=us.get("poll_interval_sec", 3),
            on_event=log_event,
            stop=stop,
        )

    if monitors.get("audit", True):
        ac = config.get("audit", {})
        start_audit_tail_source(
            audit_log_path=ac.get("log_path", "/var/log/audit/audit.log"),
            poll_interval_sec=ac.get("poll_interval_sec", 2),
            on_event=log_event,
            stop=stop,
        )

    if monitors.get("block", True):
        bc = config.get("block", {})
        start_block_udev_source(
            subsystems=bc.get("udev_subsystems", ["block", "usb"]),
            on_event=log_event,
            stop=stop,
        )

    # --- Poll perf buffers and keep alive ---
    try:
        while not stop.is_set():
            for bpf in bpf_instances:
                try:
                    bpf.perf_buffer_poll(timeout=100)
                except Exception:
                    pass
    except KeyboardInterrupt:
        pass
    shutdown()


if __name__ == "__main__":
    main()
