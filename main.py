"""Entry point for the kernel-level UEBA daemon."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

from ueba.bpf_loader import BPFMonitorManager
from ueba.config_parser import load_config
from ueba.logger import log_event, setup_logger
from ueba.user_activity import UserActivityMonitor

RUNNING = True


def _handle_signal(signum: int, frame: object) -> None:
    del signum, frame
    global RUNNING
    RUNNING = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kernel-level UEBA daemon")
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to UEBA config file",
    )
    return parser.parse_args()


def require_root() -> None:
    if os.geteuid() != 0:
        print("This program must run as root to load eBPF monitors.", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    require_root()
    args = parse_args()
    config = load_config(args.config)

    app_logger = setup_logger(
        path=config["logging"]["path"],
        max_size_mb=int(config["logging"]["max_size_mb"]),
        backups=int(config["logging"]["backups"]),
    )

    manager = BPFMonitorManager(
        project_root=Path(__file__).resolve().parent,
        logger=app_logger,
        emit_event=lambda event_type, payload: log_event(app_logger, event_type, payload),
        exclude_comm=config.get("filters", {}).get("exclude_comm", []),
    )

    monitors = config.get("monitors", {})
    if monitors.get("process_exec", True):
        manager.load_exec_monitor()
    if monitors.get("file_open", True):
        manager.load_file_monitor()
    if monitors.get("network", True):
        manager.load_network_monitor()
    if monitors.get("privilege_events", True):
        manager.load_privilege_monitor()

    user_monitor: UserActivityMonitor | None = None
    if monitors.get("user_activity", True):
        user_monitor = UserActivityMonitor(interval_seconds=30)
        user_monitor.start(lambda event_type, data: log_event(app_logger, event_type, data), app_logger)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    app_logger.info("UEBA started")
    while RUNNING:
        try:
            manager.poll(timeout_ms=500)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            logging.getLogger("ueba").warning("poll error: %s", exc)

    if user_monitor:
        user_monitor.stop()
    manager.cleanup()
    app_logger.info("UEBA stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
