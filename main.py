#!/usr/bin/env python3
"""
KernelShark Activity Logger - Main entry point for Linux Mint.
Logs user activity, device activity, network activity, and kernel trace to a text file.
Run with sudo for full functionality (audit, trace_pipe, live capture).
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

from logger_utils import load_config, init_log_file, close_log, write_log, CONFIG_PATH

# Import and start each logger
from user_activity import start_user_logger
from device_activity import start_device_logger
from network_activity import start_network_logger
from kernel_trace import start_trace_pipe_logger, run_trace_cmd_report


def main() -> None:
    parser = argparse.ArgumentParser(description="KernelShark activity logger for Linux Mint")
    parser.add_argument("-c", "--config", type=Path, default=CONFIG_PATH, help="Config YAML path")
    parser.add_argument("-o", "--output", type=str, help="Override log file path")
    parser.add_argument("--no-user", action="store_true", help="Disable user activity logging")
    parser.add_argument("--no-device", action="store_true", help="Disable device logging")
    parser.add_argument("--no-network", action="store_true", help="Disable network logging")
    parser.add_argument("--no-kernel", action="store_true", help="Disable kernel trace logging")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print("Config not found:", args.config, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("Config error:", e, file=sys.stderr)
        sys.exit(1)

    log_path = args.output or config.get("log_file", "kernelshark_activity.log")
    max_len = config.get("max_line_length", 0)
    init_log_file(log_path, max_len)
    write_log("SYSTEM", f"KernelShark activity logger started; log_file={log_path}")

    stop = threading.Event()

    def shutdown(signum=None, frame=None) -> None:
        stop.set()
        write_log("SYSTEM", "Shutting down activity logger")
        close_log()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # User activity
    if not args.no_user:
        uc = config.get("user", {})
        start_user_logger(
            audit_log=uc.get("audit_log", "/var/log/audit/audit.log"),
            wtmp_path=uc.get("wtmp_path", "/var/log/wtmp"),
            btmp_path=uc.get("btmp_path", "/var/log/btmp"),
            poll_interval_sec=uc.get("poll_interval_sec", 2),
            stop=stop,
        )

    # Device activity
    if not args.no_device:
        dc = config.get("device", {})
        if dc.get("enabled", True):
            start_device_logger(
                subsystems=dc.get("subsystems", ["input", "block", "usb", "net"]),
                stop=stop,
            )

    # Network activity
    if not args.no_network:
        nc = config.get("network", {})
        if nc.get("enabled", True):
            start_network_logger(
                interface=nc.get("interface", "any"),
                summary_only=nc.get("summary_only", True),
                bpf_filter=nc.get("bpf_filter"),
                packet_batch=nc.get("packet_batch", 50),
                stop=stop,
            )

    # Kernel trace
    if not args.no_kernel:
        kc = config.get("kernel_trace", {})
        if kc.get("enabled", True):
            if kc.get("use_trace_cmd"):
                run_trace_cmd_report(
                    interval_sec=kc.get("trace_cmd_interval_sec", 60),
                    events=kc.get("events"),
                    stop=stop,
                )
            else:
                start_trace_pipe_logger(
                    tracefs=kc.get("tracefs", "/sys/kernel/tracing"),
                    events=kc.get("events"),
                    stop=stop,
                )

    # Keep main thread alive
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass
    shutdown()


if __name__ == "__main__":
    main()
