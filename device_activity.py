"""
Device activity logger: udev monitor for plug/unplug and device changes.
"""
from __future__ import annotations

import threading
from typing import List, Set

from logger_utils import write_log

try:
    import pyudev
except ImportError:
    pyudev = None


def _device_summary(device: "pyudev.Device") -> str:
    action = device.action or "change"
    subsys = device.subsystem or ""
    devtype = device.device_type or ""
    name = device.sys_name or ""
    devnode = device.device_node or ""
    vendor = device.get("ID_VENDOR_ID") or device.get("ID_VENDOR") or ""
    model = device.get("ID_MODEL_ID") or device.get("ID_MODEL") or ""
    serial = device.get("ID_SERIAL_SHORT") or device.get("ID_SERIAL") or ""
    parts = [f"action={action}", f"subsystem={subsys}"]
    if devtype:
        parts.append(f"devtype={devtype}")
    if name:
        parts.append(f"sys_name={name}")
    if devnode:
        parts.append(f"node={devnode}")
    if vendor or model:
        parts.append(f"vendor={vendor} model={model}")
    if serial:
        parts.append(f"serial={serial}")
    return " ".join(parts)


def start_device_logger(subsystems: List[str], stop: threading.Event) -> None:
    """Start udev monitor in a background thread."""
    if pyudev is None:
        write_log("DEVICE", "pyudev not installed; device monitoring disabled")
        return

    def run() -> None:
        try:
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            allowed = set(subsystems) if subsystems else None
            if allowed and len(allowed) == 1:
                try:
                    monitor.filter_by(subsystem=subsystems[0])
                except (ValueError, OSError):
                    pass
            monitor.start()
            # If multiple subsystems, we didn't set a filter; filter in loop
            for device in monitor:
                if allowed and (device.subsystem or "") not in allowed:
                    continue
                if stop.is_set():
                    break
                try:
                    msg = _device_summary(device)
                    write_log("DEVICE", msg)
                except Exception:
                    pass
        except Exception as e:
            write_log("DEVICE", f"udev monitor error: {e}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
