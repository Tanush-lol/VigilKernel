"""
Block and USB device activity (udev): external drives, data migration, device connect/disconnect.
Emits JSON events for add/remove/change.
"""
from __future__ import annotations

import threading
from typing import Callable, List

from utils import iso_timestamp

try:
    import pyudev
except ImportError:
    pyudev = None


def _device_info(device) -> dict:
    return {
        "action": device.action or "change",
        "subsystem": device.subsystem or "",
        "devtype": device.device_type or "",
        "sys_name": device.sys_name or "",
        "devnode": device.device_node or "",
        "id_vendor": device.get("ID_VENDOR") or device.get("ID_VENDOR_ID") or "",
        "id_model": device.get("ID_MODEL") or device.get("ID_MODEL_ID") or "",
        "id_serial": device.get("ID_SERIAL_SHORT") or device.get("ID_SERIAL") or "",
        "id_fs_type": device.get("ID_FS_TYPE") or "",
        "id_fs_label": device.get("ID_FS_LABEL") or "",
    }


def start_block_udev_source(
    subsystems: List[str],
    on_event: Callable[[dict], None],
    stop: threading.Event,
) -> None:
    """Background thread: udev monitor for block/usb (disks, external drives)."""
    if pyudev is None:
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
            for device in monitor:
                if stop.is_set():
                    break
                if allowed and (device.subsystem or "") not in allowed:
                    continue
                try:
                    info = _device_info(device)
                    on_event({
                        "@timestamp": iso_timestamp(),
                        "event_type": "device",
                        "device_action": info["action"],
                        "subsystem": info["subsystem"],
                        "devnode": info["devnode"],
                        "id_vendor": info["id_vendor"],
                        "id_model": info["id_model"],
                        "id_serial": info["id_serial"],
                        "id_fs_type": info["id_fs_type"],
                        "id_fs_label": info["id_fs_label"],
                    })
                except Exception:
                    pass
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
