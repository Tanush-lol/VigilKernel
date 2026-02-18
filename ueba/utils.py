"""Shared utility helpers."""

from __future__ import annotations

import ipaddress
from pathlib import Path


def get_process_name(pid: int) -> str:
    """Best-effort process name lookup from /proc."""
    comm_path = Path(f"/proc/{pid}/comm")
    try:
        return comm_path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


def ip_to_str(ip_addr: int) -> str:
    """Convert an IPv4 integer to dotted notation."""
    return str(ipaddress.IPv4Address(ip_addr))


def bytes_to_text(raw: bytes) -> str:
    """Decode null-terminated C strings safely."""
    return raw.split(b"\x00", maxsplit=1)[0].decode("utf-8", errors="replace")
