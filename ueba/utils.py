"""
Utility functions for UEBA: process name, IP formatting, timestamp, etc.
"""
from __future__ import annotations

import os
import socket
import struct
from pathlib import Path
from typing import Optional

# Try to read process info; may fail without CAP_SYS_PTRACE or root
def get_process_name(pid: int) -> str:
    """Return process name (comm) for pid, or empty string on error."""
    if pid <= 0:
        return ""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip() or ""
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def get_process_cmdline(pid: int, max_len: int = 256) -> str:
    """Return /proc/<pid>/cmdline as a single string, truncated."""
    if pid <= 0:
        return ""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read(max_len)
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip() or ""
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def ip_to_str(ip_bytes: bytes, ip_version: int = 4) -> str:
    """Convert 4-byte (IPv4) or 16-byte (IPv6) to string."""
    if not ip_bytes:
        return ""
    if ip_version == 4 and len(ip_bytes) >= 4:
        return socket.inet_ntop(socket.AF_INET, ip_bytes[:4])
    if ip_version == 6 and len(ip_bytes) >= 16:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes[:16])
    return ""


def ip_from_uint32(addr: int) -> str:
    """Convert 32-bit big-endian IPv4 to string."""
    try:
        return socket.inet_ntoa(struct.pack(">I", addr & 0xFFFFFFFF))
    except Exception:
        return str(addr)


def iso_timestamp() -> str:
    """Current time in ISO8601 with milliseconds."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def safe_str(b: bytes, encoding: str = "utf-8", max_len: int = 512) -> str:
    """Decode bytes to string, replace errors, truncate."""
    if not b:
        return ""
    s = b.decode(encoding, errors="replace").strip()
    for c in "\x00\r\n":
        s = s.replace(c, " ")
    if len(s) > max_len:
        s = s[:max_len]
    return s
