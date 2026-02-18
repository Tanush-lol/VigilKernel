"""Compile, load, and dispatch eBPF monitors using BCC."""

from __future__ import annotations

import ctypes as ct
import importlib
import logging
from pathlib import Path
from socket import ntohs
from typing import Any, Callable

from ueba.utils import bytes_to_text, ip_to_str


class ExecEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 128),
    ]


class FileEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("flags", ct.c_int),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
    ]


class NetEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("family", ct.c_ushort),
        ("protocol", ct.c_ubyte),
        ("event_type", ct.c_ubyte),
        ("comm", ct.c_char * 16),
    ]


class PrivEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("event_type", ct.c_ubyte),
        ("arg0", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("detail", ct.c_char * 256),
    ]


_EVENT_TYPE_MAP = {
    1: "connect",
    2: "accept",
    3: "bind",
    4: "listen",
}

_PRIV_EVENT_MAP = {
    1: "setuid",
    2: "capset",
    3: "module_load",
}


class BPFMonitorManager:
    """Lifecycle manager for monitor BPF programs."""

    def __init__(
        self,
        project_root: Path,
        logger: logging.Logger,
        emit_event: Callable[[str, dict[str, Any]], None],
        exclude_comm: list[str],
    ) -> None:
        self.project_root = project_root
        self.logger = logger
        self.emit_event = emit_event
        self.exclude_comm = set(exclude_comm)
        self.bpf_cls = self._resolve_bpf_class()
        self.monitors: list[Any] = []

    @staticmethod
    def _resolve_bpf_class() -> Any:
        try:
            module = importlib.import_module("bcc")
            return getattr(module, "BPF")
        except Exception:
            return None

    def _should_skip(self, comm: str) -> bool:
        return comm in self.exclude_comm

    def load_exec_monitor(self) -> None:
        self._load_monitor("bpf/exec_monitor.c", self._handle_exec)

    def load_file_monitor(self) -> None:
        self._load_monitor("bpf/file_monitor.c", self._handle_file)

    def load_network_monitor(self) -> None:
        self._load_monitor("bpf/net_monitor.c", self._handle_net)

    def load_privilege_monitor(self) -> None:
        self._load_monitor("bpf/priv_monitor.c", self._handle_priv)

    def _load_monitor(self, rel_path: str, callback: Callable[[int, Any, int], None]) -> None:
        source = (self.project_root / rel_path).read_text(encoding="utf-8")
        if self.bpf_cls is None:
            self.logger.warning("BCC Python bindings are unavailable; skipping %s", rel_path)
            return
        try:
            monitor = self.bpf_cls(text=source)
            monitor["events"].open_perf_buffer(callback, page_cnt=64)
            self.monitors.append(monitor)
            self.logger.info("Loaded monitor: %s", rel_path)
        except Exception as exc:
            self.logger.warning("Unable to load %s: %s", rel_path, exc)

    def _handle_exec(self, cpu: int, data: Any, size: int) -> None:
        del cpu, size
        event = ct.cast(data, ct.POINTER(ExecEvent)).contents
        comm = bytes_to_text(event.comm)
        if self._should_skip(comm):
            return
        payload = {
            "pid": event.pid,
            "uid": event.uid,
            "comm": comm,
            "filename": bytes_to_text(event.filename),
        }
        self.emit_event("execve", payload)

    def _handle_file(self, cpu: int, data: Any, size: int) -> None:
        del cpu, size
        event = ct.cast(data, ct.POINTER(FileEvent)).contents
        comm = bytes_to_text(event.comm)
        if self._should_skip(comm):
            return
        payload = {
            "pid": event.pid,
            "uid": event.uid,
            "comm": comm,
            "filename": bytes_to_text(event.filename),
            "flags": event.flags,
        }
        self.emit_event("open", payload)

    def _handle_net(self, cpu: int, data: Any, size: int) -> None:
        del cpu, size
        event = ct.cast(data, ct.POINTER(NetEvent)).contents
        comm = bytes_to_text(event.comm)
        if self._should_skip(comm):
            return
        payload = {
            "pid": event.pid,
            "uid": event.uid,
            "comm": comm,
            "saddr": ip_to_str(event.saddr),
            "daddr": ip_to_str(event.daddr),
            "sport": int(event.sport),
            "dport": ntohs(event.dport),
            "protocol": "TCP" if event.protocol == 6 else str(event.protocol),
            "family": event.family,
        }
        self.emit_event(_EVENT_TYPE_MAP.get(event.event_type, "network_event"), payload)

    def _handle_priv(self, cpu: int, data: Any, size: int) -> None:
        del cpu, size
        event = ct.cast(data, ct.POINTER(PrivEvent)).contents
        comm = bytes_to_text(event.comm)
        if self._should_skip(comm):
            return
        payload = {
            "pid": event.pid,
            "uid": event.uid,
            "comm": comm,
            "arg0": event.arg0,
            "detail": bytes_to_text(event.detail),
        }
        self.emit_event(_PRIV_EVENT_MAP.get(event.event_type, "privilege"), payload)

    def poll(self, timeout_ms: int = 250) -> None:
        for monitor in self.monitors:
            monitor.perf_buffer_poll(timeout=timeout_ms)

    def cleanup(self) -> None:
        self.monitors.clear()
