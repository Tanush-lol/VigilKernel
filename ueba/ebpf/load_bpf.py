"""
Load eBPF programs (exec, file, net) using BCC and attach perf buffer callbacks.
Each loader returns (bpf_instance, attach_list) so main can detach on exit.
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# BCC is optional; fail gracefully with clear message
try:
    from bcc import BPF
except ImportError:
    BPF = None  # type: ignore

# Base path for .c files
EBPF_DIR = Path(__file__).resolve().parent


def _read_c(path: Path) -> str:
    with open(path, "r") as f:
        return f.read()


def load_exec_monitor(
    on_event: Callable[[Dict[str, Any]], None],
) -> Tuple[Optional[Any], List[Any]]:
    """Load exec_monitor.c, attach kprobe to execve, return (BPF object, attach list)."""
    if BPF is None:
        return None, []

    src = _read_c(EBPF_DIR / "exec_monitor.c")
    try:
        bpf = BPF(text=src)
    except Exception as e:
        sys.stderr.write(f"exec_monitor BPF load failed: {e}\n")
        return None, []

    # Kernel 4.17+ uses __x64_sys_execve; older use sys_execve
    exec_symbols = ["__x64_sys_execve", "sys_execve", "__ia32_sys_execve"]
    attached = []
    for sym in exec_symbols:
        try:
            bpf.attach_kprobe(event=sym, fn_name="trace_execve_entry")
            attached.append(("kprobe", sym, "trace_execve_entry"))
            break
        except Exception:
            continue
    if not attached:
        sys.stderr.write("exec_monitor: could not attach to any execve symbol\n")
        return bpf, []

    def _perf_cb(cpu: int, data: bytes, size: int) -> None:
        if size < 4 + 4 + 16 + 256 + 256:
            return
        # C struct: u64 ts, u32 pid, u32 uid, char comm[16], char filename[256], char argv[256]
        ts = struct.unpack_from("Q", data, 0)[0]
        pid = struct.unpack_from("I", data, 8)[0]
        uid = struct.unpack_from("I", data, 12)[0]
        comm = data[16:32].split(b"\x00")[0].decode("utf-8", errors="replace")
        filename = data[32:288].split(b"\x00")[0].decode("utf-8", errors="replace")
        argv = data[288:544].split(b"\x00")[0].decode("utf-8", errors="replace")
        on_event({
            "@timestamp": _ns_to_iso(ts),
            "event_type": "execve",
            "pid": pid,
            "uid": uid,
            "comm": comm,
            "filename": filename,
            "argv": [argv] if argv else [],
        })

    bpf["exec_events"].open_perf_buffer(_perf_cb)
    return bpf, attached


def load_file_monitor(
    on_event: Callable[[Dict[str, Any]], None],
) -> Tuple[Optional[Any], List[Any]]:
    """Load file_monitor.c, attach to openat."""
    if BPF is None:
        return None, []

    src = _read_c(EBPF_DIR / "file_monitor.c")
    try:
        bpf = BPF(text=src)
    except Exception as e:
        sys.stderr.write(f"file_monitor BPF load failed: {e}\n")
        return None, []

    openat_symbols = ["__x64_sys_openat", "sys_openat", "__ia32_sys_openat"]
    attached = []
    for sym in openat_symbols:
        try:
            bpf.attach_kprobe(event=sym, fn_name="trace_openat_entry")
            attached.append(("kprobe", sym, "trace_openat_entry"))
            break
        except Exception:
            continue
    if not attached:
        return bpf, []

    def _perf_cb(cpu: int, data: bytes, size: int) -> None:
        if size < 8 + 4 + 4 + 4 + 16 + 256:
            return
        ts = struct.unpack_from("Q", data, 0)[0]
        pid = struct.unpack_from("I", data, 8)[0]
        uid = struct.unpack_from("I", data, 12)[0]
        flags = struct.unpack_from("I", data, 16)[0]
        comm = data[20:36].split(b"\x00")[0].decode("utf-8", errors="replace")
        filename = data[36:292].split(b"\x00")[0].decode("utf-8", errors="replace")
        on_event({
            "@timestamp": _ns_to_iso(ts),
            "event_type": "openat",
            "pid": pid,
            "uid": uid,
            "comm": comm,
            "filename": filename,
            "flags": flags,
        })

    bpf["file_events"].open_perf_buffer(_perf_cb)
    return bpf, attached


def load_net_monitor(
    on_event: Callable[[Dict[str, Any]], None],
    include_connect: bool = True,
    include_bind: bool = True,
    include_listen: bool = True,
) -> Tuple[Optional[Any], List[Any]]:
    """Load net_monitor.c, attach to tcp_v4_connect, inet_bind, inet_listen."""
    if BPF is None:
        return None, []

    src = _read_c(EBPF_DIR / "net_monitor.c")
    try:
        bpf = BPF(text=src)
    except Exception as e:
        sys.stderr.write(f"net_monitor BPF load failed: {e}\n")
        return None, []

    attached = []
    if include_connect:
        try:
            bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect_entry")
            bpf.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect_return")
            attached.append(("kprobe", "tcp_v4_connect", None))
        except Exception as e:
            sys.stderr.write(f"net_monitor tcp_v4_connect attach failed: {e}\n")
    if include_bind:
        try:
            bpf.attach_kprobe(event="inet_bind", fn_name="trace_inet_bind")
            attached.append(("kprobe", "inet_bind", None))
        except Exception:
            pass
    if include_listen:
        try:
            bpf.attach_kprobe(event="inet_listen", fn_name="trace_inet_listen")
            attached.append(("kprobe", "inet_listen", None))
        except Exception:
            pass

    def _perf_cb(cpu: int, data: bytes, size: int) -> None:
        if size < 8 + 4 + 4 + 4 + 4 + 4 + 2 + 2 + 16:
            return
        ts = struct.unpack_from("Q", data, 0)[0]
        pid = struct.unpack_from("I", data, 8)[0]
        uid = struct.unpack_from("I", data, 12)[0]
        event_type = struct.unpack_from("I", data, 16)[0]
        saddr = struct.unpack_from("I", data, 20)[0]
        daddr = struct.unpack_from("I", data, 24)[0]
        sport = struct.unpack_from("H", data, 28)[0]
        dport = struct.unpack_from("H", data, 30)[0]
        comm = data[32:48].split(b"\x00")[0].decode("utf-8", errors="replace")
        # Ports are in network byte order in kernel
        import socket
        sport = socket.ntohs(sport) if sport else 0
        dport = socket.ntohs(dport) if dport else 0
        def _ip4(i):
            try:
                return socket.inet_ntoa(struct.pack(">I", i & 0xFFFFFFFF))
            except Exception:
                return str(i)
        ev = {
            "@timestamp": _ns_to_iso(ts),
            "event_type": ["connect", "accept", "bind", "listen"][event_type - 1] if 1 <= event_type <= 4 else "net",
            "pid": pid,
            "uid": uid,
            "comm": comm,
            "saddr": _ip4(saddr),
            "daddr": _ip4(daddr),
            "sport": sport,
            "dport": dport,
            "protocol": "TCP",
        }
        on_event(ev)

    bpf["net_events"].open_perf_buffer(_perf_cb)
    return bpf, attached


def _ns_to_iso(ns: int) -> str:
    from datetime import datetime, timezone
    if ns <= 0:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    sec = ns // 1_000_000_000
    nsec = (ns % 1_000_000_000) // 1_000
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{nsec:06d}Z"
