"""
Network activity logger: pyshark live capture, log summary to text file.
Requires root or cap_net_raw for live capture.
"""
from __future__ import annotations

import threading
from typing import Optional

from logger_utils import write_log

try:
    import pyshark
except ImportError:
    pyshark = None


def _packet_summary(pkt) -> Optional[str]:
    """Build a one-line summary of a packet."""
    try:
        layers = []
        if hasattr(pkt, "ip"):
            layers.append(f"IP {pkt.ip.src} -> {pkt.ip.dst}")
        elif hasattr(pkt, "ipv6"):
            layers.append(f"IPv6 {pkt.ipv6.src} -> {pkt.ipv6.dst}")
        else:
            return None
        if hasattr(pkt, "tcp"):
            layers.append(f"TCP {pkt.tcp.srcport} -> {pkt.tcp.dstport}")
        elif hasattr(pkt, "udp"):
            layers.append(f"UDP {pkt.udp.srcport} -> {pkt.udp.dstport}")
        elif hasattr(pkt, "icmp"):
            layers.append("ICMP")
        if hasattr(pkt, "http") and hasattr(pkt.http, "request_uri"):
            layers.append(f"HTTP {pkt.http.request_uri[:80]}")
        return " | ".join(layers)
    except Exception:
        return None


def start_network_logger(
    interface: str = "any",
    summary_only: bool = True,
    bpf_filter: Optional[str] = None,
    packet_batch: int = 50,
    stop: threading.Event = None,
) -> None:
    """Start pyshark live capture in a background thread."""
    if pyshark is None:
        write_log("NETWORK", "pyshark not installed; network monitoring disabled")
        return
    stop = stop or threading.Event()

    def run() -> None:
        try:
            kwargs = {"interface": interface}
            if bpf_filter:
                kwargs["bpf_filter"] = bpf_filter
            cap = pyshark.LiveCapture(**kwargs)
            if summary_only:
                while not stop.is_set():
                    try:
                        cap.sniff(packet_count=packet_batch, timeout=10)
                        for pkt in cap:
                            s = _packet_summary(pkt)
                            if s:
                                write_log("NETWORK", s)
                        cap.clear()
                    except Exception as e:
                        if not stop.is_set():
                            write_log("NETWORK", f"capture error: {e}")
            else:
                def on_packet(pkt):
                    s = _packet_summary(pkt)
                    if s:
                        write_log("NETWORK", s)

                cap.apply_on_packets(on_packet, timeout=1)
                while not stop.is_set():
                    cap.sniff(packet_count=packet_batch, timeout=5)
                    for pkt in cap:
                        on_packet(pkt)
                    cap.clear()
        except Exception as e:
            write_log("NETWORK", f"pyshark start error (need root?): {e}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
