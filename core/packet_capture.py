"""
core/packet_capture.py
-----------------------
Threaded packet capture built on Scapy. Runs sniff() on a background
thread and hands each parsed packet to a callback so the GUI thread
never blocks. Requires elevated privileges (root / Administrator /
CAP_NET_RAW) to open a raw socket.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, List

from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    summary: str = ""
    suspicious: bool = False
    suspicious_reason: str = ""


def list_interfaces() -> List[str]:
    """
    Returns human-friendly interface names for the dropdown.

    On Windows, Scapy's raw get_if_list() returns opaque Npcap device
    paths like '\\Device\\NPF_{GUID}'. conf.ifaces exposes the same
    interfaces with friendly descriptions (e.g. 'Wi-Fi', 'Ethernet'),
    and Scapy accepts those friendly names directly in sniff(iface=...),
    resolving them back to the correct device internally. On
    Linux/macOS, conf.ifaces names are already the friendly ones
    (eth0, en0, etc.), so this path works everywhere.
    """
    try:
        names = []
        for iface in conf.ifaces.values():
            label = getattr(iface, "description", None) or getattr(iface, "name", None)
            if label and label not in names:
                names.append(label)
        if names:
            return names
    except Exception:
        pass

    try:
        return get_if_list()
    except Exception:
        return []


def _classify_protocol(pkt) -> str:
    """Best-effort application/transport protocol label for a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if 443 in (sport, dport):
            return "HTTPS"
        if 80 in (sport, dport):
            return "HTTP"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def parse_packet(pkt) -> Optional[PacketInfo]:
    """Converts a raw Scapy packet into a PacketInfo, or None if not IP."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    protocol = _classify_protocol(pkt)

    src_port = dst_port = None
    if pkt.haslayer(TCP):
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

    return PacketInfo(
        timestamp=time.time(),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=len(pkt),
        summary=pkt.summary(),
    )


class PacketCapture:
    """
    Wraps scapy.sniff() in a background thread.

    Usage:
        cap = PacketCapture(on_packet=handle_packet, iface="eth0")
        cap.start()
        ...
        cap.stop()
    """

    def __init__(self, on_packet: Callable[[PacketInfo], None],
                 iface: Optional[str] = None, bpf_filter: str = ""):
        self._on_packet = on_packet
        self._iface = iface
        self._bpf_filter = bpf_filter
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.running = False
        self.error: Optional[str] = None

    def start(self):
        if self.running:
            return
        self._stop_event.clear()
        self.error = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.running = True

    def stop(self):
        self._stop_event.set()
        self.running = False

    def _run(self):
        try:
            sniff(
                iface=self._iface if self._iface else None,
                filter=self._bpf_filter if self._bpf_filter else None,
                prn=self._handle,
                store=False,
                stop_filter=lambda _pkt: self._stop_event.is_set(),
            )
        except PermissionError:
            self.error = (
                "Permission denied opening a raw socket. "
                "Run NetSpectre as Administrator / with sudo."
            )
        except Exception as exc:  # noqa: BLE001 - surface any capture error to the GUI
            self.error = str(exc)
        finally:
            self.running = False

    def _handle(self, pkt):
        info = parse_packet(pkt)
        if info is not None:
            self._on_packet(info)