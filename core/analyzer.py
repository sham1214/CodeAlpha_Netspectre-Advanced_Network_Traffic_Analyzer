

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Tuple

from core.packet_capture import PacketInfo

# --- Detection thresholds (tune to taste) -----------------------------
PORT_SCAN_UNIQUE_PORTS = 15      # distinct dest ports from one src IP
PORT_SCAN_WINDOW_SEC = 10
PING_FLOOD_COUNT = 30            # ICMP echo requests from one src IP
PING_FLOOD_WINDOW_SEC = 5
CONN_FLOOD_COUNT = 100           # packets from one src IP
CONN_FLOOD_WINDOW_SEC = 10
KNOWN_PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"}


@dataclass
class Alert:
    timestamp: float
    kind: str
    source_ip: str
    message: str


class TrafficAnalyzer:
    def __init__(self, on_alert=None):
        self._lock = threading.Lock()
        self._on_alert = on_alert

        # Dashboard / stats state
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.talkers: Dict[str, int] = defaultdict(int)
        self.start_time = time.time()

        # Sliding windows for detection, keyed by source IP
        self._port_history: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._icmp_history: Dict[str, Deque[float]] = defaultdict(deque)
        self._conn_history: Dict[str, Deque[float]] = defaultdict(deque)

        self._alerted_recent: Dict[str, float] = {}  # dedupe alerts per (ip, kind)

        self.alerts: List[Alert] = []

    # -- Ingest --------------------------------------------------------
    def process(self, pkt: PacketInfo) -> List[Alert]:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += pkt.length
            self.protocol_counts[pkt.protocol] += 1
            self.talkers[pkt.src_ip] += 1

            new_alerts = []
            new_alerts += self._check_port_scan(pkt)
            new_alerts += self._check_ping_flood(pkt)
            new_alerts += self._check_conn_flood(pkt)
            new_alerts += self._check_unknown_protocol(pkt)

            for alert in new_alerts:
                self.alerts.append(alert)
                if self._on_alert:
                    self._on_alert(alert)

            return new_alerts

    # -- Detectors -------------------------------------------------------
    def _dedupe(self, ip: str, kind: str, cooldown: float = 15.0) -> bool:
        """Returns True if this (ip, kind) alert should fire (not on cooldown)."""
        key = f"{ip}:{kind}"
        now = time.time()
        last = self._alerted_recent.get(key, 0)
        if now - last < cooldown:
            return False
        self._alerted_recent[key] = now
        return True

    def _check_port_scan(self, pkt: PacketInfo) -> List[Alert]:
        if pkt.dst_port is None:
            return []
        now = time.time()
        hist = self._port_history[pkt.src_ip]
        hist.append((now, pkt.dst_port))
        while hist and now - hist[0][0] > PORT_SCAN_WINDOW_SEC:
            hist.popleft()

        unique_ports = {p for _, p in hist}
        if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS and self._dedupe(pkt.src_ip, "port_scan"):
            pkt.suspicious, pkt.suspicious_reason = True, "Possible port scan"
            return [Alert(now, "Port Scan", pkt.src_ip,
                           f"Possible Port Scan from {pkt.src_ip} "
                           f"({len(unique_ports)} ports in {PORT_SCAN_WINDOW_SEC}s)")]
        return []

    def _check_ping_flood(self, pkt: PacketInfo) -> List[Alert]:
        if pkt.protocol != "ICMP":
            return []
        now = time.time()
        hist = self._icmp_history[pkt.src_ip]
        hist.append(now)
        while hist and now - hist[0] > PING_FLOOD_WINDOW_SEC:
            hist.popleft()

        if len(hist) >= PING_FLOOD_COUNT and self._dedupe(pkt.src_ip, "ping_flood"):
            pkt.suspicious, pkt.suspicious_reason = True, "Possible ping flood"
            return [Alert(now, "Ping Flood", pkt.src_ip,
                           f"Possible Ping Flood from {pkt.src_ip} "
                           f"({len(hist)} ICMP packets in {PING_FLOOD_WINDOW_SEC}s)")]
        return []

    def _check_conn_flood(self, pkt: PacketInfo) -> List[Alert]:
        now = time.time()
        hist = self._conn_history[pkt.src_ip]
        hist.append(now)
        while hist and now - hist[0] > CONN_FLOOD_WINDOW_SEC:
            hist.popleft()

        if len(hist) >= CONN_FLOOD_COUNT and self._dedupe(pkt.src_ip, "conn_flood"):
            pkt.suspicious, pkt.suspicious_reason = True, "Too many connections"
            return [Alert(now, "Connection Flood", pkt.src_ip,
                           f"Too many connections from {pkt.src_ip} "
                           f"({len(hist)} packets in {CONN_FLOOD_WINDOW_SEC}s)")]
        return []

    def _check_unknown_protocol(self, pkt: PacketInfo) -> List[Alert]:
        if pkt.protocol not in KNOWN_PROTOCOLS and self._dedupe(pkt.src_ip, f"unknown_{pkt.protocol}", 30.0):
            pkt.suspicious, pkt.suspicious_reason = True, "Unknown protocol"
            return [Alert(time.time(), "Unknown Protocol", pkt.src_ip,
                           f"Unknown protocol '{pkt.protocol}' from {pkt.src_ip}")]
        return []

    # -- Dashboard helpers ----------------------------------------------
    def top_talkers(self, n: int = 10) -> List[Tuple[str, int]]:
        with self._lock:
            return sorted(self.talkers.items(), key=lambda kv: kv[1], reverse=True)[:n]

    def most_used_protocol(self) -> str:
        with self._lock:
            if not self.protocol_counts:
                return "-"
            return max(self.protocol_counts.items(), key=lambda kv: kv[1])[0]

    def average_packet_size(self) -> float:
        with self._lock:
            if self.total_packets == 0:
                return 0.0
            return self.total_bytes / self.total_packets

    def packets_per_second(self) -> float:
        with self._lock:
            elapsed = max(time.time() - self.start_time, 1e-6)
            return self.total_packets / elapsed

    def reset(self):
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.talkers.clear()
            self.start_time = time.time()
            self._port_history.clear()
            self._icmp_history.clear()
            self._conn_history.clear()
            self._alerted_recent.clear()
            self.alerts.clear()
