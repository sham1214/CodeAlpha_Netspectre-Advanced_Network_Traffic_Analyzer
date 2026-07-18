
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

from PySide6.QtCore import Qt, QObject, Signal, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QListWidget, QListWidgetItem,
    QStackedWidget, QLineEdit, QComboBox, QFileDialog, QTextEdit, QGridLayout,
    QMessageBox,
)

from core.packet_capture import PacketCapture, PacketInfo, list_interfaces
from core.analyzer import TrafficAnalyzer, Alert
from core.dns import DNSResolver
from core.geoip import GeoIPLookup
from core.export import export_packets

from ui.theme import STYLESHEET, RED, TEXT_MUTED
from ui.widgets import StatCard, protocol_badge_html, TopTalkerBar
from ui.charts import ProtocolChart

MAX_TABLE_ROWS = 5000  # cap to keep the GUI responsive on long captures


class CaptureBridge(QObject):
    """
    Marshals background-thread events (new packet, DNS resolved, alert,
    capture error) onto the Qt main thread via signals.
    """
    packet_ready = Signal(object)     # PacketInfo
    dns_resolved = Signal(str, str)   # ip, hostname
    geo_resolved = Signal(str, dict)  # ip, geo result dict
    alert_raised = Signal(object)     # Alert
    capture_error = Signal(str)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSpectre — Network Traffic Analyzer")
        self.resize(1400, 860)
        self.setStyleSheet(STYLESHEET)

        # --- Core engine objects -----------------------------------
        self.bridge = CaptureBridge()
        self.analyzer = TrafficAnalyzer(on_alert=lambda a: self.bridge.alert_raised.emit(a))
        self.dns_resolver = DNSResolver(on_resolved=lambda ip, name: self.bridge.dns_resolved.emit(ip, name))
        self.geoip = GeoIPLookup(on_resolved=lambda ip, geo: self.bridge.geo_resolved.emit(ip, geo))
        self.capture: Optional[PacketCapture] = None

        self.dns_resolver.start()

        self._packets: List[Dict[str, Any]] = []   # exportable packet dicts
        self._row_by_ip_pending: Dict[str, List[int]] = {}  # ip -> row indices awaiting DNS
        self._geo_row_pending: Dict[str, List[int]] = {}    # ip -> row indices awaiting online GeoIP
        self._active_filter = "ALL"
        self._search_text = ""

        self.bridge.packet_ready.connect(self._on_packet_ready)
        self.bridge.dns_resolved.connect(self._on_dns_resolved)
        self.bridge.geo_resolved.connect(self._on_geo_resolved)
        self.bridge.alert_raised.connect(self._on_alert)
        self.bridge.capture_error.connect(self._on_capture_error)

        self._build_ui()

        # Dashboard refresh timer (stats don't need per-packet redraw)
        self._dash_timer = QTimer(self)
        self._dash_timer.timeout.connect(self._refresh_dashboard)
        self._dash_timer.start(1000)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self._build_toolbar())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_live_page())
        self.stack.addWidget(self._build_dashboard_page())
        self.stack.addWidget(self._build_charts_page())
        self.stack.addWidget(self._build_log_page())
        right.addWidget(self.stack, 1)

        right.addWidget(self._build_status_bar())

        right_widget = QWidget()
        right_widget.setLayout(right)
        root.addWidget(right_widget, 1)

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(220)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 12)
        layout.setSpacing(0)

        title = QLabel("🛰  NetSpectre")
        title.setObjectName("SidebarTitle")
        subtitle = QLabel("Network Traffic Analyzer")
        subtitle.setObjectName("SidebarSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        self.nav_list = QListWidget()
        for label in ["🔴 Live Capture", "📈 Dashboard", "📊 Statistics", "📜 Event Log"]:
            QListWidgetItem(label, self.nav_list)
        self.nav_list.setCurrentRow(0)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        layout.addWidget(self.nav_list, 1)

        self.packet_counter_label = QLabel("Packets: 0")
        self.packet_counter_label.setStyleSheet(f"color:{TEXT_MUTED}; padding: 8px 16px;")
        layout.addWidget(self.packet_counter_label)

        return sidebar

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        self.start_btn = QPushButton("▶  Start Capture")
        self.start_btn.setObjectName("StartButton")
        self.start_btn.clicked.connect(self._start_capture)

        self.stop_btn = QPushButton("■  Stop Capture")
        self.stop_btn.setObjectName("StopButton")
        self.stop_btn.clicked.connect(self._stop_capture)
        self.stop_btn.setEnabled(False)

        self.clear_btn = QPushButton("🗑  Clear")
        self.clear_btn.clicked.connect(self._clear_capture)

        self.iface_combo = QComboBox()
        ifaces = list_interfaces() or ["default"]
        self.iface_combo.addItems(ifaces)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["ALL", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"])
        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter: e.g. 192.168.1.10  or  port 80")
        self.search_box.textChanged.connect(self._on_search_changed)

        export_csv = QPushButton("Export CSV")
        export_csv.clicked.connect(lambda: self._export("csv"))
        export_json = QPushButton("Export JSON")
        export_json.clicked.connect(lambda: self._export("json"))
        export_txt = QPushButton("Export TXT")
        export_txt.clicked.connect(lambda: self._export("txt"))

        for w in (self.start_btn, self.stop_btn, self.clear_btn, QLabel("Interface:"), self.iface_combo,
                  QLabel("Protocol:"), self.filter_combo, self.search_box):
            layout.addWidget(w)
        layout.addStretch(1)
        for w in (export_csv, export_json, export_txt):
            layout.addWidget(w)

        return bar

    def _build_live_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 0, 16, 16)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Source IP", "Destination IP", "Src Port", "Dst Port",
             "Protocol", "Length", "Geo"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table)
        return page

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        grid = QGridLayout()
        self.stat_total = StatCard("Total Packets")
        self.stat_pps = StatCard("Packets / sec")
        self.stat_avg_size = StatCard("Avg Packet Size")
        self.stat_top_protocol = StatCard("Most Used Protocol")
        for i, card in enumerate([self.stat_total, self.stat_pps, self.stat_avg_size, self.stat_top_protocol]):
            grid.addWidget(card, 0, i)
        layout.addLayout(grid)

        layout.addWidget(QLabel("<b>Top Talkers</b>"))
        self.talkers_container = QVBoxLayout()
        talkers_widget = QWidget()
        talkers_widget.setLayout(self.talkers_container)
        layout.addWidget(talkers_widget)
        layout.addStretch(1)
        return page

    def _build_charts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(QLabel("<b>Live Protocol Traffic (packets/sec)</b>"))
        self.chart = ProtocolChart()
        layout.addWidget(self.chart, 1)
        return page

    def _build_log_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(QLabel("<b>Event Log</b>"))
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view, 1)
        return page

    def _build_status_bar(self) -> QWidget:
        self.status_label = QLabel("Idle — press Start Capture to begin")
        self.status_label.setObjectName("StatusBar")
        return self.status_label

    # ------------------------------------------------------------------
    # Navigation / filters
    # ------------------------------------------------------------------
    def _on_nav_changed(self, row: int):
        self.stack.setCurrentIndex(row)

    def _on_filter_changed(self, text: str):
        self._active_filter = text
        self._apply_table_filter()

    def _on_search_changed(self, text: str):
        self._search_text = text.strip().lower()
        self._apply_table_filter()

    def _apply_table_filter(self):
        for row in range(self.table.rowCount()):
            visible = True
            proto_item = self.table.item(row, 5)
            if self._active_filter != "ALL" and proto_item and proto_item.text() != self._active_filter:
                visible = False

            if visible and self._search_text:
                visible = self._row_matches_search(row, self._search_text)

            self.table.setRowHidden(row, not visible)

    def _row_matches_search(self, row: int, needle: str) -> bool:
        if needle.startswith("port "):
            try:
                port = needle.split("port ", 1)[1].strip()
            except IndexError:
                return True
            src_port = self.table.item(row, 3)
            dst_port = self.table.item(row, 4)
            return (src_port and src_port.text() == port) or (dst_port and dst_port.text() == port)

        for col in (1, 2):  # source / dest IP
            item = self.table.item(row, col)
            if item and needle in item.text().lower():
                return True
        return False

    # ------------------------------------------------------------------
    # Capture lifecycle
    # ------------------------------------------------------------------
    def _start_capture(self):
        iface = self.iface_combo.currentText()
        self.capture = PacketCapture(
            on_packet=lambda pkt: self.bridge.packet_ready.emit(pkt),
            iface=None if iface == "default" else iface,
        )
        self.capture.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"Capturing on {iface}…")
        self._log_event("Started capture")

        # Poll briefly for an early permission/interface error.
        QTimer.singleShot(800, self._check_capture_error)

    def _check_capture_error(self):
        if self.capture and self.capture.error:
            self.bridge.capture_error.emit(self.capture.error)

    def _stop_capture(self):
        if self.capture:
            self.capture.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Idle — capture stopped")
        self._log_event("Stopped capture")

    def _on_capture_error(self, message: str):
        self._stop_capture()
        self.status_label.setText(f"Error: {message}")
        QMessageBox.critical(self, "Capture Error", message)

    # ------------------------------------------------------------------
    # Packet handling
    # ------------------------------------------------------------------
    def _on_packet_ready(self, pkt: PacketInfo):
        self.analyzer.process(pkt)
        self.chart.record(pkt.protocol)

        hostname_src = self.dns_resolver.resolve(pkt.src_ip)
        hostname_dst = self.dns_resolver.resolve(pkt.dst_ip)
        geo = self.geoip.lookup(pkt.dst_ip)

        row = self._insert_row(pkt, hostname_src, hostname_dst, geo)

        # Track pending DNS updates so we can patch the cell in place later.
        for ip in (pkt.src_ip, pkt.dst_ip):
            self._row_by_ip_pending.setdefault(ip, []).append(row)

        if geo.get("label") == "Looking up…":
            self._geo_row_pending.setdefault(pkt.dst_ip, []).append(row)

        packet_dict = {
            "timestamp": pkt.timestamp,
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "protocol": pkt.protocol,
            "length": pkt.length,
            "suspicious": pkt.suspicious,
            "suspicious_reason": pkt.suspicious_reason,
        }
        self._packets.append(packet_dict)

        if pkt.protocol == "DNS":
            self._log_event("DNS request detected")
        elif pkt.protocol == "HTTPS":
            self._log_event("HTTPS Connection")

        self.packet_counter_label.setText(f"Packets: {self.analyzer.total_packets}")

    def _insert_row(self, pkt: PacketInfo, src_name: str, dst_name: str, geo: dict) -> int:
        row = self.table.rowCount()
        self.table.insertRow(row)

        ts_str = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S")
        values = [
            ts_str,
            src_name,
            dst_name,
            str(pkt.src_port) if pkt.src_port else "-",
            str(pkt.dst_port) if pkt.dst_port else "-",
            pkt.protocol,
            str(pkt.length),
            geo.get("label", ""),
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            if pkt.suspicious:
                item.setForeground(QColor(RED))
            self.table.setItem(row, col, item)

        if pkt.suspicious:
            self.table.item(row, 5).setToolTip(pkt.suspicious_reason)

        # Trim old rows to keep the table responsive during long captures.
        if self.table.rowCount() > MAX_TABLE_ROWS:
            self.table.removeRow(0)
            self._packets.pop(0)

        self._apply_table_filter_to_row(row)
        return row

    def _apply_table_filter_to_row(self, row: int):
        proto_item = self.table.item(row, 5)
        visible = self._active_filter == "ALL" or (proto_item and proto_item.text() == self._active_filter)
        if visible and self._search_text:
            visible = self._row_matches_search(row, self._search_text)
        self.table.setRowHidden(row, not visible)

    def _on_dns_resolved(self, ip: str, hostname: str):
        rows = self._row_by_ip_pending.pop(ip, [])
        for row in rows:
            if row >= self.table.rowCount():
                continue
            for col in (1, 2):
                item = self.table.item(row, col)
                if item and item.text() == ip:
                    item.setText(hostname)

    def _on_geo_resolved(self, ip: str, geo: dict):
        rows = self._geo_row_pending.pop(ip, [])
        label = geo.get("label", "Unknown")
        for row in rows:
            if row >= self.table.rowCount():
                continue
            item = self.table.item(row, 7)
            if item:
                item.setText(label)

    def _on_alert(self, alert: Alert):
        ts_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
        self._log_event(alert.message, ts=ts_str, is_alert=True)

    def _log_event(self, message: str, ts: Optional[str] = None, is_alert: bool = False):
        ts = ts or datetime.now().strftime("%H:%M:%S")
        color = RED if is_alert else "#8b949e"
        self.log_view.append(f'<span style="color:{color}">[{ts}]</span>  {message}')

    # ------------------------------------------------------------------
    # Dashboard refresh
    # ------------------------------------------------------------------
    def _refresh_dashboard(self):
        self.stat_total.set_value(str(self.analyzer.total_packets))
        self.stat_pps.set_value(f"{self.analyzer.packets_per_second():.1f}")
        self.stat_avg_size.set_value(f"{self.analyzer.average_packet_size():.0f} B")
        self.stat_top_protocol.set_value(self.analyzer.most_used_protocol())

        # Rebuild top-talkers list
        while self.talkers_container.count():
            item = self.talkers_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        talkers = self.analyzer.top_talkers(10)
        max_count = talkers[0][1] if talkers else 1
        for ip, count in talkers:
            self.talkers_container.addWidget(TopTalkerBar(ip, count, max_count))

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------
    def _clear_capture(self):
        self.table.setRowCount(0)
        self._packets.clear()
        self._row_by_ip_pending.clear()
        self._geo_row_pending.clear()
        self.analyzer.reset()
        self.chart.reset()
        self.packet_counter_label.setText("Packets: 0")
        self._refresh_dashboard()
        self._log_event("Cleared captured packets")
        self.status_label.setText(
            f"Capturing on {self.iface_combo.currentText()}…" if self.capture and self.capture.running
            else "Idle — capture cleared"
        )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def _export(self, fmt: str):
        if not self._packets:
            QMessageBox.information(self, "Export", "No packets captured yet.")
            return
        default_name = f"netspectre_capture.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, f"Export as {fmt.upper()}", default_name)
        if not path:
            return
        try:
            export_packets(self._packets, path, fmt)
            self._log_event(f"Exported {len(self._packets)} packets to {path}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export Failed", str(exc))

    # ------------------------------------------------------------------
    def closeEvent(self, event):
        if self.capture:
            self.capture.stop()
        self.dns_resolver.stop()
        self.geoip.close()
        super().closeEvent(event)