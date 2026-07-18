

import time
from collections import deque
from typing import Dict, Deque

import pyqtgraph as pg
from PySide6.QtCore import QTimer

from ui.theme import BG_PANEL, PROTOCOL_COLORS, TEXT_MUTED

TRACKED_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
WINDOW_SECONDS = 60


class ProtocolChart(pg.PlotWidget):
    """Rolling line chart of packets/sec per protocol."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setBackground(BG_PANEL)
        self.showGrid(x=True, y=True, alpha=0.15)
        self.setLabel("left", "packets / sec", color=TEXT_MUTED)
        self.setLabel("bottom", "seconds ago", color=TEXT_MUTED)
        self.addLegend(offset=(10, 10))
        self.getAxis("left").setTextPen(TEXT_MUTED)
        self.getAxis("bottom").setTextPen(TEXT_MUTED)

        self._counts: Dict[str, Deque[int]] = {
            proto: deque([0] * WINDOW_SECONDS, maxlen=WINDOW_SECONDS)
            for proto in TRACKED_PROTOCOLS
        }
        self._pending: Dict[str, int] = {proto: 0 for proto in TRACKED_PROTOCOLS}

        self._curves = {}
        x = list(range(-WINDOW_SECONDS + 1, 1))
        for proto in TRACKED_PROTOCOLS:
            color = PROTOCOL_COLORS.get(proto, "#8b949e")
            curve = self.plot(x, list(self._counts[proto]), pen=pg.mkPen(color, width=2), name=proto)
            self._curves[proto] = curve

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    def record(self, protocol: str):
        """Call once per observed packet; buckets it into the current second."""
        if protocol in self._pending:
            self._pending[protocol] += 1
        # HTTP/HTTPS packets are still TCP at the transport layer for our
        # classifier, so we don't double count -- packet_capture already
        # picks the most specific label.

    def _tick(self):
        x = list(range(-WINDOW_SECONDS + 1, 1))
        for proto in TRACKED_PROTOCOLS:
            self._counts[proto].append(self._pending[proto])
            self._pending[proto] = 0
            self._curves[proto].setData(x, list(self._counts[proto]))

    def reset(self):
        for proto in TRACKED_PROTOCOLS:
            self._counts[proto] = deque([0] * WINDOW_SECONDS, maxlen=WINDOW_SECONDS)
            self._pending[proto] = 0
