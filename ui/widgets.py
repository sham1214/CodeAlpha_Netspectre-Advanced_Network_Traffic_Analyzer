


from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget
from PySide6.QtCore import Qt

from ui.theme import PROTOCOL_COLORS, TEXT_MUTED


class StatCard(QFrame):
    """Small rounded card showing a single dashboard metric."""

    def __init__(self, label: str, value: str = "-", parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setObjectName("StatValue")
        self.title_label = QLabel(label)
        self.title_label.setObjectName("StatLabel")

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value: str):
        self.value_label.setText(value)


def protocol_badge_html(protocol: str) -> str:
    """Returns an HTML snippet rendering a colored pill for a protocol name."""
    color = PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS["OTHER"])
    return (
        f'<span style="background-color:{color}22; color:{color}; '
        f'padding:2px 8px; border-radius:8px; font-weight:600;">{protocol}</span>'
    )


class TopTalkerBar(QWidget):
    """A single 'top talkers' row: IP label + proportional bar + count."""

    def __init__(self, ip: str, count: int, max_count: int, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(2)

        header = QLabel(f"<b>{ip}</b>")
        layout.addWidget(header)

        ratio = count / max_count if max_count else 0
        bar_width = max(int(ratio * 100), 2)
        bar_html = (
            f'<div style="background-color:#2a3140; border-radius:4px; height:10px;">'
            f'<div style="background-color:#3b82f6; width:{bar_width}%; height:10px; '
            f'border-radius:4px;"></div></div>'
        )
        bar_label = QLabel()
        bar_label.setText(bar_html)
        layout.addWidget(bar_label)

        count_label = QLabel(f"{count} packets")
        count_label.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        layout.addWidget(count_label)
