
BG = "#0e1117"
BG_PANEL = "#161b22"
BG_ELEVATED = "#1c2230"
BORDER = "#2a3140"
TEXT = "#e6e6e6"
TEXT_MUTED = "#8b949e"
ACCENT = "#3b82f6"
ACCENT_HOVER = "#5b93f5"
GREEN = "#22c55e"
RED = "#ef4444"
YELLOW = "#eab308"
ORANGE = "#f97316"

PROTOCOL_COLORS = {
    "TCP": "#3b82f6",
    "UDP": "#22c55e",
    "ICMP": "#eab308",
    "HTTP": "#f97316",
    "HTTPS": "#a855f7",
    "DNS": "#06b6d4",
    "OTHER": "#8b949e",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 13px;
}}

#Sidebar {{
    background-color: {BG_PANEL};
    border-right: 1px solid {BORDER};
}}

#SidebarTitle {{
    font-size: 17px;
    font-weight: 600;
    padding: 18px 16px 4px 16px;
    color: {TEXT};
}}

#SidebarSubtitle {{
    font-size: 11px;
    color: {TEXT_MUTED};
    padding: 0 16px 14px 16px;
}}

QPushButton {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 8px 14px;
}}

QPushButton:hover {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}

QPushButton:disabled {{
    color: {TEXT_MUTED};
    background-color: {BG_ELEVATED};
    border-color: {BORDER};
}}

#StartButton {{
    background-color: {GREEN};
    border-color: {GREEN};
    color: #06210f;
    font-weight: 600;
}}
#StartButton:hover {{ background-color: #34d76f; }}

#StopButton {{
    background-color: {RED};
    border-color: {RED};
    color: #2b0a0a;
    font-weight: 600;
}}
#StopButton:hover {{ background-color: #f56565; }}

QTableWidget {{
    background-color: {BG_PANEL};
    alternate-background-color: {BG_ELEVATED};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 8px;
    selection-background-color: {ACCENT};
}}

QHeaderView::section {{
    background-color: {BG_ELEVATED};
    color: {TEXT_MUTED};
    padding: 6px;
    border: none;
    border-bottom: 1px solid {BORDER};
    font-weight: 600;
}}

QLineEdit, QComboBox {{
    background-color: {BG_ELEVATED};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 8px;
    color: {TEXT};
}}

QLabel#StatusBar {{
    background-color: {BG_PANEL};
    color: {TEXT_MUTED};
    border-top: 1px solid {BORDER};
    padding: 6px 12px;
}}

QListWidget {{
    background-color: {BG_PANEL};
    border: none;
    outline: none;
}}

QListWidget::item {{
    padding: 10px 16px;
    border-radius: 6px;
    margin: 2px 8px;
}}

QListWidget::item:selected {{
    background-color: {ACCENT};
    color: white;
}}

QListWidget::item:hover:!selected {{
    background-color: {BG_ELEVATED};
}}

QTextEdit {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    color: {TEXT};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}}

QScrollBar:vertical {{
    background: {BG};
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 20px;
}}

#StatCard {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}

#StatValue {{
    font-size: 22px;
    font-weight: 700;
    color: {TEXT};
}}

#StatLabel {{
    font-size: 11px;
    color: {TEXT_MUTED};
}}
"""
