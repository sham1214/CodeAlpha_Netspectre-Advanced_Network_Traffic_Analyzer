#!/usr/bin/env python3


import os
import sys

from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow


def _warn_if_not_privileged():
    """Best-effort check; actual failure is still handled at capture time."""
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[NetSpectre] Warning: not running as root. Packet capture will "
            "likely fail to open a raw socket. Re-run with sudo if capture "
            "does not start.",
            file=sys.stderr,
        )


def main():
    _warn_if_not_privileged()

    app = QApplication(sys.argv)
    app.setApplicationName("NetSpectre")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
