# 🛰 NetSpectre — Advanced Network Traffic Analyzer

NetSpectre is a real-time network traffic analyzer built in Python. It
captures live packets, resolves hostnames and geolocation, visualizes
traffic patterns, flags suspicious activity, and exports capture data —
all inside a modern, dark-themed desktop GUI inspired by professional
SOC / network-analysis tooling.

> Built as a networking internship project — designed to demonstrate
> practical packet-analysis and systems-programming skills beyond a
> basic sniffer.

---

## ✨ Features

- **🔴 Live Packet Capture** — real-time capture via Scapy with
  timestamp, source/destination IP, ports, protocol, and length.
- **🌍 DNS Resolution** — reverse-resolves IPs to hostnames
  (`142.250.183.78` → `google.com`) with background, non-blocking lookups.
- **🎨 Modern GUI** — dark-themed PySide6 interface with sidebar
  navigation, live table, dashboard, and status bar.
- **📊 Live Statistics** — rolling per-second charts of TCP, UDP,
  ICMP, HTTP, and HTTPS traffic via PyQtGraph.
- **🚨 Suspicious Activity Detection** — flags port scans, ping
  floods, connection floods, and unknown protocols in red.
- **🔍 Powerful Filters** — filter by protocol, IP address
  (`192.168.1.10`), or port (`port 80`).
- **🌎 GeoIP Lookup** — shows country of origin for public IPs via
  MaxMind GeoLite2; private IPs show as "Local Network".
- **📁 Export** — save captured traffic as CSV, JSON, or TXT.
- **📈 Dashboard** — top talkers, most-used protocol, average packet
  size, and packets/sec at a glance.
- **📜 Event Log** — timestamped log of capture events and alerts.

---

## 🛠 Tech Stack

| Purpose             | Library                     |
|----------------------|------------------------------|
| Packet capture        | [Scapy](https://scapy.net/) |
| GUI                    | [PySide6](https://doc.qt.io/qtforpython/) (Qt6) |
| Live charts            | [PyQtGraph](https://www.pyqtgraph.org/) |
| Data handling          | [Pandas](https://pandas.pydata.org/) |
| GeoIP                  | [geoip2](https://geoip2.readthedocs.io/) + MaxMind GeoLite2 |
| Concurrency            | `threading`, Qt signals/slots |

---

## 📦 Installation

### 1. Clone and install dependencies
```bash
git clone https://github.com/<your-username>/NetSpectre.git
cd NetSpectre
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. (Optional) Enable GeoIP
Download the free `GeoLite2-City.mmdb` database from
[MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
(requires a free account) and place it at:
```
assets/GeoLite2-City.mmdb
```
Without this file, GeoIP lookups simply show "Unknown" — everything
else still works.

### 3. Run
Packet capture needs a raw socket, which requires elevated privileges:

```bash
# Linux / macOS
sudo python3 main.py

# Windows (run terminal as Administrator)
python main.py
```

---

## 🏗 Architecture

```
NetSpectre/
│
├── main.py                  # App entry point
├── ui/
│   ├── main_window.py        # Main window: sidebar, table, toolbar, pages
│   ├── charts.py              # Live PyQtGraph protocol chart
│   ├── widgets.py             # Stat cards, protocol badges, top-talker bars
│   └── theme.py                # Dark theme QSS + color palette
├── core/
│   ├── packet_capture.py     # Threaded Scapy sniffing
│   ├── analyzer.py            # Stats + suspicious-activity detection
│   ├── dns.py                  # Background reverse DNS resolver + cache
│   ├── geoip.py                 # MaxMind GeoLite2 lookups
│   └── export.py                # CSV / JSON / TXT export
├── assets/                   # Icons, GeoLite2 database
├── screenshots/               # App screenshots for this README
├── requirements.txt
└── LICENSE
```

**Design principle:** the capture and DNS-resolution threads never
touch Qt widgets directly. They communicate with the GUI thread only
through Qt signals (`CaptureBridge` in `main_window.py`), which is the
correct, crash-free way to do cross-thread UI updates in PySide6.

---

## 🔬 How Packet Sniffing Works

1. **Raw socket capture** — Scapy opens a raw socket (or uses
   `libpcap`/`Npcap` under the hood) to receive every packet that
   crosses the chosen network interface, bypassing the normal
   socket API that only sees traffic addressed to the host.
2. **Parsing** — each packet is inspected layer by layer (`IP`,
   `TCP`/`UDP`/`ICMP`, `DNS`) to pull out addresses, ports, and a
   best-guess application protocol (e.g., port 443 → HTTPS).
3. **Analysis** — the `TrafficAnalyzer` keeps sliding-window
   counters per source IP to catch patterns like a burst of unique
   destination ports (port scan) or ICMP floods (ping flood),
   without needing to store full packet history.
4. **Presentation** — results stream into the Qt table and charts
   via signals so the capture thread is never blocked waiting on the
   GUI, keeping capture smooth even under heavy traffic.

---

## 🚧 Future Improvements

- Deep packet inspection for common application protocols (FTP, SSH banners)
- Persistent capture storage (SQLite) for very long sessions
- PCAP file import/export (Wireshark-compatible)
- Configurable/pluggable detection rules
- Per-interface traffic breakdown and bandwidth graphs
- Packaged binaries (PyInstaller) for one-click installs

---

## ⚠️ Disclaimer

NetSpectre is intended for educational use and monitoring networks you
own or have explicit authorization to observe. Capturing traffic on
networks without permission may violate local laws and organizational
policies.

## 📄 License

MIT — see [LICENSE](LICENSE).
