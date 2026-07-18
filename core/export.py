

import csv
import json
from datetime import datetime
from typing import List, Dict, Any

FIELDNAMES = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "length", "suspicious", "suspicious_reason",
]


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def to_csv(packets: List[Dict[str, Any]], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for pkt in packets:
            row = {k: pkt.get(k, "") for k in FIELDNAMES}
            row["timestamp"] = _fmt_ts(pkt["timestamp"]) if "timestamp" in pkt else ""
            writer.writerow(row)


def to_json(packets: List[Dict[str, Any]], path: str) -> None:
    serializable = []
    for pkt in packets:
        item = dict(pkt)
        if "timestamp" in item:
            item["timestamp"] = _fmt_ts(item["timestamp"])
        serializable.append(item)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)


def to_txt(packets: List[Dict[str, Any]], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for pkt in packets:
            ts = _fmt_ts(pkt["timestamp"]) if "timestamp" in pkt else ""
            f.write(
                f"[{ts}] {pkt.get('protocol', ''):<6} "
                f"{pkt.get('src_ip', ''):>15}:{pkt.get('src_port') or '-'} -> "
                f"{pkt.get('dst_ip', ''):>15}:{pkt.get('dst_port') or '-'} "
                f"({pkt.get('length', 0)} bytes)"
            )
            if pkt.get("suspicious"):
                f.write(f"  [!] {pkt.get('suspicious_reason', 'Suspicious')}")
            f.write("\n")


EXPORTERS = {
    "csv": to_csv,
    "json": to_json,
    "txt": to_txt,
}


def export_packets(packets: List[Dict[str, Any]], path: str, fmt: str) -> None:
    fmt = fmt.lower().lstrip(".")
    if fmt not in EXPORTERS:
        raise ValueError(f"Unsupported export format: {fmt}")
    EXPORTERS[fmt](packets, path)
