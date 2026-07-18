"""
core/geoip.py
--------------
Resolves a public IP address to a country of origin.

Two strategies, chosen automatically:
1. Local MaxMind GeoLite2-City database (assets/GeoLite2-City.mmdb), if
   present. Fast, fully offline, no rate limits, no third party ever sees
   the IPs being looked up.
2. Free ip-api.com HTTP lookup, used automatically whenever no local
   database is installed. This means GeoIP works out of the box with no
   extra download. Lookups run on background worker threads (same pattern
   as DNS resolution) so they never block capture or the GUI, and every
   result is cached for the life of the session.

Private/reserved IPs are always short-circuited to "Local Network"
without any lookup, local or online.
"""

import ipaddress
import json
import os
import queue
import threading
import urllib.request
from typing import Callable, Optional

try:
    import geoip2.database
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

_FLAGS = {
    "US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "CA": "🇨🇦",
    "AU": "🇦🇺", "JP": "🇯🇵", "CN": "🇨🇳", "IN": "🇮🇳", "PK": "🇵🇰",
    "BR": "🇧🇷", "RU": "🇷🇺", "NL": "🇳🇱", "SG": "🇸🇬", "IE": "🇮🇪",
    "KR": "🇰🇷", "ZA": "🇿🇦", "AE": "🇦🇪", "SE": "🇸🇪", "CH": "🇨🇭",
}

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets", "GeoLite2-City.mmdb",
)

_ONLINE_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode"
_ONLINE_TIMEOUT = 2.5
_PLACEHOLDER = {"label": "Looking up…", "country": "", "flag": "", "org": ""}
_LOCAL_NET = {"label": "Local Network", "country": "", "flag": "", "org": ""}
_UNKNOWN = {"label": "Unknown", "country": "", "flag": "", "org": ""}


class GeoIPLookup:
    def __init__(self, db_path: str = DEFAULT_DB_PATH,
                 on_resolved: Optional[Callable[[str, dict], None]] = None,
                 num_workers: int = 3):
        self._lock = threading.Lock()
        self._cache = {}
        self._reader = None
        self._local_available = False
        self._on_resolved = on_resolved

        self._queue: "queue.Queue[str]" = queue.Queue()
        self._pending = set()
        self._running = False
        self._workers = []

        if _GEOIP2_AVAILABLE and os.path.exists(db_path):
            try:
                self._reader = geoip2.database.Reader(db_path)
                self._local_available = True
            except Exception:
                self._reader = None
                self._local_available = False

        if not self._local_available:
            self._start_workers(num_workers)

    @property
    def mode(self) -> str:
        """'local' if a GeoLite2 database is loaded, otherwise 'online'."""
        return "local" if self._local_available else "online"

    def _start_workers(self, n: int):
        self._running = True
        for _ in range(n):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._workers.append(t)

    def stop(self):
        self._running = False

    def lookup(self, ip: str) -> dict:
        """
        Returns {"label": str, "country": str, "flag": str, "org": str}.
        Always returns something usable immediately:
        - private/reserved IPs  -> "Local Network", no lookup at all
        - cached public IP      -> the cached result
        - local DB available    -> resolved synchronously (fast, offline)
        - online mode           -> "Looking up…" now; real result arrives
                                    later via the on_resolved callback
        """
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                return dict(_LOCAL_NET)
        except ValueError:
            return dict(_UNKNOWN)

        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached

        if self._local_available:
            result = self._lookup_local(ip)
            with self._lock:
                self._cache[ip] = result
            return result

        # Online mode: kick off a background lookup, return a placeholder now.
        with self._lock:
            if ip not in self._pending:
                self._pending.add(ip)
                self._queue.put(ip)
        return dict(_PLACEHOLDER)

    def _lookup_local(self, ip: str) -> dict:
        result = dict(_UNKNOWN)
        try:
            resp = self._reader.city(ip)
            country = resp.country.name or ""
            code = resp.country.iso_code or ""
            flag = _FLAGS.get(code, "")
            if country:
                result = {"label": f"{country} {flag}".strip(), "country": country, "flag": flag, "org": ""}
        except Exception:
            pass
        return result

    def _worker_loop(self):
        while self._running:
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            result = self._lookup_online(ip)
            with self._lock:
                self._cache[ip] = result
                self._pending.discard(ip)
            if self._on_resolved:
                self._on_resolved(ip, result)

    @staticmethod
    def _lookup_online(ip: str) -> dict:
        result = dict(_UNKNOWN)
        try:
            req = urllib.request.Request(
                _ONLINE_API_URL.format(ip=ip),
                headers={"User-Agent": "NetSpectre/1.0"},
            )
            with urllib.request.urlopen(req, timeout=_ONLINE_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                country = data.get("country", "")
                code = data.get("countryCode", "")
                flag = _FLAGS.get(code, "")
                if country:
                    result = {"label": f"{country} {flag}".strip(), "country": country, "flag": flag, "org": ""}
        except Exception:
            pass
        return result

    def close(self):
        self.stop()
        if self._reader:
            self._reader.close()