

import socket
import threading
import queue
import ipaddress
from typing import Optional, Callable

# How long a resolved / failed entry stays valid before we retry it.
_CACHE_TTL = 300  # seconds


class DNSResolver:
    """
    Non-blocking reverse DNS resolver.

    Usage:
        resolver = DNSResolver(on_resolved=callback)
        resolver.start()
        name = resolver.resolve("142.250.183.78")   # returns cached value or
                                                      # the IP itself immediately,
                                                      # and resolves in background
    """

    def __init__(self, on_resolved: Optional[Callable[[str, str], None]] = None):
        self._cache = {}
        self._lock = threading.Lock()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._on_resolved = on_resolved
        self._workers = []
        self._running = False

    def start(self, num_workers: int = 4):
        self._running = True
        for _ in range(num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._workers.append(t)

    def stop(self):
        self._running = False

    def resolve(self, ip: str) -> str:
        """
        Returns a hostname immediately if cached, otherwise queues a
        background lookup and returns the raw IP for now. Private /
        reserved IPs are labeled directly without a DNS query.
        """
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                # Show the real private-range address (e.g. 192.168.18.5)
                # instead of masking it — reverse DNS on local/home networks
                # rarely resolves to anything useful anyway.
                return ip
        except ValueError:
            return ip

        with self._lock:
            cached = self._cache.get(ip)
        if cached is not None:
            return cached

        self._queue.put(ip)
        return ip

    def _worker_loop(self):
        while self._running:
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            hostname = self._lookup(ip)
            with self._lock:
                self._cache[ip] = hostname
            if self._on_resolved:
                self._on_resolved(ip, hostname)

    @staticmethod
    def _lookup(ip: str) -> str:
        try:
            socket.setdefaulttimeout(1.0)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ip