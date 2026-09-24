"""Caché en memoria con caducidad, para las vistas de periodos largos (30d/90d).

Con ~1 millón de filas, esas consultas tardan 0,3–2,6 s en el NAS; se precalculan
en segundo plano y se sirven desde aquí (pueden ir hasta CACHE_TTL_S por detrás).
"""
from __future__ import annotations

import threading
import time


class TTLCache:
    def __init__(self, max_entries: int = 256):
        self.max_entries = max_entries
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires, value = item
            if expires <= time.monotonic():
                del self._data[key]
                return None
            return value

    def set(self, key, value, ttl_s: float) -> None:
        now = time.monotonic()
        with self._lock:
            if key not in self._data and len(self._data) >= self.max_entries:
                for k in [k for k, (exp, _) in self._data.items() if exp <= now]:
                    del self._data[k]
                while len(self._data) >= self.max_entries:      # el más antiguo en insertarse
                    del self._data[next(iter(self._data))]
            self._data.pop(key, None)
            self._data[key] = (now + ttl_s, value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
