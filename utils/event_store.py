"""Shared in-memory store for parsed log events."""

import threading
from collections import deque
from datetime import datetime
from typing import Optional

_MAX = 50_000


class EventStore:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._events = deque(maxlen=_MAX)
                cls._instance._rlock = threading.RLock()
        return cls._instance

    def append(self, event: dict):
        with self._rlock:
            self._events.append(event)

    def all(self) -> list[dict]:
        with self._rlock:
            return list(self._events)

    def recent(self, n: int = 200) -> list[dict]:
        with self._rlock:
            events = list(self._events)
        return events[-n:]

    def stats(self) -> dict:
        events = self.all()
        by_source: dict[str, int] = {}
        for e in events:
            s = e.get("source", "unknown")
            by_source[s] = by_source.get(s, 0) + 1
        return {
            "total": len(events),
            "by_source": by_source,
        }
