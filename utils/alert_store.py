"""Shared in-memory store for alerts, with update support."""

import threading
from collections import OrderedDict

_MAX = 10_000


class AlertStore:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._alerts: OrderedDict[str, dict] = OrderedDict()
                cls._instance._rlock = threading.RLock()
        return cls._instance

    def append(self, alert: dict):
        with self._rlock:
            self._alerts[alert["id"]] = alert
            if len(self._alerts) > _MAX:
                self._alerts.popitem(last=False)

    def update(self, alert: dict):
        with self._rlock:
            if alert["id"] in self._alerts:
                self._alerts[alert["id"]].update(alert)
            else:
                self.append(alert)

    def all(self) -> list[dict]:
        with self._rlock:
            return list(self._alerts.values())

    def recent(self, n: int = 100) -> list[dict]:
        alerts = self.all()
        return alerts[-n:]

    def by_severity(self) -> dict[str, list[dict]]:
        result: dict[str, list] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for a in self.all():
            sev = a.get("severity", "info")
            result.setdefault(sev, []).append(a)
        return result

    def summary(self) -> dict:
        by_sev = self.by_severity()
        return {k: len(v) for k, v in by_sev.items()}

    def timeline(self, hours: int = 24) -> list[dict]:
        """Hourly bucket counts for the last *hours* hours."""
        from datetime import datetime, timedelta
        from collections import defaultdict

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        buckets: dict[str, int] = defaultdict(int)

        for alert in self.all():
            try:
                ts = datetime.fromisoformat(alert["created_at"])
            except (KeyError, ValueError):
                continue
            if ts >= cutoff:
                bucket = ts.strftime("%Y-%m-%dT%H:00")
                buckets[bucket] += 1

        return [{"hour": k, "count": v} for k, v in sorted(buckets.items())]
