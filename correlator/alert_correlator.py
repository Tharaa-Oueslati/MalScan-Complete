"""
AlertCorrelator — links alerts that share an IP or user within a time window.

When two or more alerts are correlated a "campaign" is created, which raises
the effective severity one level and groups events in the dashboard.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
from utils.logger import get_logger
from utils.alert_store import AlertStore

log = get_logger("correlator")

CORRELATION_WINDOW = timedelta(minutes=15)

SEVERITY_UP = {
    "info": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


class AlertCorrelator:
    def __init__(self):
        self.alert_store = AlertStore()
        # ip|user → list of alert ids seen recently
        self._index: dict[str, list[dict]] = defaultdict(list)

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, alert: dict):
        """Correlate *alert* against recent alerts and update campaigns."""
        keys = self._keys_for(alert)
        now = datetime.utcnow()

        for key in keys:
            # Purge stale entries
            self._index[key] = [
                a for a in self._index[key]
                if now - datetime.fromisoformat(a["created_at"]) < CORRELATION_WINDOW
            ]

            related = self._index[key]
            if related:
                campaign_id = related[0].get("campaign_id") or alert["id"]
                # Escalate severity
                escalated = SEVERITY_UP.get(alert["severity"], alert["severity"])
                alert["campaign_id"] = campaign_id
                alert["correlated_with"] = [a["id"] for a in related]
                if escalated != alert["severity"]:
                    log.info(
                        f"Correlation: {alert['rule']} severity "
                        f"{alert['severity']}→{escalated} (campaign {campaign_id})"
                    )
                    alert["severity"] = escalated
                    alert["escalated"] = True

                # Back-fill campaign_id on prior alerts
                for a in related:
                    a["campaign_id"] = campaign_id
                    self.alert_store.update(a)

            self._index[key].append(alert)

        self.alert_store.update(alert)

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _keys_for(alert: dict) -> list[str]:
        keys = []
        if alert.get("ip"):
            keys.append(f"ip:{alert['ip']}")
        if alert.get("user"):
            keys.append(f"user:{alert['user']}")
        if not keys:
            keys.append(f"host:{alert.get('host', 'unknown')}")
        return keys
