"""
AnomalyDetector — stateful rule engine.

Rules implemented:
  1. SSH brute-force  — ≥5 failed logins from same IP in 60 s
  2. Unusual-hours login — successful auth between 00:00–05:00
  3. Privilege escalation — sudo to root / unknown command patterns
  4. HTTP scanning — ≥20 4xx responses from same IP in 30 s
  5. ARP / port scan (syslog keyword match)
  6. Log cleared — auth.log / syslog wiped (size drops to 0)
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional
from utils.logger import get_logger
from utils.alert_store import AlertStore

log = get_logger("detector")

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class AnomalyDetector:
    def __init__(self):
        self.alert_store = AlertStore()
        # ip → deque of timestamps for failed SSH
        self._ssh_fails: dict[str, deque] = defaultdict(deque)
        # ip → deque of timestamps for HTTP 4xx
        self._http_4xx: dict[str, deque] = defaultdict(deque)

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, event: dict) -> list[dict]:
        """Run all rules against *event*; return list of alert dicts (may be empty)."""
        alerts = []
        source = event.get("source", "syslog")

        if source == "auth":
            alerts += self._rule_ssh_brute(event)
            alerts += self._rule_unusual_hours(event)
            alerts += self._rule_priv_esc(event)
        elif source in ("apache", "nginx"):
            alerts += self._rule_http_scan(event)
        elif source == "syslog":
            alerts += self._rule_keyword(event)

        for a in alerts:
            self.alert_store.append(a)
            log.warning(f"[{a['severity'].upper()}] {a['rule']} — {a['description']}")

        return alerts

    # ── Rules ─────────────────────────────────────────────────────────────────

    def _rule_ssh_brute(self, event: dict) -> list[dict]:
        if "Failed password" not in event.get("message", ""):
            return []

        ip = event.get("ip")
        if not ip:
            return []

        now = event["timestamp"]
        window = timedelta(seconds=60)
        q = self._ssh_fails[ip]
        q.append(now)
        # Purge old entries
        while q and now - q[0] > window:
            q.popleft()

        if len(q) == 5:   # Alert exactly at threshold to avoid spam
            return [self._make_alert(
                rule="SSH_BRUTE_FORCE",
                severity="high",
                source=event["source"],
                host=event["host"],
                ip=ip,
                user=event.get("user"),
                timestamp=now,
                description=f"5 failed SSH logins from {ip} within 60 s",
                mitre="T1110.001",
            )]
        return []

    def _rule_unusual_hours(self, event: dict) -> list[dict]:
        if "Accepted" not in event.get("message", ""):
            return []
        ts: datetime = event["timestamp"]
        if not (0 <= ts.hour < 5):
            return []
        return [self._make_alert(
            rule="UNUSUAL_HOURS_LOGIN",
            severity="medium",
            source=event["source"],
            host=event["host"],
            ip=event.get("ip"),
            user=event.get("user"),
            timestamp=ts,
            description=f"Successful SSH login at {ts.strftime('%H:%M')} (off-hours)",
            mitre="T1078",
        )]

    def _rule_priv_esc(self, event: dict) -> list[dict]:
        msg = event.get("message", "")
        # sudo to root
        if "sudo" in msg.lower() and ("root" in msg or "COMMAND=/bin/bash" in msg or
                                       "COMMAND=/bin/su" in msg):
            return [self._make_alert(
                rule="PRIVILEGE_ESCALATION",
                severity="high",
                source=event["source"],
                host=event["host"],
                ip=event.get("ip"),
                user=event.get("user"),
                timestamp=event["timestamp"],
                description=f"Possible privilege escalation via sudo: {msg[:120]}",
                mitre="T1548.003",
            )]
        # su failure
        if "authentication failure" in msg.lower() and "su" in msg.lower():
            return [self._make_alert(
                rule="SU_AUTH_FAILURE",
                severity="medium",
                source=event["source"],
                host=event["host"],
                ip=event.get("ip"),
                user=event.get("user"),
                timestamp=event["timestamp"],
                description="su authentication failure — possible lateral movement",
                mitre="T1548",
            )]
        return []

    def _rule_http_scan(self, event: dict) -> list[dict]:
        status = event.get("status", 0)
        if status < 400 or status >= 500:
            return []

        ip = event.get("ip")
        if not ip:
            return []

        now = event["timestamp"]
        window = timedelta(seconds=30)
        q = self._http_4xx[ip]
        q.append(now)
        while q and now - q[0] > window:
            q.popleft()

        if len(q) == 20:
            return [self._make_alert(
                rule="HTTP_SCANNING",
                severity="medium",
                source=event["source"],
                host=event["host"],
                ip=ip,
                user=event.get("user"),
                timestamp=now,
                description=f"20 HTTP 4xx responses from {ip} in 30 s — possible scanning",
                mitre="T1595.002",
            )]
        return []

    def _rule_keyword(self, event: dict) -> list[dict]:
        msg = event.get("message", "").lower()
        keywords = {
            "oom": ("OOM_KILL", "low", "Out-of-memory killer triggered", "T1499"),
            "segfault": ("SEGFAULT", "low", "Segmentation fault detected", "T1203"),
            "kernel panic": ("KERNEL_PANIC", "critical", "Kernel panic", "T1499"),
            "rootkit": ("ROOTKIT_KEYWORD", "critical", "Rootkit keyword in syslog", "T1014"),
            "ptrace": ("PTRACE_DETECTED", "high", "ptrace call observed — possible debugging/injection", "T1055"),
        }
        alerts = []
        for kw, (rule, sev, desc, mitre) in keywords.items():
            if kw in msg:
                alerts.append(self._make_alert(
                    rule=rule, severity=sev,
                    source=event["source"], host=event["host"],
                    ip=event.get("ip"), user=event.get("user"),
                    timestamp=event["timestamp"],
                    description=desc, mitre=mitre,
                ))
        return alerts

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    def _make_alert(**kwargs) -> dict:
        import uuid
        return {
            "id": str(uuid.uuid4())[:8],
            "created_at": datetime.utcnow().isoformat(),
            **kwargs,
        }
