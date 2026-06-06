"""
LogParser — normalises syslog, auth.log, Apache/Nginx access logs into
a common event schema.
"""

import re
import os
from datetime import datetime
from typing import Optional
from utils.logger import get_logger
from utils.event_store import EventStore

log = get_logger("parser")

# ── Common event schema ──────────────────────────────────────────────────────
# {
#   "id":        str (uuid),
#   "timestamp": datetime,
#   "source":    str  ("auth", "syslog", "apache", "nginx"),
#   "host":      str,
#   "user":      Optional[str],
#   "ip":        Optional[str],
#   "message":   str,
#   "raw":       str,
# }

SYSLOG_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)"
)

AUTH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
AUTH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)"
)

APACHE_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
)

NGINX_RE = APACHE_RE  # Combined-log format is identical


class LogParser:
    def __init__(self):
        self._offsets: dict[str, int] = {}
        self.store = EventStore()

    # ── Public API ────────────────────────────────────────────────────────────

    def parse_file(self, path: str) -> list[dict]:
        """Read new lines from *path* since last call; return parsed events."""
        if not os.path.exists(path):
            return []

        offset = self._offsets.get(path, 0)
        events = []

        try:
            with open(path, "r", errors="replace") as fh:
                fh.seek(offset)
                new_lines = fh.readlines()
                self._offsets[path] = fh.tell()
        except OSError as e:
            log.warning(f"Cannot read {path}: {e}")
            return []

        source = self._detect_source(path)
        for line in new_lines:
            line = line.rstrip()
            if not line:
                continue
            event = self._parse_line(line, source, path)
            if event:
                self.store.append(event)
                events.append(event)

        return events

    def parse_line(self, line: str, source: str = "syslog") -> Optional[dict]:
        """Parse a single line — useful for testing."""
        return self._parse_line(line.rstrip(), source, "<stdin>")

    # ── Internals ─────────────────────────────────────────────────────────────

    def _detect_source(self, path: str) -> str:
        name = os.path.basename(path).lower()
        if "auth" in name:
            return "auth"
        if "apache" in name or "access" in name:
            return "apache"
        if "nginx" in name:
            return "nginx"
        return "syslog"

    def _parse_line(self, line: str, source: str, path: str) -> Optional[dict]:
        if source in ("apache", "nginx"):
            return self._parse_http(line, source)
        return self._parse_syslog(line, source)

    def _parse_syslog(self, line: str, source: str) -> Optional[dict]:
        m = SYSLOG_RE.match(line)
        if not m:
            return None

        ts = self._syslog_ts(m.group("month"), m.group("day"), m.group("time"))
        msg = m.group("msg")
        user, ip = None, None

        if source == "auth":
            for pattern, key in [(AUTH_FAILED_RE, "failed"), (AUTH_ACCEPTED_RE, "accepted")]:
                am = pattern.search(msg)
                if am:
                    user = am.group("user")
                    ip = am.group("ip")
                    break
            sm = SUDO_RE.search(msg)
            if sm:
                user = sm.group("user")

        return {
            "id": _uid(),
            "timestamp": ts,
            "source": source,
            "host": m.group("host"),
            "process": m.group("process"),
            "user": user,
            "ip": ip,
            "message": msg,
            "raw": line,
        }

    def _parse_http(self, line: str, source: str) -> Optional[dict]:
        m = APACHE_RE.match(line)
        if not m:
            return None
        ts = self._apache_ts(m.group("time"))
        return {
            "id": _uid(),
            "timestamp": ts,
            "source": source,
            "host": "webserver",
            "process": source,
            "user": m.group("user") if m.group("user") != "-" else None,
            "ip": m.group("ip"),
            "method": m.group("method"),
            "path": m.group("path"),
            "status": int(m.group("status")),
            "size": int(m.group("size")),
            "message": f'{m.group("method")} {m.group("path")} → {m.group("status")}',
            "raw": line,
        }

    @staticmethod
    def _syslog_ts(month: str, day: str, time_str: str) -> datetime:
        year = datetime.utcnow().year
        try:
            return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.utcnow()

    @staticmethod
    def _apache_ts(ts_str: str) -> datetime:
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        except ValueError:
            return datetime.utcnow()


# ── Helpers ───────────────────────────────────────────────────────────────────
import uuid

def _uid() -> str:
    return str(uuid.uuid4())[:8]
