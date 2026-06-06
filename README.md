# LogSentinel — SIEM-lite Log Analysis Platform

> Belgian Cybersecurity Internship Portfolio · Project 3 of 3  
> Keywords: SIEM, SOC, anomaly detection, log analysis, ELK, Docker Compose

---

## What it does

LogSentinel ingests **syslog**, **auth.log**, **Apache**, and **Nginx** logs, runs a stateful rule engine to detect anomalies, correlates related alerts into attack campaigns, and serves a real-time dashboard.

```
Log files → Parser → AnomalyDetector → AlertCorrelator → Flask API → Dashboard
```

---

## Detection rules

| Rule | Trigger | MITRE |
|---|---|---|
| `SSH_BRUTE_FORCE` | ≥5 failed SSH logins from same IP in 60 s | T1110.001 |
| `UNUSUAL_HOURS_LOGIN` | Successful SSH auth between 00:00–05:00 | T1078 |
| `PRIVILEGE_ESCALATION` | `sudo` to root / `COMMAND=/bin/bash` | T1548.003 |
| `SU_AUTH_FAILURE` | `su` pam authentication failure | T1548 |
| `HTTP_SCANNING` | ≥20 HTTP 4xx from same IP in 30 s | T1595.002 |
| `OOM_KILL` | Out-of-memory kernel message | T1499 |
| `PTRACE_DETECTED` | ptrace syscall in syslog | T1055 |
| `ROOTKIT_KEYWORD` | "rootkit" keyword in syslog | T1014 |
| `KERNEL_PANIC` | Kernel panic message | T1499 |

---

## Quick start

### Option A — Docker Compose (recommended)

```bash
docker compose up
```

Dashboard → http://localhost:5000

### Option B — Local Python

```bash
pip install -r requirements.txt
python main.py --watch logs/samples --port 5000
```

### Option C — ELK stack included

```bash
docker compose --profile elk up
```

Spins up Elasticsearch + Kibana alongside LogSentinel.  
Kibana → http://localhost:5601

---

## Project structure

```
logsentinel/
├── main.py                    # Entry point — pipeline + Flask server
├── parsers/
│   └── log_parser.py          # Multi-format parser (syslog, auth, Apache, Nginx)
├── detectors/
│   └── anomaly_detector.py    # Stateful rule engine
├── correlator/
│   └── alert_correlator.py    # Cross-source alert correlation / campaign detection
├── dashboard/
│   ├── app.py                 # Flask app factory + REST API
│   └── static/
│       └── index.html         # Single-page dashboard (Chart.js, dark theme)
├── utils/
│   ├── alert_store.py         # Thread-safe in-memory alert store
│   ├── event_store.py         # Thread-safe in-memory event store
│   └── logger.py              # Structured logging
├── logs/samples/              # Sample logs for local testing
│   ├── auth.log
│   ├── syslog.log
│   └── apache-access.log
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## REST API

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Alert counts by severity + event stats |
| `GET /api/alerts` | Latest 200 alerts (newest first) |
| `GET /api/timeline` | Hourly alert buckets (last 24 h) |
| `GET /api/events` | Latest 100 parsed log events |

---

## Alert correlation

When two alerts share an **IP address** or **username** within a 15-minute window, they are grouped into a *campaign*. The severity of the later alert is **escalated one level** (medium → high, high → critical). The dashboard shows active campaigns in the bottom-right panel.

Example: brute-force (HIGH) + unusual-hours login (MEDIUM) from the same IP → campaign created, login escalated to HIGH.

---

## Extending

**Add a detection rule** — open `detectors/anomaly_detector.py`, add a method `_rule_yourname(self, event)` following the existing pattern, call it from `analyze()`.

**Add a log format** — open `parsers/log_parser.py`, add a regex + parse method, extend `_detect_source()`.

**Persist to disk** — swap `EventStore` / `AlertStore` for SQLite-backed versions; the interface is identical.

---

## Recruiter keywords present in this project

`SIEM` `SOC` `log analysis` `anomaly detection` `alert correlation` `Docker Compose`  
`Python` `Flask` `regex` `ELK` `Elasticsearch` `MITRE ATT&CK` `brute-force detection`  
`privilege escalation` `threat hunting` `real-time alerting` `DevSecOps`
