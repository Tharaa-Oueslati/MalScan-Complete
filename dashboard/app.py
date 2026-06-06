"""
Flask dashboard — serves the SPA and JSON API endpoints.
"""

from flask import Flask, jsonify, render_template_string, send_from_directory
from utils.alert_store import AlertStore
from utils.event_store import EventStore
import os


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static")
    alert_store = AlertStore()
    event_store = EventStore()

    # ── Static SPA ────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
        with open(html_path) as f:
            return f.read()

    # ── JSON API ──────────────────────────────────────────────────────────────

    @app.route("/api/summary")
    def api_summary():
        return jsonify({
            "alerts": alert_store.summary(),
            "events": event_store.stats(),
        })

    @app.route("/api/alerts")
    def api_alerts():
        alerts = alert_store.recent(200)
        # Serialize datetimes
        safe = []
        for a in reversed(alerts):
            safe.append({k: (v.isoformat() if hasattr(v, "isoformat") else v)
                         for k, v in a.items()})
        return jsonify(safe)

    @app.route("/api/timeline")
    def api_timeline():
        return jsonify(alert_store.timeline(24))

    @app.route("/api/events")
    def api_events():
        events = event_store.recent(100)
        safe = []
        for e in reversed(events):
            safe.append({k: (v.isoformat() if hasattr(v, "isoformat") else v)
                         for k, v in e.items()})
        return jsonify(safe)

    return app
