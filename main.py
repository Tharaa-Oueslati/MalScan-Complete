"""
LogSentinel — SIEM-lite Log Analysis Platform
Entry point: starts the ingestion pipeline and Flask dashboard.
"""

import threading
import time
import argparse
from pathlib import Path

from parsers.log_parser import LogParser
from detectors.anomaly_detector import AnomalyDetector
from correlator.alert_correlator import AlertCorrelator
from dashboard.app import create_app
from utils.logger import get_logger

log = get_logger("main")


def run_pipeline(watch_dirs: list[str], interval: int = 5):
    """Continuously tail log files and run detection."""
    parser = LogParser()
    detector = AnomalyDetector()
    correlator = AlertCorrelator()

    log.info(f"Pipeline started — watching: {watch_dirs}")

    while True:
        for directory in watch_dirs:
            for log_file in Path(directory).rglob("*.log"):
                events = parser.parse_file(str(log_file))
                for event in events:
                    alerts = detector.analyze(event)
                    for alert in alerts:
                        correlator.ingest(alert)

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="LogSentinel SIEM-lite")
    parser.add_argument("--watch", nargs="+", default=["logs/samples"],
                        help="Directories to watch for log files")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--interval", type=int, default=5,
                        help="Pipeline poll interval (seconds)")
    parser.add_argument("--no-pipeline", action="store_true",
                        help="Dashboard only mode")
    args = parser.parse_args()

    app = create_app()

    if not args.no_pipeline:
        pipeline_thread = threading.Thread(
            target=run_pipeline,
            args=(args.watch, args.interval),
            daemon=True
        )
        pipeline_thread.start()
        log.info("Pipeline thread started")

    log.info(f"Dashboard running at http://localhost:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
