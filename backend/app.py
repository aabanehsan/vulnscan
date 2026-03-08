"""
VulnScan - Main Flask Application
Multi-stage vulnerability scanner with OWASP Top 10 coverage
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import uuid
import json
import time
import threading
from datetime import datetime

from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.auth_scanner import AuthScanner
from scanners.idor_scanner import IDORScanner
from scanners.header_scanner import HeaderScanner
from utils.crawler import Crawler
from utils.waf_detector import WAFDetector
from reports.report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)  # Allow frontend to call backend

# In-memory scan storage (use Redis/DB for production)
active_scans = {}


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "online", "version": "2.4.1"})


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    """Kick off a new scan. Returns a scan_id immediately."""
    data = request.json
    target = data.get("target", "").strip()
    modules = data.get("modules", ["xss", "sqli", "auth", "idor", "headers"])

    if not target or not target.startswith("http"):
        return jsonify({"error": "Invalid target URL"}), 400

    scan_id = "VS-" + str(uuid.uuid4())[:8].upper()
    active_scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "modules": modules,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "findings": [],
        "logs": [],
        "progress": 0,
        "requests_sent": 0,
        "endpoints_found": 0,
        "waf_detected": None,
        "bypass_rate": 0,
    }

    # Run scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id, target, modules))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Poll scan status and results."""
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scan/<scan_id>/stream", methods=["GET"])
def stream_scan(scan_id):
    """Server-Sent Events stream for real-time log updates."""
    def event_stream():
        last_idx = 0
        while True:
            scan = active_scans.get(scan_id)
            if not scan:
                break
            logs = scan["logs"]
            if len(logs) > last_idx:
                for log in logs[last_idx:]:
                    yield f"data: {json.dumps(log)}\n\n"
                last_idx = len(logs)
            if scan["status"] == "complete":
                yield f"data: {json.dumps({'type': 'done', 'msg': 'Scan complete'})}\n\n"
                break
            time.sleep(0.5)

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/scan/<scan_id>/report", methods=["GET"])
def download_report(scan_id):
    """Generate and return a structured HTML report."""
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    rg = ReportGenerator(scan)
    html = rg.generate_html()
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename=vulnscan_{scan_id}.html"})


@app.route("/api/scan/<scan_id>/abort", methods=["POST"])
def abort_scan(scan_id):
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    scan["status"] = "aborted"
    return jsonify({"status": "aborted"})


# ─────────────────────────────────────────────
#  SCAN ORCHESTRATOR
# ─────────────────────────────────────────────

def add_log(scan_id, log_type, message):
    scan = active_scans.get(scan_id)
    if scan:
        scan["logs"].append({
            "time": datetime.utcnow().strftime("%H:%M:%S"),
            "type": log_type,
            "msg": message
        })


def run_scan(scan_id, target, modules):
    scan = active_scans[scan_id]

    try:
        add_log(scan_id, "info", f"Initializing scan against {target}")
        add_log(scan_id, "info", f"Modules enabled: {', '.join(modules)}")

        # Step 1: WAF Detection
        scan["progress"] = 5
        add_log(scan_id, "info", "Detecting WAF/IDS presence...")
        waf = WAFDetector(target)
        waf_result = waf.detect()
        scan["waf_detected"] = waf_result or "None detected"
        if waf_result:
            add_log(scan_id, "warn", f"WAF detected: {waf_result} — loading bypass signatures")
        else:
            add_log(scan_id, "ok", "No WAF detected — direct injection mode")

        if scan["status"] == "aborted":
            return

        # Step 2: Crawl endpoints
        scan["progress"] = 15
        add_log(scan_id, "info", "Crawling target for endpoints...")
        crawler = Crawler(target)
        endpoints = crawler.crawl()
        scan["endpoints_found"] = len(endpoints)
        scan["requests_sent"] += crawler.request_count
        add_log(scan_id, "ok", f"Discovered {len(endpoints)} endpoints across {target}")

        if scan["status"] == "aborted":
            return

        # Step 3: Run selected scanners
        scanner_map = {
            "xss":     (XSSScanner,     "A03 — XSS Injection",     30),
            "sqli":    (SQLiScanner,    "A03 — SQL Injection",     50),
            "auth":    (AuthScanner,    "A07 — Auth Failures",     65),
            "idor":    (IDORScanner,    "A01 — Broken Access",     80),
            "headers": (HeaderScanner,  "A05 — Misconfig Headers", 90),
        }

        for mod_key, (ScannerClass, label, progress_target) in scanner_map.items():
            if mod_key not in modules:
                continue
            if scan["status"] == "aborted":
                return

            add_log(scan_id, "info", f"Running {label}...")
            scanner = ScannerClass(target, endpoints, waf_result)
            results = scanner.run()
            scan["requests_sent"] += scanner.request_count
            scan["bypass_rate"] = scanner.bypass_rate

            for finding in results:
                scan["findings"].append(finding)
                sev = finding["severity"].upper()
                log_type = "err" if sev in ("CRITICAL", "HIGH") else "warn"
                add_log(scan_id, log_type,
                        f"[{sev}] {finding['type']} — {finding['endpoint']}")

            scan["progress"] = progress_target

        # Step 4: Done
        scan["progress"] = 100
        scan["status"] = "complete"
        scan["completed_at"] = datetime.utcnow().isoformat()
        total = len(scan["findings"])
        crits = sum(1 for f in scan["findings"] if f["severity"] == "critical")
        highs = sum(1 for f in scan["findings"] if f["severity"] == "high")
        add_log(scan_id, "ok",
                f"Scan complete — {total} findings ({crits} critical, {highs} high)")

    except Exception as e:
        scan["status"] = "error"
        add_log(scan_id, "err", f"Scanner error: {str(e)}")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
