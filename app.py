"""Flask web server for domain-recon.

Serves the dashboard and exposes:
    GET /                      -> dashboard page
    GET /api/scan?domain=...   -> JSON report
    GET /api/scan.csv?domain=  -> CSV download

Run:  python app.py   (then open http://127.0.0.1:5000)
"""

from __future__ import annotations

import argparse
import os

from flask import Flask, Response, jsonify, render_template, request

from reconlib import InvalidDomain, findings_to_csv, scan_domain
from reconlib.demo import DEMO_REPORT
from reconlib.utils import normalize_domain

# Absolute template/static paths so the server works from any working directory
# (and when the package is installed elsewhere).
_HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
            template_folder=os.path.join(_HERE, "templates"),
            static_folder=os.path.join(_HERE, "static"))


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/demo")
def api_demo():
    """A canned report so the dashboard can be demoed offline (used by ?demo=1)."""
    return jsonify(DEMO_REPORT)


@app.get("/api/scan")
def api_scan():
    domain = request.args.get("domain", "")
    try:
        report = scan_domain(domain)
    except InvalidDomain as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # last-resort guard so the API never 500s silently
        return jsonify({"error": f"Scan failed: {exc.__class__.__name__}: {exc}"}), 500
    return jsonify(report)


@app.get("/api/scan.csv")
def api_scan_csv():
    domain = request.args.get("domain", "")
    try:
        report = scan_domain(domain)
        safe = normalize_domain(domain)
    except InvalidDomain as exc:
        return jsonify({"error": str(exc)}), 400
    csv_text = findings_to_csv(report)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="recon_{safe}.csv"'},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def main():
    parser = argparse.ArgumentParser(description="domain-recon web dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"\n  domain-recon dashboard -> http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
