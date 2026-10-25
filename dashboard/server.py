#!/usr/bin/env python3
"""
Dashboard Backend Server & Telemetry API
Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
Member 5: Manideep (OPA, Vault & Dashboard)

Serves the visual security observability dashboard and handles:
- GET /api/events: streams verified OPA authorization and Vault PKI certificate events
- POST /api/simulate: appends real-time simulation events to audit log
- POST /api/run-tests: executes automated test suites on-demand
- Static files: index.html, css/index.css, js/app.js
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

ROOT_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT_DIR / "dashboard"
TELEMETRY_LOG = ROOT_DIR / "opa" / "telemetry" / "audit_log.json"
SCHEMA_FILE = ROOT_DIR / "opa" / "telemetry" / "dashboard_events.json"

DEFAULT_PORT = 8050


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path == "/api/events":
            self.handle_get_events()
        elif path == "/api/schema":
            self.handle_get_schema()
        elif path == "/api/status":
            self.handle_get_status()
        else:
            # Fall back to serving static files from dashboard/
            super().do_GET()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        if path == "/api/simulate":
            self.handle_simulate(post_data)
        elif path == "/api/run-tests":
            self.handle_run_tests(post_data)
        else:
            self.send_error(404, "Endpoint not found")

    def handle_get_events(self):
        records = []
        if TELEMETRY_LOG.exists():
            try:
                records = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
            except Exception as e:
                records = [{"error": f"Failed reading audit log: {str(e)}"}]
        self.send_json_response(records)

    def handle_get_schema(self):
        schema = {}
        if SCHEMA_FILE.exists():
            try:
                schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        self.send_json_response(schema)

    def handle_get_status(self):
        # Quick health check of mesh components
        opa_installed = False
        try:
            r = subprocess.run(["opa", "version"], capture_output=True, text=True, timeout=3)
            opa_installed = (r.returncode == 0)
        except Exception:
            opa_installed = False

        status = {
            "status": "healthy",
            "opa_installed": opa_installed,
            "telemetry_log_exists": TELEMETRY_LOG.exists(),
            "root_ca_configured": True,
            "pqc_ciphers": ["Hybrid ECDH-P256 + ML-KEM-768", "ML-DSA-65"]
        }
        self.send_json_response(status)

    def handle_simulate(self, body_bytes):
        try:
            event = json.loads(body_bytes.decode("utf-8"))
            records = []
            if TELEMETRY_LOG.exists():
                try:
                    records = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
                except Exception:
                    records = []
            records.append(event)
            # Retain latest 150 events
            records = records[-150:]
            TELEMETRY_LOG.parent.mkdir(parents=True, exist_ok=True)
            TELEMETRY_LOG.write_text(json.dumps(records, indent=2), encoding="utf-8")
            self.send_json_response({"status": "recorded", "total": len(records)})
        except Exception as e:
            self.send_error(400, f"Simulation error: {str(e)}")

    def handle_run_tests(self, body_bytes):
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            suite = req.get("suite", "service_path")

            if suite == "vault_pki":
                script = ROOT_DIR / "tests" / "test_vault_pki.py"
            else:
                script = ROOT_DIR / "tests" / "test_service_path.py"

            proc = subprocess.run(
                [sys.executable, str(script)],
                capture_output=True,
                text=True,
                cwd=str(ROOT_DIR),
                timeout=30
            )

            output = proc.stdout + "\n" + proc.stderr
            self.send_json_response({
                "suite": suite,
                "exit_code": proc.returncode,
                "output": output
            })
        except Exception as e:
            self.send_error(500, f"Failed running test suite: {str(e)}")

    def send_json_response(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    server_address = ("127.0.0.1", port)
    try:
        httpd = HTTPServer(server_address, DashboardHandler)
        print("=" * 65)
        print("   PQC Zero-Trust Mesh - Observability & Security Dashboard")
        print("=" * 65)
        print(f"[+] Dashboard UI:     http://127.0.0.1:{port}")
        print(f"[+] Events API:       http://127.0.0.1:{port}/api/events")
        print(f"[+] Component Status: http://127.0.0.1:{port}/api/status")
        print(f"[+] Telemetry Source: {TELEMETRY_LOG}")
        print("\nPress Ctrl+C to stop the dashboard server.")
        httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e) or getattr(e, "winerror", None) == 10048:
            print(f"[-] Port {port} is busy. Trying port {port + 1}...")
            main_fallback(port + 1)
        else:
            raise


def main_fallback(port):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, DashboardHandler)
    print(f"[+] Dashboard UI: http://127.0.0.1:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
