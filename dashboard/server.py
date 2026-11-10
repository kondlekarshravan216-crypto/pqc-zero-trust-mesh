#!/usr/bin/env python3
"""
Dashboard Backend Server & Telemetry API
Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
Member 5: Manideep (OPA, Vault & Dashboard)

Serves the visual security observability dashboard and handles:
- GET  /api/events: streams verified OPA authorization and Vault PKI certificate events
- GET  /api/status: component health, genuine vs simulated event distribution, engine modes
- POST /api/evaluate-opa: executes genuine OPA policy evaluations against authz.rego
- POST /api/vault/issue: issues/renews workload certificates via Vault PKI Engine
- POST /api/vault/revoke: executes emergency revocation and CRL update via Vault PKI Engine
- POST /api/simulate: records simulated/synthetic events
- POST /api/run-tests: executes automated test suites on-demand
- Static files: index.html, css/index.css, js/app.js
"""

import sys
import os
import json
import time
import subprocess
import datetime as dt
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT_DIR / "dashboard"
OPA_POLICIES_DIR = ROOT_DIR / "opa" / "policies"
TELEMETRY_LOG = ROOT_DIR / "opa" / "telemetry" / "audit_log.json"
SCHEMA_FILE = ROOT_DIR / "opa" / "telemetry" / "dashboard_events.json"

sys.path.insert(0, str(ROOT_DIR / "vault" / "scripts"))
try:
    from vault_pki_coordinator import VaultPKIEngine
    PKI_COORDINATOR = VaultPKIEngine()
except Exception:
    VaultPKIEngine = None
    PKI_COORDINATOR = None


def get_pki_coordinator():
    """Returns a VaultPKIEngine synchronized with current Vault daemon availability."""
    global PKI_COORDINATOR
    if VaultPKIEngine is None:
        return None
    if PKI_COORDINATOR is None:
        try:
            PKI_COORDINATOR = VaultPKIEngine()
        except Exception:
            return None
        return PKI_COORDINATOR

    live_healthy = PKI_COORDINATOR.api_client.check_health()
    if live_healthy and PKI_COORDINATOR.engine_mode != "LIVE_VAULT_HTTP_API":
        PKI_COORDINATOR = VaultPKIEngine()
    elif not live_healthy and PKI_COORDINATOR.engine_mode == "LIVE_VAULT_HTTP_API":
        PKI_COORDINATOR = VaultPKIEngine()
    return PKI_COORDINATOR

DEFAULT_PORT = 8050


# ==============================================================================
# Helper: Genuine OPA Evaluator
# ==============================================================================
def evaluate_opa_policy(caller_identity: str, destination: str, action: str, path: str = "") -> Dict[str, Any]:
    """
    Evaluates policy directly against opa/policies/authz.rego.
    Tries 'opa eval' CLI first, with deterministic internal zero-trust engine fallback.
    """
    start_time = time.perf_counter()
    opa_input = {
        "identity": caller_identity,
        "destination": destination,
        "action": action,
        "attributes": {
            "source": {"principal": caller_identity},
            "request": {
                "http": {
                    "method": action,
                    "path": path or ("/database" if destination == "database" else "/api/v1/resource")
                }
            }
        }
    }

    # Attempt 1: Subprocess opa eval (--stdin-input reads JSON input from stdin)
    try:
        proc = subprocess.run(
            ["opa", "eval", "--data", str(OPA_POLICIES_DIR / "authz.rego"), "--stdin-input", "data.authz"],
            input=json.dumps(opa_input),
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False
        )
        if proc.returncode == 0:
            parsed = json.loads(proc.stdout)
            result = parsed.get("result", [{}])[0].get("expressions", [{}])[0].get("value", {})
            duration_ms = (time.perf_counter() - start_time) * 1000
            return {
                "allow": bool(result.get("allow", False)),
                "reason": result.get("reason", "OPA Policy Evaluation"),
                "eval_duration_ms": round(duration_ms, 2),
                "evaluator": "opa_cli_v1"
            }
    except Exception:
        pass

    # Attempt 2: High-fidelity Python evaluation matching authz.rego rules
    approved_frontends = {
        "frontend",
        "frontend-service",
        "spiffe://cluster.local/ns/mesh/sa/frontend-service",
        "spiffe://pqzt.local/ns/demo/sa/frontend",
    }
    approved_backends = {
        "backend",
        "backend-service",
        "spiffe://cluster.local/ns/mesh/sa/backend-service",
        "spiffe://pqzt.local/ns/demo/sa/backend",
    }
    read_actions = {"GET", "get", "read", "HEAD", "head"}

    allow = False
    reason = "Access denied: unapproved identity or unauthorized destination"

    if destination == "backend" and caller_identity in approved_frontends and action in read_actions:
        allow = True
        reason = "Access granted: approved frontend identity accessing backend"
    elif destination == "database" and caller_identity in approved_backends and action in read_actions:
        allow = True
        reason = "Access granted: approved backend identity accessing database"
    elif destination == "database" and caller_identity not in approved_backends:
        allow = False
        reason = "Access denied: lateral movement to database prevented"
    elif (caller_identity in approved_frontends or caller_identity in approved_backends) and action not in read_actions:
        allow = False
        reason = "Access denied: unauthorized mutating HTTP action"

    duration_ms = (time.perf_counter() - start_time) * 1000
    return {
        "allow": allow,
        "reason": reason,
        "eval_duration_ms": round(duration_ms, 2),
        "evaluator": "rego_embedded_engine"
    }


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
        elif path == "/api/vault/status":
            self.handle_get_vault_status()
        else:
            # Fall back to serving static files from dashboard/
            super().do_GET()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        if path == "/api/evaluate-opa":
            self.handle_evaluate_opa(post_data)
        elif path == "/api/vault/issue":
            self.handle_vault_issue(post_data)
        elif path == "/api/vault/revoke":
            self.handle_vault_revoke(post_data)
        elif path == "/api/simulate":
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
        opa_installed = False
        try:
            r = subprocess.run(["opa", "version"], capture_output=True, text=True, timeout=2, check=False)
            opa_installed = (r.returncode == 0)
        except Exception:
            opa_installed = False

        records = []
        if TELEMETRY_LOG.exists():
            try:
                records = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
            except Exception:
                pass

        genuine_count = sum(1 for e in records if e.get("isGenuine") is True)
        simulated_count = len(records) - genuine_count

        coordinator = get_pki_coordinator()
        vault_status = coordinator.get_integration_status() if coordinator else {}

        status = {
            "status": "healthy",
            "opa_installed": opa_installed,
            "telemetry_log_exists": TELEMETRY_LOG.exists(),
            "total_events": len(records),
            "genuine_events": genuine_count,
            "simulated_events": simulated_count,
            "genuine_rate_pct": round((genuine_count / len(records) * 100), 1) if records else 100.0,
            "vault_engine_mode": vault_status.get("engine_mode", "STANDALONE_CRYPTOGRAPHIC_EMULATION"),
            "live_vault_healthy": vault_status.get("live_vault_healthy", False),
            "ca_serial": vault_status.get("ca_serial", ""),
            "pqc_ciphers": ["Hybrid ECDH-P256 + ML-KEM-768", "ML-DSA-65"]
        }
        self.send_json_response(status)

    def handle_get_vault_status(self):
        coordinator = get_pki_coordinator()
        if coordinator:
            self.send_json_response(coordinator.get_integration_status())
        else:
            self.send_json_response({"error": "Vault coordinator uninitialized"}, status=503)

    def handle_evaluate_opa(self, body_bytes):
        """Executes a genuine real-time OPA evaluation and emits a genuine audit event."""
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            caller = req.get("caller_identity", "spiffe://pqzt.local/ns/demo/sa/frontend")
            dest = req.get("destination", "backend")
            action = req.get("action", "GET")
            path = req.get("path", "/api/v1/resource")

            eval_res = evaluate_opa_policy(caller, dest, action, path)
            allow = eval_res["allow"]
            reason = eval_res["reason"]
            evaluator = eval_res["evaluator"]

            # Distinguish genuine OPA CLI evaluations from Python fallback
            is_genuine_opa = (evaluator == "opa_cli_v1")

            now = dt.datetime.now(dt.timezone.utc)
            event = {
                "timestamp": now.isoformat(),
                "eventType": "allowed_request" if allow else "denied_request",
                "category": "authorization",
                "severity": "INFO" if allow else "WARNING",
                "sourceIdentity": caller,
                "destinationService": dest,
                "action": action,
                "path": path,
                "decision": allow,
                "reason": reason,
                "evalDurationMs": eval_res["eval_duration_ms"],
                "evaluator": evaluator,
                "isGenuine": is_genuine_opa,
                "verificationMode": "live_opa_ext_authz" if is_genuine_opa else "python_policy_fallback",
                "source": "live_request_evaluator" if is_genuine_opa else "python_embedded_fallback",
                "details": (
                    f"Genuine ext_authz decision: {'ALLOW' if allow else 'DENY'} ({reason})"
                    if is_genuine_opa else
                    f"Python fallback evaluation (OPA CLI unavailable): {'ALLOW' if allow else 'DENY'} ({reason})"
                )
            }

            self._append_telemetry(event)
            self.send_json_response({
                "decision": allow,
                "reason": reason,
                "eval_duration_ms": eval_res["eval_duration_ms"],
                "event": event
            })
        except Exception as e:
            self.send_error(400, f"OPA Evaluation failed: {str(e)}")

    def handle_vault_issue(self, body_bytes):
        """Invokes Vault PKI engine to issue a genuine workload certificate."""
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            common_name = req.get("common_name", "frontend")
            is_server = bool(req.get("is_server", False))
            coordinator = get_pki_coordinator()
            if not coordinator:
                self.send_error(503, "Vault engine unavailable")
                return

            _, _, serial, version = coordinator.renew_certificate(common_name, is_server=is_server)
            self.send_json_response({
                "status": "success",
                "common_name": common_name,
                "version": version,
                "serial": serial,
                "backend": coordinator.engine_mode,
                "isGenuine": True
            })
        except Exception as e:
            self.send_error(500, f"Vault issuance error: {str(e)}")

    def handle_vault_revoke(self, body_bytes):
        """Invokes Vault PKI engine to execute emergency revocation."""
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            serial = req.get("serial")
            coordinator = get_pki_coordinator()
            if not coordinator:
                self.send_error(503, "Vault engine unavailable")
                return

            if not serial:
                active_serials = [
                    s for s, meta in coordinator.certificates.items()
                    if meta.get("status") == "ACTIVE"
                ]
                if active_serials:
                    serial = active_serials[0]
                else:
                    _, _, serial, _ = coordinator.renew_certificate("frontend", is_server=False)

            revoked = coordinator.revoke_certificate(serial, reason="emergency_dashboard_trigger")
            self.send_json_response({
                "status": "revoked" if revoked else "not_found",
                "serial": serial,
                "backend": coordinator.engine_mode,
                "isGenuine": True
            })
        except Exception as e:
            self.send_error(500, f"Vault revocation error: {str(e)}")

    def handle_simulate(self, body_bytes):
        try:
            event = json.loads(body_bytes.decode("utf-8"))
            if "isGenuine" not in event:
                event["isGenuine"] = False
            if "source" not in event:
                event["source"] = "manual_simulation"
            records = self._append_telemetry(event)
            self.send_json_response({"status": "recorded", "total": len(records)})
        except Exception as e:
            self.send_error(400, f"Simulation error: {str(e)}")

    def _append_telemetry(self, event: dict) -> list:
        records = []
        if TELEMETRY_LOG.exists():
            try:
                records = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
            except Exception:
                records = []
        records.append(event)
        records = records[-150:]
        TELEMETRY_LOG.parent.mkdir(parents=True, exist_ok=True)
        TELEMETRY_LOG.write_text(json.dumps(records, indent=2), encoding="utf-8")
        return records

    def handle_run_tests(self, body_bytes):
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            suite = req.get("suite", "service_path")

            if suite == "vault_pki":
                cmd = [sys.executable, str(ROOT_DIR / "tests" / "test_vault_pki.py")]
            elif suite == "dashboard":
                cmd = [sys.executable, str(ROOT_DIR / "tests" / "test_dashboard.py")]
            elif suite == "opa":
                if os.name == "nt":
                    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ROOT_DIR / "tests" / "test_opa.ps1")]
                else:
                    cmd = ["bash", str(ROOT_DIR / "tests" / "test_opa.sh")]
            else:
                cmd = [sys.executable, str(ROOT_DIR / "tests" / "test_service_path.py")]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(ROOT_DIR),
                timeout=60,
                check=False
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
        print(f"[+] OPA Evaluator:    http://127.0.0.1:{port}/api/evaluate-opa")
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
