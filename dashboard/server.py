#!/usr/bin/env python3
"""
Dashboard Backend Server & Telemetry API
Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
Member 5: Manideep (OPA, Vault & Dashboard)

Serves the visual security observability dashboard and handles:
- GET  /api/events: streams stored telemetry records with their recorded provenance
- GET  /api/status: dashboard status, OPA CLI presence, provenance counts, and Vault engine mode
- POST /api/evaluate-opa: evaluates authz.rego via local OPA CLI or labelled Python fallback (not Envoy ext_authz)
- POST /api/vault/issue: issues/renews certificates via the selected live Vault or emulation engine
- POST /api/vault/revoke: revokes an explicitly supplied serial via the selected engine
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
import re
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
    PKI_COORDINATOR = None

DEFAULT_PORT = 8050


# ==============================================================================
# Helper: Local OPA CLI / Python Policy Evaluator
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

    # Attempt 1: Subprocess opa eval
    try:
        proc = subprocess.run(
            ["opa", "eval", "--data", str(OPA_POLICIES_DIR / "authz.rego"), "--input", "-", "data.authz"],
            input=json.dumps(opa_input),
            capture_output=True,
            text=True,
            timeout=2.0
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
        # Mutating endpoints are local-only and must be called by this UI origin
        # or a trusted local script (which can omit Origin).
        origin = self.headers.get("Origin")
        request_host = self.headers.get("Host", "").lower()
        fetch_site = self.headers.get("Sec-Fetch-Site", "").lower()
        if fetch_site in {"cross-site", "same-site"}:
            self.send_error(403, "Cross-origin requests are not allowed")
            return
        if origin:
            parsed_origin = urllib.parse.urlsplit(origin)
            if (
                parsed_origin.scheme != "http"
                or parsed_origin.netloc.lower() != request_host
                or parsed_origin.hostname not in {"127.0.0.1", "localhost"}
            ):
                self.send_error(403, "Origin does not match the local dashboard")
                return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_error(415, "Content-Type must be application/json")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return
        if content_length < 0 or content_length > 65536:
            self.send_error(413, "Request body too large")
            return

        url = urllib.parse.urlparse(self.path)
        path = url.path
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
            r = subprocess.run(["opa", "version"], capture_output=True, text=True, timeout=2)
            opa_installed = (r.returncode == 0)
        except Exception:
            opa_installed = False

        records = []
        if TELEMETRY_LOG.exists():
            try:
                records = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
            except Exception:
                pass

        # Classify events from their recorded provenance, not the legacy
        # isGenuine boolean. Older versions incorrectly tagged emulation and
        # in-process test-harness events as genuine and treated missing tags
        # as simulated.
        live_vault_events = 0
        local_opa_cli_events = 0
        test_harness_events = 0
        emulation_events = 0
        explicitly_simulated_events = 0
        unclassified_events = 0

        for event in records:
            if (
                event.get("isLiveVault") is True
                or event.get("vaultBackend") == "LIVE_VAULT_HTTP_API"
                or event.get("provenance") == "live_vault_pki"
            ):
                live_vault_events += 1
            elif (
                event.get("evaluator") == "opa_cli_v1"
                or event.get("verificationMode") in {
                    "local_opa_cli_evaluation",
                    "live_opa_ext_authz"  # legacy label used for a local opa eval call
                }
            ):
                local_opa_cli_events += 1
            elif event.get("provenance") in {
                "live_service_path_mtls",
                "python_in_process_tls_test_harness"
            }:
                test_harness_events += 1
            elif (
                event.get("vaultBackend") == "STANDALONE_CRYPTOGRAPHIC_EMULATION"
                or event.get("provenance") == "standalone_cryptographic_emulation"
            ):
                emulation_events += 1
            elif event.get("isGenuine") is False or event.get("source") == "manual_simulation":
                explicitly_simulated_events += 1
            else:
                unclassified_events += 1

        legacy_marked_genuine = sum(1 for e in records if e.get("isGenuine") is True)
        legacy_missing_flag = sum(1 for e in records if "isGenuine" not in e)

        vault_status = PKI_COORDINATOR.get_integration_status() if PKI_COORDINATOR else {}

        status = {
            "status": "healthy",
            "dashboard_status": "healthy",
            "opa_installed": opa_installed,
            "opa_request_path_health": "not_checked",
            "telemetry_log_exists": TELEMETRY_LOG.exists(),
            "total_events": len(records),
            "live_vault_events": live_vault_events,
            "local_opa_cli_evaluations": local_opa_cli_events,
            "test_harness_events": test_harness_events,
            "emulation_events": emulation_events,
            "explicitly_simulated_events": explicitly_simulated_events,
            "unclassified_legacy_events": unclassified_events,
            "legacy_events_marked_genuine": legacy_marked_genuine,
            "legacy_events_missing_isGenuine": legacy_missing_flag,
            "vault_engine_mode": vault_status.get("engine_mode", "STANDALONE_CRYPTOGRAPHIC_EMULATION"),
            "live_vault_healthy": vault_status.get("live_vault_healthy", False),
            "pqc_key_establishment": {
                "prototype": ["X25519 + ML-KEM-768"],
                "captured_tls_group": ["X25519MLKEM768"]
            },
            "post_quantum_signatures": {
                "implemented": [],
                "planned": ["ML-DSA-65"]
            }
        }
        self.send_json_response(status)

    def handle_get_vault_status(self):
        if PKI_COORDINATOR:
            self.send_json_response(PKI_COORDINATOR.get_integration_status())
        else:
            self.send_json_response({"error": "Vault coordinator uninitialized"}, status=503)

    def handle_evaluate_opa(self, body_bytes):
        """Runs a local policy evaluation and labels the backend; this is not Envoy ext_authz."""
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
                "verificationMode": "local_opa_cli_evaluation" if is_genuine_opa else "python_policy_fallback",
                "source": "local_opa_cli" if is_genuine_opa else "python_embedded_fallback",
                "details": (
                    f"Local OPA CLI evaluation (not an Envoy ext_authz network-path test): {'ALLOW' if allow else 'DENY'} ({reason})"
                    if is_genuine_opa else
                    f"Python fallback evaluation (OPA CLI unavailable): {'ALLOW' if allow else 'DENY'} ({reason})"
                )
            }

            self._append_telemetry(event)
            self.send_json_response({
                "decision": allow,
                "reason": reason,
                "eval_duration_ms": eval_res["eval_duration_ms"],
                "evaluator": evaluator,
                "event": event
            })
        except Exception as e:
            self.send_error(400, f"OPA Evaluation failed: {str(e)}")

    def handle_vault_issue(self, body_bytes):
        """Issues a workload certificate through the configured live/emulated engine."""
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            common_name = req.get("common_name", "frontend")
            is_server = req.get("is_server", False)
            if common_name not in {"frontend", "backend"} or not isinstance(is_server, bool):
                self.send_error(400, "common_name must be frontend/backend and is_server must be boolean")
                return
            if not PKI_COORDINATOR:
                self.send_error(503, "Vault engine unavailable")
                return

            cert_f, key_f, serial, version = PKI_COORDINATOR.renew_certificate(common_name, is_server=is_server)
            live_vault = PKI_COORDINATOR.engine_mode == "LIVE_VAULT_HTTP_API"
            self.send_json_response({
                "status": "success",
                "common_name": common_name,
                "version": version,
                "serial": serial,
                "backend": PKI_COORDINATOR.engine_mode,
                "isGenuine": live_vault,
                "provenance": "live_vault_pki" if live_vault else "standalone_cryptographic_emulation"
            })
        except Exception as e:
            self.send_error(500, f"Vault issuance error: {str(e)}")

    def handle_vault_revoke(self, body_bytes):
        """Revokes an explicitly identified certificate through the configured engine."""
        try:
            req = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            serial = req.get("serial")
            if not isinstance(serial, str) or not re.fullmatch(r"[0-9A-Fa-f:-]{8,128}", serial):
                self.send_error(400, "A valid certificate serial is required; no default certificate will be selected")
                return
            if not PKI_COORDINATOR:
                self.send_error(503, "Vault engine unavailable")
                return

            revoked = PKI_COORDINATOR.revoke_certificate(serial, reason="emergency_dashboard_trigger")
            live_vault = PKI_COORDINATOR.engine_mode == "LIVE_VAULT_HTTP_API"
            self.send_json_response({
                "status": "revoked" if revoked else "not_found",
                "serial": serial,
                "backend": PKI_COORDINATOR.engine_mode,
                "isGenuine": live_vault,
                "provenance": "live_vault_pki" if live_vault else "standalone_cryptographic_emulation"
            })
        except Exception as e:
            self.send_error(500, f"Vault revocation error: {str(e)}")

    def handle_simulate(self, body_bytes):
        try:
            event = json.loads(body_bytes.decode("utf-8"))
            # Never trust client-supplied provenance for simulated events.
            event["isGenuine"] = False
            event["source"] = "manual_simulation"
            event["provenance"] = "manual_simulation"
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
        self.send_header("X-Content-Type-Options", "nosniff")
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
