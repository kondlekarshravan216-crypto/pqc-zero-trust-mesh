#!/usr/bin/env python3
"""
Automated Runtime Telemetry & API Test Suite for Security Observability Dashboard
Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
Member 5: Manideep (OPA, Vault & Dashboard)

Tests:
1. Dashboard Health, Live OPA CLI & Vault Engine Status (GET /api/status, /api/vault/status)
2. Telemetry Audit Stream, Event Schema & Static UI Delivery (GET /api/events, /api/schema, /)
3. Live OPA Policy Evaluation & Genuine Telemetry Persistence (POST /api/evaluate-opa)
4. Dashboard Vault PKI Issuance, Emergency Revocation & Telemetry Provenance (POST /api/vault/issue, /api/vault/revoke)
"""

import sys
import json
import threading
import datetime as dt
import urllib.request
import urllib.error
from http.server import HTTPServer
from pathlib import Path
from typing import Tuple, Any

ROOT_DIR = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT_DIR / "tests"
sys.path.insert(0, str(ROOT_DIR / "dashboard"))

import server as dashboard_server  # noqa: E402

TOTAL_TESTS = 0
PASSED_TESTS = 0
FAILED_TESTS = 0
TEST_RESULTS = []


def record_result(category: str, name: str, expected: str, actual: str, passed: bool, details: str = ""):
    global TOTAL_TESTS, PASSED_TESTS, FAILED_TESTS
    TOTAL_TESTS += 1
    if passed:
        PASSED_TESTS += 1
        status = "PASS"
    else:
        FAILED_TESTS += 1
        status = "FAIL"

    TEST_RESULTS.append({
        "id": TOTAL_TESTS,
        "category": category,
        "name": name,
        "expected": expected,
        "actual": actual,
        "status": status,
        "details": details,
    })

    print(f"[{status}] Test {TOTAL_TESTS}: {name}")
    print(f"       Expected: {expected} | Actual: {actual}")
    if details:
        print(f"       Details:  {details}")


def http_get(base_url: str, path: str) -> Tuple[int, Any]:
    req = urllib.request.Request(f"{base_url}{path}", method="GET")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            return resp.status, json.loads(raw)
        return resp.status, raw


def http_post_json(base_url: str, path: str, payload: dict) -> Tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def main():
    print("=" * 65)
    print("   PQC Zero-Trust Mesh - Dashboard Runtime Telemetry Suite")
    print("=" * 65)

    httpd = HTTPServer(("127.0.0.1", 0), dashboard_server.DashboardHandler)
    port = httpd.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    srv_thread.start()
    print(f"[+] Dashboard test server listening on {base_url}")

    try:
        # Test 1: /api/status and /api/vault/status
        code_status, status_data = http_get(base_url, "/api/status")
        code_vault, vault_data = http_get(base_url, "/api/vault/status")
        counts_consistent = (
            status_data.get("genuine_events", -1) + status_data.get("simulated_events", -1)
            == status_data.get("total_events", -2)
        )
        t1_pass = (
            code_status == 200
            and code_vault == 200
            and status_data.get("status") == "healthy"
            and status_data.get("opa_installed") is True
            and bool(status_data.get("ca_serial"))
            and counts_consistent
            and vault_data.get("engine_mode") in ("LIVE_VAULT_HTTP_API", "STANDALONE_CRYPTOGRAPHIC_EMULATION")
        )
        record_result(
            "Dashboard Status",
            "Dashboard Health, OPA CLI & Vault Engine Status (/api/status)",
            "HTTP 200, healthy=True, opa_installed=True, valid CA serial & event counts",
            f"HTTP {code_status}, opa={status_data.get('opa_installed')}, vault_mode={status_data.get('vault_engine_mode')}, live_vault={status_data.get('live_vault_healthy')}",
            t1_pass,
            f"CA Serial: {status_data.get('ca_serial', '')[:16]}..., Total Events: {status_data.get('total_events')}",
        )

        # Test 2: /api/events, /api/schema, and static UI /
        code_ui, ui_html = http_get(base_url, "/")
        code_events, events_data = http_get(base_url, "/api/events")
        code_schema, schema_data = http_get(base_url, "/api/schema")
        t2_pass = (
            code_ui == 200
            and "Zero-Trust Security Mesh Observability" in ui_html
            and code_events == 200
            and isinstance(events_data, list)
            and len(events_data) > 0
            and code_schema == 200
            and isinstance(schema_data, dict)
            and len(schema_data) > 0
        )
        record_result(
            "Telemetry Stream",
            "Telemetry Stream, Schema & Dashboard UI Delivery (/api/events, /api/schema)",
            "HTTP 200 for UI HTML, non-empty JSON event stream, and telemetry schema",
            f"UI={code_ui}, events={len(events_data) if isinstance(events_data, list) else 'err'}, schema_keys={len(schema_data) if isinstance(schema_data, dict) else 0}",
            t2_pass,
            "Verified live dashboard HTML + audit_log.json streaming",
        )

        # Test 3: Live OPA Evaluation (/api/evaluate-opa) ALLOW & DENY + Genuine Provenance
        c_allow, r_allow = http_post_json(
            base_url,
            "/api/evaluate-opa",
            {
                "caller_identity": "spiffe://pqzt.local/ns/demo/sa/frontend",
                "destination": "backend",
                "action": "GET",
                "path": "/api/v1/resource",
            },
        )
        c_lateral, r_lateral = http_post_json(
            base_url,
            "/api/evaluate-opa",
            {
                "caller_identity": "spiffe://pqzt.local/ns/demo/sa/frontend",
                "destination": "database",
                "action": "GET",
                "path": "/database/credentials",
            },
        )
        c_rogue, r_rogue = http_post_json(
            base_url,
            "/api/evaluate-opa",
            {
                "caller_identity": "spiffe://pqzt.local/ns/demo/sa/unapproved-attacker",
                "destination": "backend",
                "action": "GET",
                "path": "/api/v1/resource",
            },
        )
        _, updated_events = http_get(base_url, "/api/events")
        recent_opa = [e for e in updated_events[-5:] if e.get("evaluator") == "opa_cli_v1"]

        t3_pass = (
            c_allow == 200
            and r_allow.get("decision") is True
            and r_allow.get("event", {}).get("evaluator") == "opa_cli_v1"
            and r_allow.get("event", {}).get("isGenuine") is True
            and c_lateral == 200
            and r_lateral.get("decision") is False
            and r_lateral.get("event", {}).get("evaluator") == "opa_cli_v1"
            and r_lateral.get("event", {}).get("isGenuine") is True
            and c_rogue == 200
            and r_rogue.get("decision") is False
            and len(recent_opa) >= 3
        )
        record_result(
            "OPA Runtime Evaluator",
            "Live OPA Evaluation & Genuine Telemetry Persistence (/api/evaluate-opa)",
            "ALLOW=True, Lateral DENY=False, Rogue DENY=False via opa_cli_v1 (isGenuine=True)",
            f"allow={r_allow.get('decision')}, lateral={r_lateral.get('decision')}, rogue={r_rogue.get('decision')}, evaluator={r_allow.get('event', {}).get('evaluator')}",
            t3_pass,
            f"Recorded {len(recent_opa)} genuine opa_cli_v1 events in audit stream",
        )

        # Test 4: Dashboard Vault PKI Issuance & Revocation (/api/vault/issue, /api/vault/revoke)
        c_issue, r_issue = http_post_json(
            base_url,
            "/api/vault/issue",
            {"common_name": "frontend", "is_server": False},
        )
        issued_serial = r_issue.get("serial", "")
        c_revoke, r_revoke = http_post_json(
            base_url,
            "/api/vault/revoke",
            {"serial": issued_serial},
        )
        # Also verify empty-body emergency revoke does not fail with null serial
        c_auto_revoke, r_auto_revoke = http_post_json(base_url, "/api/vault/revoke", {})
        _, post_vault_events = http_get(base_url, "/api/events")
        serials_in_log = {e.get("serialNumber") for e in post_vault_events[-10:]}

        t4_pass = (
            c_issue == 200
            and r_issue.get("status") == "success"
            and bool(issued_serial)
            and r_issue.get("isGenuine") is True
            and c_revoke == 200
            and r_revoke.get("status") == "revoked"
            and r_revoke.get("serial") == issued_serial
            and c_auto_revoke == 200
            and r_auto_revoke.get("status") == "revoked"
            and bool(r_auto_revoke.get("serial"))
            and issued_serial in serials_in_log
        )
        record_result(
            "Vault Runtime Telemetry",
            "Dashboard Vault PKI Issue & CRL Revoke Telemetry (/api/vault/issue, /api/vault/revoke)",
            "Issue returns active serial, Revoke updates CRL & appends genuine telemetry",
            f"issue={r_issue.get('status')} ({issued_serial[:12]}...), revoke={r_revoke.get('status')}, backend={r_issue.get('backend')}",
            t4_pass,
            "Verified both targeted serial revocation and automatic active serial revocation",
        )
    finally:
        httpd.shutdown()
        httpd.server_close()

    print("\n" + "=" * 65)
    print("                   SUMMARY OF RESULTS")
    print("=" * 65)
    print(f"Total Tests Executed: {TOTAL_TESTS}")
    print(f"Passed:                {PASSED_TESTS}")
    print(f"Failed:                {FAILED_TESTS}")

    report_file = TESTS_DIR / "results-dashboard.md"
    lines = [
        "# Security Observability Dashboard Runtime Telemetry Results",
        f"**Date**: {dt.datetime.now(dt.timezone.utc).isoformat()}  ",
        "**Module**: Security Observability Dashboard (`dashboard/server.py`)  ",
        f"**Status**: {'ALL TESTS PASSED (100%)' if FAILED_TESTS == 0 else 'TESTS FAILED'}  ",
        "",
        "## Summary of Test Results",
        "",
        "| ID | Category | Test Name | Expected | Actual | Status | Details |",
        "| :---: | :--- | :--- | :--- | :--- | :---: | :--- |",
    ]
    for t in TEST_RESULTS:
        lines.append(
            f"| {t['id']} | {t['category']} | {t['name']} | `{t['expected']}` | `{t['actual']}` | **{t['status']}** | {t['details']} |"
        )
    lines.extend([
        "",
        f"**Summary**: **{PASSED_TESTS} / {TOTAL_TESTS} Tests Passed ({(PASSED_TESTS / TOTAL_TESTS) * 100:.1f}%)**.",
    ])
    report_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[+] Detailed markdown report generated at: {report_file.name}")

    sys.exit(1 if FAILED_TESTS > 0 else 0)


if __name__ == "__main__":
    main()
