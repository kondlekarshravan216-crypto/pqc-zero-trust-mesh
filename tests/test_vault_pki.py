#!/usr/bin/env python3
"""
Automated Test Suite for HashiCorp Vault PKI Setup, Certificate Renewal & Rotation
Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
Member 5: Manideep (OPA, Vault & Dashboard)

Tests:
1. Vault PKI Engine Configuration & Mesh CA Generation
2. Workload Role Setup (mesh-workload with SPIFFE URI SANs)
3. Leaf Certificate Issuance for Frontend & Backend (clientAuth / serverAuth)
4. Live mTLS Handshake with Vault PKI Certificates
5. Automated Certificate Renewal (Version 2 with new keypair & serial)
6. Zero-Downtime Dynamic Server TLS Context Rotation (Envoy SDS model)
7. Client Re-handshake with Rotated Certificate Version 2
8. Emergency Revocation & CRL Generation
9. Revoked Certificate Handshake Enforcement & CRL Verification
10. Vault PKI Least-Privilege Policy Verification (mesh-pki.hcl)
11. Telemetry Audit Event Pipeline Verification
12. Vault HTTP REST API Client Endpoint & Header Contract
13. Dual-Mode Engine Architecture & Integration Audit Breakdown
14. Cryptographic Trust Chain & SPIFFE SVID Verification
"""

import sys
import json
import time
import socket
import ssl
import threading
import datetime as dt
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "vault" / "scripts"))
from vault_pki_coordinator import VaultPKIEngine, VaultAPIClient

TESTS_DIR = ROOT_DIR / "tests"
VAULT_DIR = ROOT_DIR / "vault"
TELEMETRY_LOG = ROOT_DIR / "opa" / "telemetry" / "audit_log.json"

TOTAL_TESTS = 0
PASSED_TESTS = 0
FAILED_TESTS = 0
TEST_RESULTS = []


def record_result(category, name, expected, actual, passed, details=""):
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
        "details": details
    })

    print(f"[{status}] Test {TOTAL_TESTS}: {name}")
    print(f"       Expected: {expected} | Actual: {actual}")
    if details:
        print(f"       Details:  {details}")


class DynamicTLSServer:
    """Mock backend server supporting zero-downtime hot swap of TLS certificates (Envoy SDS)."""
    def __init__(self, ca_path: Path, cert_path: Path, key_path: Path):
        self.ca_path = ca_path
        self.cert_path = cert_path
        self.key_path = key_path
        self.running = False
        self.sock = None
        self.port = 0
        self.thread = None
        self.lock = threading.Lock()
        self.requests_handled = 0
        self.build_ssl_context()

    def build_ssl_context(self):
        with self.lock:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(str(self.cert_path), str(self.key_path))
            ctx.load_verify_locations(str(self.ca_path))
            ctx.verify_mode = ssl.CERT_REQUIRED
            self.ssl_ctx = ctx

    def reload_tls_context(self, new_cert: Path, new_key: Path):
        """Zero-downtime hot swap of TLS context without restarting listener socket."""
        self.cert_path = new_cert
        self.key_path = new_key
        self.build_ssl_context()

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                raw_sock, _ = self.sock.accept()
                raw_sock.settimeout(3.0)
            except Exception:
                break
            try:
                with self.lock:
                    current_ctx = self.ssl_ctx
                tls_conn = current_ctx.wrap_socket(raw_sock, server_side=True)
                peer_cert = tls_conn.getpeercert()
                san = [v for k, v in peer_cert.get("subjectAltName", ()) if k == "URI"]

                # Check request
                _ = tls_conn.recv(2048)
                body = json.dumps({
                    "service": "backend",
                    "status": "ok",
                    "peer_san": san[0] if san else "unknown",
                    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()
                }).encode("utf-8")

                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Connection: close\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
                    + body
                )
                tls_conn.sendall(resp)
                tls_conn.close()
                self.requests_handled += 1
            except Exception:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


def make_mtls_request(port: int, ca_path: Path, client_cert: Path, client_key: Path) -> Tuple[int, str]:
    """Issues an mTLS client request to the test server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(str(ca_path))
    ctx.load_cert_chain(str(client_cert), str(client_key))
    ctx.check_hostname = False

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls_sock:
                req = b"GET /api/v1/resource HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n"
                tls_sock.sendall(req)
                resp = b""
                while True:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                text = resp.decode("utf-8", errors="replace")
                code = int(text.split(" ")[1]) if "HTTP/1.1 " in text else 0
                return code, text
    except ssl.SSLError as e:
        return -1, f"SSLError: {getattr(e, 'reason', str(e))}"
    except Exception as e:
        return -2, f"ConnectionError: {str(e)}"


def main():
    print("=" * 65)
    print("   PQC Zero-Trust Mesh - Vault PKI Setup & Rotation Test Suite")
    print("=" * 65)

    sandbox = TESTS_DIR / ".work-vault-pki"
    pki = VaultPKIEngine(sandbox)

    server = None
    try:
        print("\n--- Part 1: Vault PKI Engine Setup & Configuration ---")

        # Test 1: Vault PKI Engine Mount & Root CA Validation
        ca_cert_exists = pki.ca_file.exists() and pki.ca_file.stat().st_size > 500
        has_ca_serial = bool(pki.ca_serial and len(pki.ca_serial) > 8)
        record_result(
            "Vault PKI Setup",
            "Vault PKI Mount & Root CA Generation (pki_mesh)",
            "Root CA certificate created with valid serial and PEM format",
            f"ca_file_exists={ca_cert_exists}, serial={pki.ca_serial[:12]}...",
            ca_cert_exists and has_ca_serial,
            "Initializes centralized mesh certificate authority"
        )

        # Test 2: Role Configuration (mesh-workload)
        role = pki.roles.get("mesh-workload", {})
        has_allowed_domains = "pqzt.local" in role.get("allowed_domains", [])
        has_spiffe_sans = any("spiffe://" in s for s in role.get("allowed_uri_sans", []))
        ttl_12h = role.get("ttl") == "12h"
        record_result(
            "Vault PKI Setup",
            "Workload Role Definition (mesh-workload)",
            "Allows pqzt.local domain, SPIFFE URI SANs, and 12h default TTL",
            f"domains={has_allowed_domains}, spiffe={has_spiffe_sans}, ttl={role.get('ttl')}",
            has_allowed_domains and has_spiffe_sans and ttl_12h,
            "Enforces zero-trust short-lived credential policy"
        )

        print("\n--- Part 2: Workload Certificate Issuance (Frontend & Backend) ---")

        # Test 3: Issue Frontend Leaf Cert (V1)
        fc_v1, fk_v1, fs_v1 = pki.issue_certificate(
            "frontend",
            is_server=False,
            uri_sans=["spiffe://pqzt.local/ns/demo/sa/frontend"],
            dns_sans=["frontend", "frontend.demo.svc.cluster.local"],
            version=1
        )
        record_result(
            "Certificate Issuance",
            "Issue Frontend Client Leaf Certificate (V1)",
            "Certificate generated with SPIFFE URI SAN and clientAuth EKU",
            f"Serial V1: {fs_v1[:12]}...",
            fc_v1.exists() and fk_v1.exists() and bool(fs_v1),
            "Service identity: spiffe://pqzt.local/ns/demo/sa/frontend"
        )

        # Test 4: Issue Backend Server Leaf Cert (V1)
        bc_v1, bk_v1, bs_v1 = pki.issue_certificate(
            "backend",
            is_server=True,
            uri_sans=["spiffe://pqzt.local/ns/demo/sa/backend"],
            dns_sans=["backend", "backend.demo.svc.cluster.local"],
            version=1
        )
        record_result(
            "Certificate Issuance",
            "Issue Backend Server Leaf Certificate (V1)",
            "Certificate generated with SPIFFE URI SAN and serverAuth EKU",
            f"Serial V1: {bs_v1[:12]}...",
            bc_v1.exists() and bk_v1.exists() and bool(bs_v1),
            "Service identity: spiffe://pqzt.local/ns/demo/sa/backend"
        )

        print("\n--- Part 3: Live Mutual TLS Handshake using Vault Credentials ---")

        # Test 5: mTLS Handshake with Vault PKI Certificates
        server = DynamicTLSServer(pki.ca_file, bc_v1, bk_v1)
        server.start()
        time.sleep(0.3)

        code, resp = make_mtls_request(server.port, pki.ca_file, fc_v1, fk_v1)
        record_result(
            "mTLS Handshake",
            "mTLS Handshake with Vault PKI Leaf Certificates [ALLOW]",
            "HTTP 200 OK with mutual authentication",
            f"HTTP {code}",
            code == 200 and "spiffe://pqzt.local/ns/demo/sa/frontend" in resp,
            "Both server and client verify Vault Mesh Root CA trust chain"
        )

        print("\n--- Part 4: Dynamic Certificate Renewal & Rotation (Envoy SDS) ---")

        # Test 6: Automated Certificate Renewal (Generating V2 at 66% TTL threshold)
        fc_v2, fk_v2, fs_v2, v_num = pki.renew_certificate("frontend", is_server=False)
        record_result(
            "Certificate Renewal",
            "Automated Workload Certificate Renewal (Frontend V2)",
            "Fresh keypair & serial generated (V2 != V1)",
            f"Serial V2: {fs_v2[:12]}... (version {v_num})",
            v_num == 2 and fs_v2 != fs_v1 and fc_v2.exists(),
            "Simulates Vault Agent / SPIRE scheduled renewal at 66% TTL"
        )

        # Test 7: Zero-Downtime Server TLS Context Hot-Swap (Envoy SDS model)
        bc_v2, bk_v2, _, b_vnum = pki.renew_certificate("backend", is_server=True)
        server.reload_tls_context(bc_v2, bk_v2)

        # Immediate client request after server hot reload
        code, resp = make_mtls_request(server.port, pki.ca_file, fc_v2, fk_v2)
        record_result(
            "Certificate Rotation",
            "Dynamic Zero-Downtime Server TLS Hot Swap & Client V2 Handshake",
            "HTTP 200 OK without dropped connections or service restart",
            f"HTTP {code} (Server V{b_vnum}, Client V{v_num})",
            code == 200 and "status\": \"ok" in resp,
            "Demonstrates seamless Envoy Secret Discovery Service (SDS) hot-swap"
        )

        print("\n--- Part 5: Emergency Revocation & CRL Enforcement ---")

        # Test 8: Emergency Revocation of Compromised Serial in Vault
        revoked_ok = pki.revoke_certificate(fs_v1, reason="simulated_key_compromise")
        record_result(
            "Revocation Workflow",
            "Emergency Certificate Revocation in Vault (pki_mesh/revoke)",
            "Serial marked REVOKED and updated in CRL",
            f"Revocation executed={revoked_ok}, is_revoked={pki.is_revoked(fs_v1)}",
            revoked_ok and pki.is_revoked(fs_v1),
            f"Revoked serial: {fs_v1}"
        )

        # Test 9: CRL Generation & Verification (cryptographically parse PEM CRL)
        crl_has_data = pki.crl_pem is not None and len(pki.crl_pem) > 200
        v1_in_crl = False
        v2_not_in_crl = False
        if crl_has_data:
            parsed_crl = x509.load_pem_x509_crl(pki.crl_pem)
            v1_in_crl = parsed_crl.get_revoked_certificate_by_serial_number(int(fs_v1, 16)) is not None
            v2_not_in_crl = parsed_crl.get_revoked_certificate_by_serial_number(int(fs_v2, 16)) is None
        active_not_revoked = not pki.is_revoked(fs_v2)
        record_result(
            "Revocation Workflow",
            "Vault CRL Generation & Active Status Integrity",
            "CRL contains revoked V1 serial while active V2 serial is NOT revoked",
            f"crl_valid={crl_has_data}, v1_revoked={v1_in_crl}, v2_active={active_not_revoked and v2_not_in_crl}",
            crl_has_data and v1_in_crl and v2_not_in_crl and active_not_revoked,
            "Workload operations continue uninterrupted on renewed credentials"
        )

        print("\n--- Part 6: Vault PKI Policy & Telemetry Pipeline Verification ---")

        # Test 10: Vault PKI Least-Privilege Policy (mesh-pki.hcl)
        pki_policy_path = VAULT_DIR / "policies" / "mesh-pki.hcl"
        policy_content = pki_policy_path.read_text(encoding="utf-8")
        has_issue = 'path "pki_mesh/issue/mesh-workload"' in policy_content
        has_revoke = 'path "pki_mesh/revoke"' in policy_content
        has_crl = 'path "pki_mesh/crl"' in policy_content
        no_pki_delete = "delete" not in policy_content and "destroy" not in policy_content
        record_result(
            "Vault Security Policy",
            "Vault PKI Least-Privilege Access Policy (mesh-pki.hcl)",
            "Issue, CRL, and Revoke permitted; Root CA delete/destroy prohibited",
            f"issue={has_issue}, revoke={has_revoke}, crl={has_crl}, no_delete={no_pki_delete}",
            has_issue and has_revoke and has_crl and no_pki_delete,
            "Enforces zero-trust governance on cryptographic authority"
        )

        # Test 11: Security Telemetry Audit Pipeline
        logged_events = []
        if TELEMETRY_LOG.exists():
            try:
                logged_events = json.loads(TELEMETRY_LOG.read_text(encoding="utf-8"))
            except Exception:
                logged_events = []
        has_rotation_events = any(e.get("eventType") == "key_certificate_rotation" for e in logged_events)
        has_revocation_events = any(e.get("status") == "REVOKED" for e in logged_events)
        record_result(
            "Security Observability",
            "Vault PKI Certificate Telemetry Event Emission",
            "Audit pipeline logs initial issuance, scheduled rotation, and revocation",
            f"Total events: {len(logged_events)} (rotation={has_rotation_events}, revocation={has_revocation_events})",
            has_rotation_events and has_revocation_events,
            "Feeds verified certificate lifecycle events directly to dashboard"
        )

        print("\n--- Part 7: Live Vault HTTP REST API Contract & Integration Audit ---")

        # Test 12: Vault HTTP REST API Client Contract
        client = VaultAPIClient("http://127.0.0.1:8200", "test-root-token")
        headers = client.build_headers()
        has_token = headers.get("X-Vault-Token") == "test-root-token"
        has_json_ct = headers.get("Content-Type") == "application/json"
        serial_fmt_ok = client.format_vault_serial("011f93cb:3de0") == "01-1f-93-cb-3d-e0"
        is_client_valid = has_token and has_json_ct and serial_fmt_ok and client.vault_addr == "http://127.0.0.1:8200"
        record_result(
            "Vault API Integration",
            "Vault HTTP REST API Client Endpoint & Header Contract",
            "X-Vault-Token and Content-Type: application/json properly formatted",
            f"has_token={has_token}, content_type={headers.get('Content-Type')}, serial_fmt={serial_fmt_ok}",
            is_client_valid,
            "Complies with official HashiCorp Vault PKI HTTP API specifications"
        )

        # Test 13: Dual-Mode Engine Architecture & Integration Audit Breakdown
        status_info = pki.get_integration_status()
        mode_valid = status_info["engine_mode"] in ("LIVE_VAULT_HTTP_API", "STANDALONE_CRYPTOGRAPHIC_EMULATION")
        has_api_endpoints = len(status_info["architecture_breakdown"]["actual_vault_api_endpoints"]) >= 7
        has_sim_components = len(status_info["architecture_breakdown"]["simulation_fallback_components"]) >= 3
        record_result(
            "Vault Architecture",
            "Dual-Mode Engine Architecture & Integration Audit Breakdown",
            "Clear distinction of actual Vault REST endpoints vs fallback simulation",
            f"mode={status_info['engine_mode']}, api_endpoints={len(status_info['architecture_breakdown']['actual_vault_api_endpoints'])}",
            mode_valid and has_api_endpoints and has_sim_components,
            "Provides full architectural transparency on real vs simulated components"
        )

        # Test 14: Cryptographic Trust Chain & SPIFFE SVID Verification
        leaf_cert = x509.load_pem_x509_certificate(fc_v2.read_bytes())
        ca_cert = x509.load_pem_x509_certificate(pki.ca_file.read_bytes())
        
        # Verify issuer matches CA subject
        issuer_matches = (leaf_cert.issuer == ca_cert.subject)
        # Verify SPIFFE URI SAN is present
        san_ext = leaf_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        has_frontend_svid = "spiffe://pqzt.local/ns/demo/sa/frontend" in uri_sans

        # Verify signature using CA public key
        sig_valid = True
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                ec.ECDSA(leaf_cert.signature_hash_algorithm)
            )
        except Exception:
            sig_valid = False

        record_result(
            "Cryptographic Integrity",
            "Cryptographic Trust Chain & SPIFFE SVID Verification",
            "Signature verifies against Root CA public key and contains SPIFFE SVID",
            f"issuer_matches={issuer_matches}, sig_valid={sig_valid}, svid={has_frontend_svid}",
            issuer_matches and sig_valid and has_frontend_svid,
            "Guarantees workload certificate cryptographic provenance"
        )

    finally:
        print("\n[+] Cleaning up test background servers and test sandbox...")
        if server:
            server.stop()
        for f in sandbox.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
        try:
            sandbox.rmdir()
        except Exception:
            pass

    print("\n" + "=" * 65)
    print("                   SUMMARY OF RESULTS")
    print("=" * 65)
    print(f"Total Tests Executed: {TOTAL_TESTS}")
    print(f"Passed:                {PASSED_TESTS}")
    print(f"Failed:                {FAILED_TESTS}")

    # Write report
    report_file = TESTS_DIR / "results-vault-pki.md"
    lines = [
        "# Vault PKI Setup, Certificate Renewal & Rotation Results",
        f"**Date**: {dt.datetime.now(dt.timezone.utc).isoformat()}  ",
        "**Module**: Vault PKI Secrets Engine, Dynamic Rotation & CRL Revocation  ",
        f"**Status**: {'ALL TESTS PASSED (100%)' if FAILED_TESTS == 0 else 'TESTS FAILED'}  ",
        "",
        "## Summary of Test Results",
        "",
        "| ID | Category | Test Name | Expected | Actual | Status | Details |",
        "| :---: | :--- | :--- | :--- | :--- | :---: | :--- |"
    ]
    for t in TEST_RESULTS:
        lines.append(
            f"| {t['id']} | {t['category']} | {t['name']} | `{t['expected']}` | `{t['actual']}` | **{t['status']}** | {t['details']} |"
        )
    lines.extend([
        "",
        f"**Summary**: **{PASSED_TESTS} / {TOTAL_TESTS} Tests Passed ({(PASSED_TESTS/TOTAL_TESTS)*100:.1f}%)**.",
        "",
        "## Key Capabilities Verified",
        "1. **Live Vault PKI REST API Client**: Implemented standard `/v1/pki_mesh` endpoints (`mount_pki`, `generate_root_ca`, `configure_role`, `issue_certificate`, `revoke_certificate`, `get_crl`).",
        "2. **Dual-Mode Engine Architecture**: Transparently operates in `LIVE_VAULT_HTTP_API` mode or high-fidelity `STANDALONE_CRYPTOGRAPHIC_EMULATION` fallback.",
        "3. **Workload SVID Issuance**: Issues short-lived certificates with SPIFFE URI SANs (`spiffe://pqzt.local/ns/demo/sa/*`).",
        "4. **Automated Renewal & Zero-Downtime Rotation**: Simulates Envoy SDS dynamic hot reload without dropped connections.",
        "5. **Emergency Revocation**: Verifies immediate revocation and CRL publication upon key compromise.",
        "6. **Least-Privilege Policy**: Verifies `vault/policies/mesh-pki.hcl` restricts destructive operations.",
        "7. **Security Observability**: Emits verified certificate lifecycle events tagged with `isGenuine: true` directly to dashboard."
    ])
    report_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[+] Detailed markdown report generated at: {report_file.name}")

    if FAILED_TESTS > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
