# Pull Request: Day 6 — Vault PKI Engine Setup, Dynamic Key Rotation, Service Path Authz & Real-Time Security Dashboard

**Branch**: `feature/opa-vault`  
**Target Branch**: `develop`  
**Author**: Member 5 (Manideep - OPA, Vault & Dashboard Lead)  
**Date**: Day 6 / October 25, 2026  

---

## 1. Overview & Objective

This PR delivers the Day 6 milestone for the **OPA, Vault PKI & Observability Dashboard** module within the **Post-Quantum Zero-Trust Microsegmentation Mesh (`pqc-zero-trust-mesh`)**:

1. **Integrated OPA Decisions with Service Request Path**:
   - Wired OPA evaluation directly into Envoy's `envoy.filters.http.ext_authz` filter (`envoy/backend-envoy.yaml`) and stand-in proxy interception (`tests/policy_server.py`, `tests/test_service_path.py`).
   - Upgraded `opa/policies/authz.rego` to support direct identity inputs, mesh source attributes, and Envoy CheckRequest attributes (`attributes.source.principal`, `attributes.request.http.path`, `attributes.request.http.method`).
   - Expanded OPA test suite to **24/24 tests passing (100%)** (14 unit tests + 10 contract evaluation tests) and verified **15/15 service path integration tests**.
2. **Vault PKI Engine Coordination & Key Rotation Testing**:
   - Built the centralized Vault PKI Coordinator (`vault/scripts/vault_pki_coordinator.py`) and least-privilege policy (`vault/policies/mesh-pki.hcl`).
   - Programmatically initialized the `pki_mesh` mount, generated the Mesh Root CA, and configured the `mesh-workload` role issuing short-lived credentials (12h TTL) with SPIFFE URI SANs (`spiffe://pqzt.local/ns/demo/sa/*`).
   - Validated automated renewal at 66% TTL threshold (generating version 2 credentials with fresh keypairs and serials).
   - Tested zero-downtime server TLS context hot-reload simulating the Envoy Secret Discovery Service (SDS) model without dropping active connections.
   - Verified emergency revocation and Certificate Revocation List (CRL) publication, ensuring uncompromised active credentials continue uninterrupted (**11/11 tests passing, 100%**).
3. **Observability & Security Dashboard (`dashboard/`)**:
   - Built an interactive, dark-themed zero-trust visual telemetry dashboard (`dashboard/index.html`, `dashboard/css/index.css`, `dashboard/js/app.js`).
   - Created a zero-dependency Python backend server & telemetry API (`dashboard/server.py`) serving live endpoints (`/api/events`, `/api/simulate`, `/api/run-tests`, `/api/status`).
   - Integrated live SVG mesh topology with dynamic packet flow animation, workload certificate lifecycle tracker, searchable/filterable audit event stream with JSON inspector, and live simulation controls.
   - Connected test suites directly to the telemetry pipeline (`opa/telemetry/audit_log.json`).

---

## 2. Summary of Changes

### A. OPA Policy & Service Request Path
- `opa/policies/authz.rego`: Added support for Envoy ext_authz `CheckRequest` envelope attributes (`input.attributes.source.principal`, `input.attributes.request.http.path`, `input.attributes.request.http.method`).
- `opa/policies/authz_test.rego`: Added unit tests covering Envoy CheckRequest envelopes, lateral movement prevention, mesh source inputs, and mutating action blocks (14/14 PASS).
- `tests/test_service_path.py`: Integrated telemetry audit event emission for both authorization decisions (`allowed_request`, `denied_request`) and handshake rejections (`failed_authentication`).

### B. Vault PKI Engine & Key Rotation Suite
- `vault/scripts/vault_pki_coordinator.py`: Implemented centralized Vault PKI engine coordinating Root CA generation, `mesh-workload` role configuration, leaf certificate issuance, automated renewal, and CRL generation.
- `vault/policies/mesh-pki.hcl`: Created least-privilege policy allowing `pki_mesh/issue/mesh-workload`, `pki_mesh/crl`, and `pki_mesh/revoke`, while forbidding CA deletion or sudo privileges.
- `tests/test_vault_pki.py`, `tests/test_vault_pki.ps1`, `tests/test_vault_pki.sh`: Created 11-test automated suite verifying PKI engine setup, leaf issuance, mTLS handshake, renewal, dynamic hot-swap, emergency revocation, CRL verification, and telemetry emission.
- `tests/results-vault-pki.md`: Test results report detailing 100% pass rate.

### C. Observability & Security Dashboard
- `dashboard/index.html`: Responsive layout with KPI cards, interactive SVG mesh topology, OPA ext_authz decision table, Vault PKI certificate rotation tracker, and audit event stream.
- `dashboard/css/index.css`: Cyberpunk / Zero-Trust design system with glassmorphism, glowing pulse indicators, neon color accents, and Google Fonts (`Inter`, `Outfit`, `JetBrains Mono`).
- `dashboard/js/app.js`: Telemetry event ingestion, KPI calculation, SVG packet flow animation, simulation triggers, and test execution runner.
- `dashboard/server.py`: HTTP server and REST API for real-time telemetry streaming and test automation.
- `dashboard/run_dashboard.ps1` & `dashboard/run_dashboard.sh`: Cross-platform launcher scripts.

### D. Documentation & Repository Tracking
- `TEAM_STATUS.md`: Marked visual dashboard and Vault PKI setup milestones as completed for Day 6.
- `README.md`: Updated architecture components, test suite listings, and dashboard launch instructions.

---

## 3. Test Evidence

### A. Automated OPA Suite (`tests/test_opa.ps1` - 24/24 PASS)
```text
==========================================================
   PQC Zero-Trust Mesh - Automated OPA Test Suite         
==========================================================
[+] OPA binary found: Version: 1.21.1 (Platform: windows/amd64, Rego Version: v1)

--- Part 1: Policy Unit Tests (opa test) ---
PASS: 14/14
[+] All policy unit tests passed successfully.

--- Part 2: Integration Contract Tests (tests/opa/*.json) ---
[TEST 1] Contract Test 1: Frontend -> Backend [ALLOW]       => PASS (True)
[TEST 2] Contract Test 2: Backend -> Database [ALLOW]       => PASS (True)
[TEST 3] Contract Test 3: Frontend -> Database [DENY]        => PASS (False)
[TEST 4] Contract Test 4: Unknown -> Backend [DENY]         => PASS (False)

--- Part 3: Identity Tests (opa/inputs/*.json) ---
[TEST 5] Identity Test 1: Simple Verified Identity [ALLOW]  => PASS (True)
[TEST 6] Identity Test 2: Simple Unapproved Identity [DENY] => PASS (False)

--- Part 4: SPIFFE SVID Request Envelope Tests (opa/tests/*.json) ---
[TEST 7] SPIFFE SVID Test 1: Full SVID URI Allowed [ALLOW]  => PASS (True)
[TEST 8] SPIFFE SVID Test 2: Rogue SVID URI Denied [DENY]   => PASS (False)

--- Part 5: Mesh Integration Identity Tests (opa/inputs/demo_*.json) ---
[TEST 9] Mesh Identity Test 1: Demo Frontend URI Allowed    => PASS (True)
[TEST 10] Mesh Identity Test 2: Demo Unapproved URI Denied  => PASS (False)

Total Evaluation Tests: 10 | Passed: 10 | Failed: 0
[+] All tests PASSED successfully!
```

### B. Live Service Path & Secret Lifecycle Suite (`tests/test_service_path.ps1` - 15/15 PASS)
```text
=================================================================
   PQC Zero-Trust Mesh - Service Authz & Secret Lifecycle Suite
=================================================================
Part 1: Service Request Path Authorization Tests
[PASS] Test 1: Authorized Frontend -> Backend (Demo SPIFFE ID) [ALLOW]  => HTTP 200
[PASS] Test 2: Authorized Frontend -> Backend (Cluster SPIFFE ID) [ALLOW] => HTTP 200
[PASS] Test 3: Unapproved Workload SVID -> Backend [DENY]               => HTTP 403
[PASS] Test 4: Frontend Lateral Movement -> Database [DENY]              => HTTP 403
[PASS] Test 5: Unauthorized Mutating Action (DELETE) [DENY]              => HTTP 403
[PASS] Test 6: Missing Client Certificate Handshake Rejection [DENY]     => SSLError / Rejected
[PASS] Test 7: Untrusted CA Client Certificate Rejection [DENY]          => Connection Rejected
[PASS] Test 8: Expired Client Certificate Rejection [DENY]               => Certificate Expired

Part 2: Dynamic Key & Certificate Rotation Workflow
[PASS] Test 9: Issue Renewed Leaf Certificate V2 (New Keypair & Serial) => Rotated
[PASS] Test 10: Client Handshake with Rotated Certificate V2 [ALLOW]     => HTTP 200
[PASS] Test 11: Server Hot Reload & Client Re-handshake (Envoy SDS)      => HTTP 200

Part 3: Vault Configuration & Secret Lifecycle Review
[PASS] Test 12: Vault Server Dev Config (vault-dev.hcl) Security Perimeter
[PASS] Test 13: Vault Least-Privilege Policy (mesh-secrets.hcl) Immutability
[PASS] Test 14: Vault KV v2 Secret Retrieval, Rotation & Rollback Lifecycle
[PASS] Test 15: Real-Time Authorization Decision & Audit Logging
Total Tests: 15 | Passed: 15 | Failed: 0
```

### C. Vault PKI Setup & Rotation Suite (`tests/test_vault_pki.ps1` - 11/11 PASS)
```text
=================================================================
   PQC Zero-Trust Mesh - Vault PKI Setup & Rotation Test Suite
=================================================================
--- Part 1: Vault PKI Engine Setup & Configuration ---
[PASS] Test 1: Vault PKI Mount & Root CA Generation (pki_mesh)
[PASS] Test 2: Workload Role Definition (mesh-workload)

--- Part 2: Workload Certificate Issuance (Frontend & Backend) ---
[PASS] Test 3: Issue Frontend Client Leaf Certificate (V1)
[PASS] Test 4: Issue Backend Server Leaf Certificate (V1)

--- Part 3: Live Mutual TLS Handshake using Vault Credentials ---
[PASS] Test 5: mTLS Handshake with Vault PKI Leaf Certificates [ALLOW]

--- Part 4: Dynamic Certificate Renewal & Rotation (Envoy SDS) ---
[PASS] Test 6: Automated Workload Certificate Renewal (Frontend V2)
[PASS] Test 7: Dynamic Zero-Downtime Server TLS Hot Swap & Client V2 Handshake

--- Part 5: Emergency Revocation & CRL Enforcement ---
[PASS] Test 8: Emergency Certificate Revocation in Vault (pki_mesh/revoke)
[PASS] Test 9: Vault CRL Generation & Active Status Integrity

--- Part 6: Vault PKI Policy & Telemetry Pipeline Verification ---
[PASS] Test 10: Vault PKI Least-Privilege Access Policy (mesh-pki.hcl)
[PASS] Test 11: Vault PKI Certificate Telemetry Event Emission
Total Tests: 11 | Passed: 11 | Failed: 0 (100% PASS)
```

---

## 4. Verification Checklist

- [x] OPA decisions integrated with the service request path via Envoy `ext_authz` and tested end-to-end (39 tests: 24 OPA + 15 Service Path).
- [x] Centralized Vault PKI coordinator configured with Mesh Root CA, short-lived workload credentials, dynamic rotation, and emergency revocation (11/11 PASS).
- [x] Zero-trust security dashboard built and running live at `http://127.0.0.1:8050` with live SVG topology, simulation console, and audit event stream.
- [x] Zero secret compliance preserved: no private keys, certificates, or tokens committed to git.
- [x] `TEAM_STATUS.md` and repository `README.md` updated.
