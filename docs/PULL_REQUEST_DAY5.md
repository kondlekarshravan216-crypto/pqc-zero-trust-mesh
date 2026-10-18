# Pull Request: Day 5 — Service Request Path Authorization, Negative Testing, Vault Secrets & Dynamic Key Rotation

**Branch**: `feature/opa-vault`  
**Target Branch**: `develop`  
**Author**: Member 5 (Manideep - OPA, Vault & Dashboard Lead)  
**Date**: Day 5 / October 18, 2026  

---

## 1. Overview & Objective

This PR delivers the Day 5 milestone for the **OPA and Vault** module within the **Post-Quantum Zero-Trust Microsegmentation Mesh (`pqc-zero-trust-mesh`)**:
1. **Live Service Request Path Authorization**: Integrated OPA evaluation directly into the actual service request path via Envoy's `envoy.filters.http.ext_authz` HTTP filter and live Python mTLS proxy interception.
2. **Authorized vs. Unauthorized Request Vectors (100% Pass across 35 tests)**:
   - Re-verified all 20 automated OPA unit and evaluation tests (`tests/test_opa.ps1` and `tests/test_opa.sh`).
   - Built and executed the 15-scenario live service path test suite (`tests/test_service_path.py` and `tests/test_service_path.ps1`), proving interception of rogue workload identities, lateral movement to databases, unauthorized HTTP mutating verbs, missing client certs, untrusted CAs, and expired certificates.
3. **Vault Configuration & Secret Lifecycle Verification**:
   - Assessed developer perimeter in `vault/configs/vault-dev.hcl` (loopback binding `127.0.0.1:8200`, storage path exclusion via `.gitignore`).
   - Assessed least-privilege capability enforcement in `vault/policies/mesh-secrets.hcl` (zero-trust immutability: `create`, `read`, `update` granted; `delete`, `destroy`, `sudo` forbidden).
   - Validated KV v2 secret lifecycle: creation (V1), retrieval, rotation (V2), version retention, and instant historical rollback.
4. **Dynamic Key & Certificate Rotation**:
   - Investigated static mounts vs. dynamic Secret Discovery Service (SDS) streaming.
   - Tested zero-downtime hot reload: generated renewed keypair and leaf cert V2, hot-swapped server TLS context in-memory without dropping the socket listener, and completed client requests with renewed credentials.
5. **Cross-Module Compatibility & Team Coordination**:
   - Unified SPIFFE trust domains in `opa/policies/authz.rego` to support both `spiffe://pqzt.local/ns/demo/sa/frontend` and `spiffe://cluster.local/ns/mesh/sa/frontend-service`.
   - Wired `opa-service` container into `docker-compose.yml`.
   - Documented full results in `docs/AUTHORIZATION_AND_SECRET_MANAGEMENT_VERIFICATION.md` and updated `TEAM_STATUS.md`.

---

## 2. Summary of Changes

### A. OPA Policies & Test Suites
- `opa/policies/authz.rego`: Added `spiffe://pqzt.local/ns/demo/sa/frontend` and `frontend` to approved identities; added HTTP method handling (`read_actions`).
- `opa/policies/authz_test.rego`: Added unit tests for demo SPIFFE identity and unauthorized mutating actions (`test_allow_demo_frontend_identity`, `test_deny_unauthorized_action`).
- `opa/policies/authorization.rego`: Expanded `mesh.authz` to support HTTP GET / read methods.
- `opa/inputs/demo_frontend_allowed.json` & `demo_unapproved_denied.json`: Added test input fixtures.
- `tests/test_opa.ps1` & `tests/test_opa.sh`: Added Part 5 integration contract tests (expanded from 16 to 20 tests, 100% PASS).

### B. Service Request Path Integration & Stand-in Upgrades
- `envoy/backend-envoy.yaml`: Configured `envoy.filters.http.ext_authz` filter pointing to `opa_service:8181` cluster before router.
- `docker-compose.yml`: Added `opa-service` container definition and wired `backend-envoy.depends_on`.
- `tests/policy_server.py`: Added `--opa-url` argument and request-path authorization query logic.
- `tests/test_service_path.py`: Created 15-test automated end-to-end service request path, Vault secret management, and dynamic key rotation test runner.
- `tests/test_service_path.ps1` & `tests/test_service_path.sh`: Added native PowerShell and Bash wrappers.

### C. Security Documentation & Repository Alignment
- `docs/AUTHORIZATION_AND_SECRET_MANAGEMENT_VERIFICATION.md`: Comprehensive engineering report detailing all 35 test results, architecture sequence diagrams, configuration resolutions, and team coordination matrices.
- `TEAM_STATUS.md`: Updated Day 5 verified progress, pending items, and Member 5 status.
- `README.md`: Documented new test suites and verification reports.
- `.gitignore`: Whitelisted `!docs/*.md` to ensure markdown documentation is tracked while preserving zero-secret compliance.

---

## 3. Test Evidence

### A. OPA Unit & Evaluation Tests (`tests/test_opa.ps1` - 20/20 PASS)
```text
==========================================================
   PQC Zero-Trust Mesh - Automated OPA Test Suite         
==========================================================
[+] OPA binary found: Version: 1.21.1 (Platform: windows/amd64, Rego Version: v1)

--- Part 1: Policy Unit Tests (opa test) ---
PASS: 10/10

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
[TEST 9] Mesh Identity Test 1: Demo Frontend URI [ALLOW]    => PASS (True)
[TEST 10] Mesh Identity Test 2: Demo Rogue URI [DENY]       => PASS (False)

==========================================================
Total Evaluation Tests: 10 | Passed: 10 | Failed: 0
[+] All tests PASSED successfully!
```

### B. Live Service Request Path & Secret Lifecycle Suite (`tests/test_service_path.ps1` - 15/15 PASS)
```text
=================================================================
   PQC Zero-Trust Mesh - Service Authz & Secret Lifecycle Suite
=================================================================
[+] Starting live OPA server on 127.0.0.1:8181... (READY)
[+] Backend Service listening on 127.0.0.1 with mTLS + OPA ext_authz

Part 1: Service Request Path Authorization Tests
[PASS] Test 1: Authorized Frontend -> Backend (Demo SPIFFE ID) [ALLOW]  => HTTP 200
[PASS] Test 2: Authorized Frontend -> Backend (Cluster SPIFFE ID) [ALLOW] => HTTP 200
[PASS] Test 3: Unapproved Workload SVID -> Backend [DENY]               => HTTP 403
[PASS] Test 4: Frontend Lateral Movement -> Database [DENY]             => HTTP 403
[PASS] Test 5: Unauthorized Mutating Action (DELETE) [DENY]             => HTTP 403
[PASS] Test 6: Missing Client Certificate Rejection [DENY]              => TLSV13_ALERT_CERTIFICATE_REQUIRED
[PASS] Test 7: Untrusted CA Client Certificate Rejection [DENY]         => TLSV1_ALERT_UNKNOWN_CA
[PASS] Test 8: Expired Client Certificate Rejection [DENY]              => SSLV3_ALERT_CERTIFICATE_EXPIRED

Part 2: Dynamic Key & Certificate Rotation Workflow
[PASS] Test 9: Issue Renewed Leaf Certificate V2 (New Keypair & Serial) => PASS
[PASS] Test 10: Client Handshake with Rotated Certificate V2 [ALLOW]     => HTTP 200
[PASS] Test 11: Server Hot Reload & Client Re-handshake (Envoy SDS)     => HTTP 200 (Zero Downtime)

Part 3: Vault Configuration & Secret Lifecycle Review
[PASS] Test 12: Vault Server Dev Config Security Perimeter               => PASS
[PASS] Test 13: Vault Least-Privilege Zero-Trust Policy Immutability    => PASS
[PASS] Test 14: Vault KV v2 Secret Retrieval, Rotation & Rollback       => PASS (Versions: [1, 2])
[PASS] Test 15: Real-Time Authorization Decision & Audit Logging        => PASS (7 Audit Records)

Total Tests Executed: 15 | Passed: 15 | Failed: 0
[+] End-to-End Service Path & Vault Suite PASSED successfully!
```

---

## 4. Verification Checklist

- [x] OPA policies validated in Rego v1 with 10/10 unit tests passing (`opa test opa/policies/ -v`)
- [x] OPA evaluation tests verified with 10/10 contract tests passing (`tests/test_opa.ps1`, `tests/test_opa.sh`)
- [x] OPA authorization integrated with the actual service request path (`envoy/backend-envoy.yaml` and `tests/test_service_path.py`)
- [x] Both authorized and unauthorized requests thoroughly tested (15/15 integration tests passing)
- [x] Vault development configuration and least-privilege policy validated (`vault-dev.hcl`, `mesh-secrets.hcl`)
- [x] Secret retrieval, rotation, version retention, and rollback workflow verified
- [x] Dynamic key and certificate rotation tested with zero-downtime hot reload
- [x] Detailed engineering verification report published (`docs/AUTHORIZATION_AND_SECRET_MANAGEMENT_VERIFICATION.md`)
- [x] Zero private keys, unseal tokens, or credentials tracked in git
- [x] `TEAM_STATUS.md` and repository `README.md` updated for Day 5
