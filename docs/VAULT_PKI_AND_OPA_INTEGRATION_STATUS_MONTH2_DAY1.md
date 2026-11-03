# Integration Status Report: Month 2 Day 1
## Vault PKI API Connection, OPA Microsegmentation & Genuine Dashboard Observability

**Branch**: `feature/opa-vault`  
**Date**: November 3, 2026 (Month 2 Day 1)  
**Author**: Member 5 — Manideep (OPA, Vault & Dashboard Lead)  
**Status**: Completed & Verified (57/57 Tests Passing, 100%)

---

## 1. Executive Summary & Deliverables

This milestone delivers the **Month 2 Day 1** core objectives for the **Post-Quantum Zero-Trust Microsegmentation Mesh (`pqc-zero-trust-mesh`)**:

1. **OPA Authorization Policy Review & Enhancement**:
   - Expanded `opa/policies/authz.rego` to enforce full three-tier zero-trust microsegmentation (`frontend` $\rightarrow$ `backend` $\rightarrow$ `database`).
   - Hardened SPIFFE SVID allowlists, destination scoping, and HTTP action constraints.
   - Enforced granular, auditable decision reasons for lateral movement prevention, mutating action restrictions, and unapproved caller identities.
   - Expanded policy test suite to **28/28 tests passing (100%)** (18 Rego unit tests + 10 contract evaluation tests).
2. **Authorized & Unauthorized Service Request Verification**:
   - Verified 15 distinct service request vectors in `tests/test_service_path.py` combining mTLS transport security and Envoy `ext_authz` policy checks.
   - Proved strict denial of lateral movement to `/database`, unauthorized HTTP verbs (e.g. `DELETE`), rogue SPIFFE IDs, missing certs, untrusted CA signatures, and expired certificates.
3. **Vault PKI Implementation Audit & REST API Connection**:
   - Audited existing Vault components, precisely delineating **actual Vault integration** from **Python simulation**.
   - Built a direct HTTP REST API client (`VaultAPIClient`) connecting to HashiCorp Vault's official PKI engine endpoints (`/v1/pki_mesh/*`) for certificate issuance, renewal, emergency revocation, and CRL generation.
   - Implemented a dual-mode engine architecture (`VaultPKIEngine`) that dynamically uses the live Vault REST API when a Vault daemon is available, while providing high-fidelity cryptographic fallback for offline testing.
   - Expanded the Vault PKI test suite to **14/14 tests passing (100%)**.
4. **Dashboard Event Accuracy & Genuine Telemetry Enforcement**:
   - Upgraded the security observability dashboard (`dashboard/server.py`, `dashboard/js/app.js`, `dashboard/index.html`) to distinguish between **genuine verified security events** and **synthetic simulation events**.
   - Connected dashboard controls to live backend endpoints (`/api/evaluate-opa`, `/api/vault/issue`, `/api/vault/revoke`), ensuring user actions execute real OPA policy evaluations and cryptographic operations.
   - Added provenance badges (`GENUINE` vs `SIMULATED`), a provenance filter dropdown, and a live genuine telemetry rate KPI.

---

## 2. Review of OPA Authorization Policy & Test Cases

### A. Architectural Review & Policy Enhancements
The mesh authorization policies reside in `opa/policies/authz.rego` (Envoy `ext_authz` and HTTP request path) and `opa/policies/authorization.rego` (inter-service contract).

#### Key Policies Enforced in `opa/policies/authz.rego`:
1. **Zero-Trust Deny-by-Default**: `default allow := false`.
2. **Identity Extraction**: Dynamically resolves caller identity from direct JSON `input.identity`, `input.source`, or Envoy CheckRequest attribute `input.attributes.source.principal`.
3. **Three-Tier Microsegmentation Perimeter**:
   - `approved_frontend_identities` (`frontend`, `frontend-service`, `spiffe://cluster.local/ns/mesh/sa/frontend-service`, `spiffe://pqzt.local/ns/demo/sa/frontend`) $\rightarrow$ allowed to query `backend` with read actions (`GET`, `HEAD`, `read`).
   - `approved_backend_identities` (`backend`, `backend-service`, `spiffe://cluster.local/ns/mesh/sa/backend-service`, `spiffe://pqzt.local/ns/demo/sa/backend`) $\rightarrow$ allowed to query `database` with read actions (`GET`, `HEAD`, `read`).
4. **Lateral Movement Prevention**:
   - If a frontend or unapproved caller attempts to access `destination == "database"`, access is strictly DENIED with reason: `"Access denied: lateral movement to database prevented"`.
5. **Least-Privilege HTTP Method Guard**:
   - Workloads attempting mutating methods (`POST`, `PUT`, `DELETE`, `PATCH`) are denied with reason: `"Access denied: unauthorized mutating HTTP action"`.

### B. OPA Test Results (28/28 PASS - 100%)
- **Unit Tests (`opa test opa/policies/ -v`)**: **18/18 PASS**
  - `data.mesh.authz.test_allow_frontend_backend`: PASS
  - `data.mesh.authz.test_allow_backend_database`: PASS
  - `data.mesh.authz.test_deny_frontend_database`: PASS
  - `data.mesh.authz.test_deny_unknown_backend`: PASS
  - `data.authz.test_allow_approved_identity`: PASS
  - `data.authz.test_deny_unapproved_identity`: PASS
  - `data.authz.test_deny_unauthorized_destination`: PASS
  - `data.authz.test_deny_empty_input`: PASS
  - `data.authz.test_allow_demo_frontend_identity`: PASS
  - `data.authz.test_deny_unauthorized_action`: PASS
  - `data.authz.test_allow_envoy_check_request`: PASS
  - `data.authz.test_deny_envoy_lateral_database`: PASS
  - `data.authz.test_allow_mesh_source_input`: PASS
  - `data.authz.test_deny_envoy_mutating_action`: PASS
  - `data.authz.test_allow_backend_database_access`: PASS *(New)*
  - `data.authz.test_allow_cluster_backend_database`: PASS *(New)*
  - `data.authz.test_deny_backend_mutating_database`: PASS *(New)*
  - `data.authz.test_deny_backend_reverse_traversal`: PASS *(New)*
- **Contract Evaluation Tests (`tests/test_opa.ps1`)**: **10/10 PASS**
  - Contract 1: Frontend $\rightarrow$ Backend `[ALLOW]` $\implies$ True
  - Contract 2: Backend $\rightarrow$ Database `[ALLOW]` $\implies$ True
  - Contract 3: Frontend $\rightarrow$ Database `[DENY]` $\implies$ False
  - Contract 4: Unknown $\rightarrow$ Backend `[DENY]` $\implies$ False
  - Identity 1: Simple Verified Identity `[ALLOW]` $\implies$ True
  - Identity 2: Simple Unapproved Identity `[DENY]` $\implies$ False
  - SPIFFE SVID 1: Full SVID URI Allowed `[ALLOW]` $\implies$ True
  - SPIFFE SVID 2: Rogue SVID URI Denied `[DENY]` $\implies$ False
  - Mesh Identity 1: Demo Frontend SPIFFE URI Allowed `[ALLOW]` $\implies$ True
  - Mesh Identity 2: Demo Unapproved SPIFFE URI Denied `[DENY]` $\implies$ False

---

## 3. Verification of Authorized & Unauthorized Service Requests

In `tests/test_service_path.py`, a live OPA server is spawned on `127.0.0.1:8181` and wired directly to a backend service with TLS 1.3 mTLS interception. 15 distinct test vectors were verified:

| Test # | Category | Request Vector | Expected | Actual | Decision | Zero-Trust Principle |
|:---:|:---|:---|:---:|:---:|:---:|:---|
| 1 | Service Path | Authorized Frontend (Demo SVID) $\rightarrow$ Backend | HTTP 200 | HTTP 200 | `ALLOW` | Mutual identity verification |
| 2 | Service Path | Authorized Frontend (Cluster SVID) $\rightarrow$ Backend | HTTP 200 | HTTP 200 | `ALLOW` | Cross-namespace SVID allowed |
| 3 | Service Path | Unapproved Workload SVID $\rightarrow$ Backend | HTTP 403 | HTTP 403 | `DENY` | Unknown caller rejected |
| 4 | Service Path | Frontend Lateral Movement $\rightarrow$ Database | HTTP 403 | HTTP 403 | `DENY` | Microsegmentation boundary |
| 5 | Service Path | Unauthorized Action (`DELETE` method) | HTTP 403 | HTTP 403 | `DENY` | Least-privilege HTTP actions |
| 6 | Transport | Missing Client Certificate | Rejected | Connection Closed | `DENY` | Mandatory mTLS authentication |
| 7 | Transport | Untrusted / Rogue CA Client Certificate | Rejected | SSLError (Unknown CA) | `DENY` | Root CA trust chain validation |
| 8 | Transport | Expired Client Certificate | Rejected | SSLError (Expired) | `DENY` | Validity window enforcement |
| 9 | Rotation | Issue Renewed Leaf Cert V2 | Serial V2 | Rotated Keypair | `PASS` | Fresh key generation at 66% TTL |
| 10 | Rotation | Client Handshake with Rotated Cert V2 | HTTP 200 | HTTP 200 | `ALLOW` | Immediate client credential rotation |
| 11 | Rotation | Server Hot Reload (Envoy SDS model) | HTTP 200 | HTTP 200 | `ALLOW` | Zero-downtime listener re-handshake |
| 12 | Vault Config | `vault-dev.hcl` Security Perimeter | Loopback | Loopback + File store | `PASS` | Unauthenticated traffic isolated |
| 13 | Vault Policy | `mesh-secrets.hcl` Least Privilege | CRU only | No Delete/Destroy/Sudo | `PASS` | Immutable secret versioning |
| 14 | Secret Mgmt | KV v2 Secret Retrieval, Rotation & Rollback | V1 $\rightarrow$ V2 $\rightarrow$ V1 | Rollback verified | `PASS` | Disaster recovery version retention |
| 15 | Observability | Real-Time Telemetry Audit Logging | ALLOW & DENY | 7 events recorded | `PASS` | Telemetry stream integrity |

---

## 4. Vault PKI Implementation Audit: Actual Integration vs. Simulation

To provide complete architectural clarity, the codebase was audited to identify which components represent actual Vault integration versus Python simulation:

### A. Actual Vault Integration Components
These components use or represent authentic HashiCorp Vault primitives and standards:
1. **HashiCorp Vault REST API Client (`VaultAPIClient` in `vault/scripts/vault_pki_coordinator.py`)**:
   - `POST /v1/sys/mounts/pki_mesh`: Mounts the PKI secrets engine with custom lease TTL (`87600h`).
   - `POST /v1/pki_mesh/root/generate/internal`: Generates the mesh Root CA certificate with EC P-256 keypair.
   - `POST /v1/pki_mesh/roles/mesh-workload`: Configures workload issuance parameters (12h TTL, `pqzt.local` domains, SPIFFE URI SANs).
   - `POST /v1/pki_mesh/issue/mesh-workload`: Real Vault issuance endpoint returning `data.certificate`, `data.private_key`, `data.serial_number`, and `data.issuing_ca`.
   - `POST /v1/pki_mesh/revoke`: Real Vault revocation endpoint updating internal revocation index.
   - `GET /v1/pki_mesh/crl/pem`: Retrieves the Certificate Revocation List in PEM format.
   - `GET /v1/pki_mesh/ca/pem`: Retrieves the active Root CA certificate.
   - `GET /v1/sys/health`: Liveness and unseal probe.
   - Authentication via HTTP header `X-Vault-Token` and `Content-Type: application/json`.
2. **Vault Production Configurations & Access Policies**:
   - `vault/configs/vault-dev.hcl`: Valid Vault daemon HCL configuration binding to loopback (`127.0.0.1:8200`), local file storage (`./vault/data`), and UI enablement.
   - `vault/policies/mesh-pki.hcl`: Least-privilege HCL policy granting `create`, `read`, and `update` on `pki_mesh/issue/mesh-workload`, `pki_mesh/crl`, and `pki_mesh/revoke`, while explicitly forbidding Root CA destruction or sudo privileges.
   - `vault/policies/mesh-secrets.hcl`: Least-privilege KV v2 policy restricting workloads to `secret/data/mesh/*`.

### B. Python Simulation Components
These components simulate infrastructure behaviors that typically require external daemons or specialized hardware:
1. **Cryptographic Fallback Engine (`VaultPKIEngine`)**:
   - When no live Vault daemon is reachable at `VAULT_ADDR`, the engine utilizes Python's `cryptography` library (`ec.generate_private_key`, `x509.CertificateBuilder`) to generate cryptographically authentic X.509 certs, keys, and CRLs matching Vault's exact schemas and formats.
   - This ensures offline test suites and CI environments execute reliably without requiring a running Vault container.
2. **Envoy SDS Mock Server (`DynamicTLSServer` in `tests/test_vault_pki.py` and `tests/test_service_path.py`)**:
   - Simulates Envoy's dynamic Secret Discovery Service (SDS) by using Python's `ssl.SSLContext` reload mechanism (`reload_tls_context`) to swap server certificates in-memory on an active TCP listener socket without dropping active connections.
3. **KV v2 State Machine Simulator (`KV2SecretEngine` in `tests/test_service_path.py`)**:
   - Simulates Vault KV v2 versioned storage semantics (put, version increment, get by version, history rollback) in-memory for fast regression testing.

---

## 5. Connecting Certificate Issuance & Revocation to the Actual Vault PKI API

In `vault/scripts/vault_pki_coordinator.py`, certificate issuance, automated renewal, and emergency revocation are now connected to the actual Vault PKI API:

```
+-----------------------------------------------------------------------+
|                         VaultPKIEngine                                |
|  - Probes live Vault daemon via GET /v1/sys/health                    |
|  - Dynamic Mode Selection:                                           |
|       * LIVE_VAULT_HTTP_API (when Vault is running at VAULT_ADDR)    |
|       * STANDALONE_CRYPTOGRAPHIC_EMULATION (offline / sandbox fallback)|
+------------------------------------+----------------------------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
+-------------------------------+           +-------------------------------+
|       VaultAPIClient          |           |   python-cryptography Engine  |
|  POST /v1/pki_mesh/issue/...  |           |   x509.CertificateBuilder     |
|  POST /v1/pki_mesh/revoke     |           |   x509.CRLBuilder             |
|  GET  /v1/pki_mesh/crl/pem    |           |   ec.generate_private_key     |
+---------------+---------------+           +---------------+---------------+
                |                                           |
                +---------------------+---------------------+
                                      |
                                      v
              +-----------------------------------------------+
              |   Workload Files (.crt, .key, ca.crt, crl.pem) |
              |   Telemetry Audit Log (audit_log.json)        |
              +-----------------------------------------------+
```

### Vault PKI Test Results (`tests/test_vault_pki.py` - 14/14 PASS):
1. **Test 1**: Vault PKI Mount & Root CA Generation (`pki_mesh`) $\implies$ PASS
2. **Test 2**: Workload Role Definition (`mesh-workload`) $\implies$ PASS
3. **Test 3**: Issue Frontend Client Leaf Certificate (V1) $\implies$ PASS
4. **Test 4**: Issue Backend Server Leaf Certificate (V1) $\implies$ PASS
5. **Test 5**: mTLS Handshake with Vault PKI Leaf Certificates `[ALLOW]` $\implies$ PASS
6. **Test 6**: Automated Workload Certificate Renewal (Frontend V2 at 66% TTL) $\implies$ PASS
7. **Test 7**: Dynamic Zero-Downtime Server TLS Hot Swap & Client V2 Handshake $\implies$ PASS
8. **Test 8**: Emergency Certificate Revocation in Vault (`pki_mesh/revoke`) $\implies$ PASS
9. **Test 9**: Vault CRL Generation & Active Status Integrity $\implies$ PASS
10. **Test 10**: Vault PKI Least-Privilege Access Policy (`mesh-pki.hcl`) $\implies$ PASS
11. **Test 11**: Vault PKI Certificate Telemetry Event Emission $\implies$ PASS
12. **Test 12**: Vault HTTP REST API Client Endpoint & Header Contract $\implies$ PASS *(New)*
13. **Test 13**: Dual-Mode Engine Architecture & Integration Audit Breakdown $\implies$ PASS *(New)*
14. **Test 14**: Cryptographic Trust Chain & SPIFFE SVID Verification $\implies$ PASS *(New)*

---

## 6. Dashboard Event Accuracy & Genuine Security Telemetry

To ensure the security dashboard displays genuine security events rather than synthetic placeholders, the telemetry pipeline was re-engineered:

1. **Live Backend Evaluator Endpoints (`dashboard/server.py`)**:
   - `POST /api/evaluate-opa`: Receives request parameters, executes genuine OPA policy evaluations against `opa/policies/authz.rego`, records the decision with real execution latency (sub-millisecond), and writes a genuine event to `audit_log.json`.
   - `POST /api/vault/issue`: Calls `VaultPKIEngine.renew_certificate`, writes authentic cryptographic certificates, and emits a genuine crypto lifecycle event.
   - `POST /api/vault/revoke`: Calls `VaultPKIEngine.revoke_certificate`, updates the CRL, and emits a genuine revocation event.
2. **Event Provenance Tagging**:
   - Every event recorded in `opa/telemetry/audit_log.json` now carries explicit provenance metadata:
     ```json
     {
       "isGenuine": true,
       "verificationMode": "live_opa_ext_authz",
       "source": "live_request_evaluator"
     }
     ```
3. **Front-End Provenance Indicators (`dashboard/js/app.js` & `dashboard/index.html`)**:
   - **Provenance Badges**: Displays `<span class="badge genuine">GENUINE</span>` for verified live engine events vs `<span class="badge simulated">SIMULATED</span>` for manual test events.
   - **Provenance Filter**: Dropdown allowing security analysts to filter:
     - *All Provenance*
     - *Genuine / Verified Only*
     - *Simulated / Synthetic Only*
   - **Header KPI**: Real-time indicator displaying overall genuine telemetry rate (e.g. `Telemetry: 95% Genuine (71/75)`).
   - **Interactive Live Traffic Controls**: Clicking simulation buttons now triggers the real backend evaluator endpoints, transforming user simulations into genuine policy evaluations.

---

## 7. Known Limitations & Unverified Items

In adherence to zero-trust documentation integrity, the following items are acknowledged as unverified in the local environment:

| Area | Status | Unverified Scope | Next Owner / Milestone |
|:---|:---|:---|:---|
| **Kubernetes NetworkPolicies** | Pending | Policies enforce at Layer 7 (OPA ext_authz); Layer 3/4 CNI policies (Calico) are not yet integrated into this test harness. | Member 2 (Dhanush) |
| **PQC Hybrid Handshake in TLS** | Prototype | Current mTLS uses ECDSA P-256 + X25519; ML-KEM-768 hybrid key exchange is tested in Python (`tests/pqc/test_hybrid_kem.py`) but not yet compiled into Envoy's OpenSSL / BoringSSL TLS stack. | Member 3 (Tharun) & Member 4 (Agnes) |
| **Live Multi-Container Envoy** | Pending | Envoy configs (`envoy/*.yaml`) are syntactically validated but have not run inside multi-pod Kubernetes containers. | Member 4 (Agnes) |
| **Hardware Security Modules (HSM)** | Not Implemented | Vault dev Root CA is stored in software/file backend; production deployment requires PKCS#11 / cloud KMS auto-unseal. | Infrastructure / Production Deployment |

---

## 8. Verification Summary & Test Matrix

| Test Suite | File | Tests Executed | Passed | Failed | Success Rate |
|:---|:---|:---:|:---:|:---:|:---:|
| **OPA Unit Tests** | `opa/policies/*_test.rego` | 18 | 18 | 0 | **100%** |
| **OPA Contract Tests** | `tests/test_opa.ps1` | 10 | 10 | 0 | **100%** |
| **Service Path Authz & Secret Lifecycle** | `tests/test_service_path.py` | 15 | 15 | 0 | **100%** |
| **Vault PKI Setup, API & Rotation** | `tests/test_vault_pki.py` | 14 | 14 | 0 | **100%** |
| **Total Comprehensive Suite** | — | **57** | **57** | **0** | **100% PASS** |
