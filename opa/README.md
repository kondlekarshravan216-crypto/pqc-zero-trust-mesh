# Open Policy Agent (OPA) - Zero-Trust Microsegmentation

This module provides fine-grained, decentralized policy enforcement for the **Post-Quantum Zero-Trust Kubernetes Microsegmentation Mesh (`pqc-zero-trust-mesh`)**. It ensures that service-to-service communication strictly enforces zero-trust authorization (deny-by-default) based on cryptographic SPIFFE identities and mesh routing constraints.

---

## 1. Environment & Setup

### Tool Status
- **Checked Command**: `opa version`
- **Current Status**: **Installed & Verified (OPA v1.21.1, Rego v1 default)**.
- All unit tests and contract integration tests execute cleanly in native environment.

### Installation Instructions

#### Option A: Windows (PowerShell / Direct Binary)
```powershell
# Via Winget
winget install OpenPolicyAgent.OPA

# Or download official binary directly
Invoke-WebRequest -Uri "https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe" -OutFile "$env:USERPROFILE\bin\opa.exe"
# Ensure directory is in your PATH
```

#### Option B: Linux / macOS / WSL
```bash
# Linux (AMD64)
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 /usr/local/bin/opa

# macOS (Homebrew)
brew install opa
```

#### Option C: Docker (When Docker daemon is active)
```bash
docker run --rm -v ${PWD}:/workspace -w /workspace openpolicyagent/opa:latest test opa/policies/ -v
```

---

## 2. Policy Explanation

### 2.1 Identity Authorization Policy (`opa/policies/authz.rego`)

The authorization policy implements Zero-Trust Network Architecture (ZTNA) principles in Rego v1:

```rego
package authz

import rego.v1

# 1. Deny-by-default: Without explicit allow conditions, all traffic is rejected
default allow := false

# 2. Approved Identities: Trusted SPIFFE IDs and workload identifiers
approved_frontend_identities := {
    "frontend-service",
    "spiffe://cluster.local/ns/mesh/sa/frontend-service",
}

# 3. Authorization Rule: Caller must be an approved frontend identity targeting backend
allow if {
    approved_frontend_identities[input.identity]
    input.destination == "backend"
}

# 4. Audit Metadata: Reasons recorded for observability & telemetry
reason := "Access granted: approved frontend identity" if {
    allow
}

reason := "Access denied: unapproved identity or unauthorized destination" if {
    not allow
}
```

### 2.2 Integration Contract Policy (`opa/policies/authorization.rego`)

Implements the inter-service authorization contract defined in `docs/architecture/opa-integration-contract.md`:

```rego
package mesh.authz

import rego.v1

default allow := false

allow if {
    input.source == "frontend"
    input.destination == "backend"
    input.action == "read"
}

allow if {
    input.source == "backend"
    input.destination == "database"
    input.action == "read"
}
```

---

## 3. Test Suite & Automated Execution

### 3.1 Automated Test Scripts (Day 2)

An automated test suite is provided to execute all unit tests and contract evaluations in one command:

- **PowerShell (Windows)**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File tests/test_opa.ps1
  ```
- **Bash (Linux / CI)**:
  ```bash
  chmod +x tests/test_opa.sh
  ./tests/test_opa.sh
  ```

### 3.2 Running Policy Unit Tests
```bash
opa test opa/policies/ -v
```
**Output**:
```text
data.mesh.authz.test_allow_frontend_backend: PASS
data.mesh.authz.test_allow_backend_database: PASS
data.mesh.authz.test_deny_frontend_database: PASS
data.mesh.authz.test_deny_unknown_backend: PASS
data.authz.test_allow_approved_identity: PASS
data.authz.test_deny_unapproved_identity: PASS
data.authz.test_deny_unauthorized_destination: PASS
data.authz.test_deny_empty_input: PASS
--------------------------------------------------------------------------------
PASS: 8/8
```

### 3.3 Four Contract Evaluation Tests (`tests/opa/*.json`)

| Test File | Source | Destination | Action | Expected | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `tests/opa/allow-frontend-backend.json` | frontend | backend | read | `true` | **PASS** |
| `tests/opa/allow-backend-database.json` | backend | database | read | `true` | **PASS** |
| `tests/opa/deny-frontend-database.json` | frontend | database | read | `false` | **PASS** |
| `tests/opa/deny-unknown-backend.json` | unknown | backend | read | `false` | **PASS** |

---

## 4. Security Observability: Dashboard Events

The mesh observability pipeline tracks security-relevant telemetry events defined in [`opa/telemetry/dashboard_events.json`](telemetry/dashboard_events.json):

| Event Type | Category | Severity | Description | Alert Trigger Condition |
| :--- | :--- | :--- | :--- | :--- |
| **Denied Requests** (`denied_request`) | Authorization | `WARNING` | Blocked inter-service requests failing OPA policy evaluation. Logs source SPIFFE ID, target service, and path. | > 5 events within 1 minute from a single source |
| **Failed Authentication** (`failed_authentication`) | Authentication | `HIGH` | mTLS handshake failures, untrusted CAs, invalid post-quantum signatures (ML-DSA), or expired SVIDs. | > 3 failures within 5 minutes |
| **Suspicious Commands** (`suspicious_command`) | Runtime Security | `CRITICAL` | Unexpected pod execution, shell spawning (`sh`, `bash`), privilege escalation, or access to sensitive endpoints. | Immediate alert on any trigger |
| **Key/Certificate Rotation** (`key_certificate_rotation`) | Crypto Lifecycle | `INFO` | Automated lifecycle events for ML-KEM hybrid key pairs, SPIFFE certificates, and mesh CA rotations. | Alert on rotation failure or cert expiring in < 1h |

---

## 5. Security & Vault Integration Notice

> **Note**: No real secrets, API keys, or Vault credentials are committed to this repository. Integration with HashiCorp Vault / SPIRE for dynamic secret leasing and post-quantum mTLS key generation will take place in subsequent phases following prototype policy validation.
