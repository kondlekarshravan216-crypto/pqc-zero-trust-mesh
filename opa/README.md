# Open Policy Agent (OPA) - Zero-Trust Microsegmentation

This module provides fine-grained, decentralized policy enforcement for the **Post-Quantum Zero-Trust Kubernetes Microsegmentation Mesh (`pqc-zero-trust-mesh`)**. It ensures that service-to-service communication strictly enforces zero-trust authorization (deny-by-default) based on cryptographic SPIFFE identities and mesh routing constraints.

---

## 1. Environment & Setup

### Tool Status
- **Checked Command**: `opa version`
- **Current Status**: **Missing / Not installed** (`The term 'opa' is not recognized as the name of a cmdlet, function, script file, or operable program`).
- Files have been prepared and structured for immediate execution once installation is approved.

### Installation Instructions

#### Option A: Windows (PowerShell / Package Managers)
```powershell
# Via Winget
winget install OpenPolicyAgent.OPA

# Via Chocolatey
choco install opa

# Or download official binary directly
Invoke-WebRequest -Uri "https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe" -OutFile "$env:USERPROFILE\bin\opa.exe"
# Ensure $env:USERPROFILE\bin is in your PATH
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

## 2. Policy Explanation (`opa/policies/authz.rego`)

The authorization policy implements Zero-Trust Network Architecture (ZTNA) principles:

```rego
package authz

# 1. Deny-by-default: Without explicit allow conditions, all traffic is rejected
default allow = false

# 2. Approved Identities: Trusted SPIFFE IDs and workload identifiers
approved_frontend_identities = {
    "frontend-service",
    "spiffe://cluster.local/ns/mesh/sa/frontend-service"
}

# 3. Authorization Rule: Caller must be an approved frontend identity targeting backend
allow {
    approved_frontend_identities[input.identity]
    input.destination == "backend"
}

# 4. Audit Metadata: Reasons recorded for observability & telemetry
reason = "Access granted: approved frontend identity" {
    allow
}

reason = "Access denied: unapproved identity or unauthorized destination" {
    not allow
}
```

### Policy Characteristics
- **Zero-Trust Baseline (`default allow = false`)**: Closed by default. Any unhandled case or missing attribute results in denial.
- **Identity Enforcement**: Verifies the caller against cryptographic mesh credentials (SPIFFE SVID established during the post-quantum hybrid mTLS handshake).
- **Segmentation**: Even valid identities cannot reach arbitrary services; communication is restricted specifically to authorized destinations (e.g., `backend`).

---

## 3. Test Inputs & Test Execution

### Test Files Created
- **Allowed Request**: [`opa/inputs/allowed.json`](inputs/allowed.json)
  ```json
  {
    "identity": "spiffe://cluster.local/ns/mesh/sa/frontend-service",
    "destination": "backend",
    "action": "GET",
    "path": "/api/v1/metrics",
    "timestamp": "2026-10-12T13:00:00Z"
  }
  ```
- **Denied Request**: [`opa/inputs/denied.json`](inputs/denied.json)
  ```json
  {
    "identity": "spiffe://cluster.local/ns/mesh/sa/unapproved-service",
    "destination": "backend",
    "action": "POST",
    "path": "/api/v1/admin/shutdown",
    "timestamp": "2026-10-12T13:05:00Z"
  }
  ```
- **Unit Test Suite**: [`opa/policies/authz_test.rego`](policies/authz_test.rego)

### Execution Commands (Run After Installing OPA)

#### 1. Evaluate Allowed Request:
```bash
opa eval --data opa/policies/authz.rego --input opa/inputs/allowed.json "data.authz"
```
**Expected Output**:
```json
{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "allow": true,
            "approved_frontend_identities": [
              "frontend-service",
              "spiffe://cluster.local/ns/mesh/sa/frontend-service"
            ],
            "reason": "Access granted: approved frontend identity"
          },
          "text": "data.authz",
          "location": { "row": 1, "col": 1 }
        }
      ]
    }
  ]
}
```
*Decision*: **`allow: true`**

#### 2. Evaluate Denied Request:
```bash
opa eval --data opa/policies/authz.rego --input opa/inputs/denied.json "data.authz"
```
**Expected Output**:
```json
{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "allow": false,
            "approved_frontend_identities": [
              "frontend-service",
              "spiffe://cluster.local/ns/mesh/sa/frontend-service"
            ],
            "reason": "Access denied: unapproved identity or unauthorized destination"
          },
          "text": "data.authz",
          "location": { "row": 1, "col": 1 }
        }
      ]
    }
  ]
}
```
*Decision*: **`allow: false`**

#### 3. Run Policy Unit Tests:
```bash
opa test opa/policies/ -v
```
**Expected Output**:
```text
data.authz.test_allow_approved_identity: PASS (0.5ms)
data.authz.test_deny_unapproved_identity: PASS (0.2ms)
data.authz.test_deny_unauthorized_destination: PASS (0.2ms)
data.authz.test_deny_empty_input: PASS (0.1ms)
--------------------------------------------------------------------------------
PASS: 4/4
```

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
