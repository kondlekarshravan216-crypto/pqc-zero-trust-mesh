# HashiCorp Vault - Secret Management & PKI Lifecycle Review

This directory contains configuration and access policies for **HashiCorp Vault** within the **Post-Quantum Zero-Trust Kubernetes Microsegmentation Mesh (`pqc-zero-trust-mesh`)**.

---

## 1. Role in Mesh Architecture (Day 2 Review)

In our zero-trust mesh architecture, HashiCorp Vault acts as the centralized secrets broker and certificate lifecycle coordinator for Member 5 responsibilities:
1. **Mesh Secret Storage**: Securely houses database credentials, backend API tokens, and sensitive runtime configuration via the KV v2 secrets engine.
2. **PKI & Certificate Authority Lifecycle**: Supplies root/intermediate CA capabilities to issue and rotate X.509 certificates and SPIFFE SVIDs used by Envoy proxies during hybrid mTLS handshakes.
3. **Least Privilege Secret Access**: Enforces role-based and service-identity-based access control policies (`mesh-secrets.hcl`), preventing unauthorized lateral secret retrieval.
4. **Auditability & Observability**: Logs all secret read/write operations, feeding into the security observability dashboard (`opa/telemetry/dashboard_events.json`).

---

## 2. Configuration Analysis & Review

### 2.1 Server Configuration (`vault/configs/vault-dev.hcl`)

```hcl
ui = true

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

storage "file" {
  path = "./vault/data"
}

api_addr = "http://127.0.0.1:8200"
```

#### Evaluation:
- **Environment Fit**: Tailored for local development, rapid prototyping, and automated CI integration.
- **`ui = true`**: Enables the web dashboard at `http://127.0.0.1:8200/ui` for real-time inspection of secrets engines, leases, and access policies.
- **`listener "tcp"`**:
  - Bound strictly to loopback (`127.0.0.1:8200`), restricting external network exposure.
  - `tls_disable = true` simplifies local dev setup without certificate bootstrapping chicken-and-egg issues.
  - *Production Recommendation*: Enable TLS (`tls_cert_file`, `tls_key_file`, `tls_client_ca_file`) for mutual TLS between Envoy/SPIRE and Vault.
- **`storage "file"`**:
  - Uses file-backed persistence under `./vault/data`.
  - Directory is properly protected via [`vault/.gitignore`](.gitignore) and root [`.gitignore`](../.gitignore), preventing accidental commitment of raw encrypted state or local data.
  - *Production Recommendation*: In Kubernetes, transition to Vault Integrated Storage (Raft) with persistent volume claims (PVCs) for high availability across cluster nodes.
- **`api_addr`**: Correctly specifies the advertised API URL for clients and CLI tools.

---

### 2.2 Access Policy (`vault/policies/mesh-secrets.hcl`)

```hcl
path "secret/data/mesh/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/mesh/*" {
  capabilities = ["read", "list"]
}
```

#### Evaluation:
- **KV Version 2 Alignment**: The policy correctly uses Vault KV v2 path conventions:
  - `secret/data/mesh/*`: Data path containing actual payload versions.
  - `secret/metadata/mesh/*`: Metadata path containing version numbers, timestamps, and deletion state.
- **Least-Privilege Enforcement**:
  - **Zero-Trust Principle (No Destructive Action)**: Grants `create`, `read`, and `update`, but deliberately omits `delete` and `destroy` capabilities. Service workloads can write new secrets or retrieve active secrets, but cannot destroy audit history or purge secrets.
  - **Metadata Isolation**: Grants `read` and `list` on metadata so workloads and operators can check key versions and rotation schedules without modifying secret structure.
- **Future Integration Enhancements**:
  - Add PKI policy paths for dynamic certificate issuance:
    ```hcl
    path "pki_mesh/issue/workload-role" {
      capabilities = ["update"]
    }
    ```
  - Bind workload access directly to Kubernetes ServiceAccounts using `auth/kubernetes` with SPIFFE ID validation.

---

## 3. Operational Guide

### 3.1 Starting the Development Vault Server

```powershell
# In PowerShell (from project root)
vault server -config=vault/configs/vault-dev.hcl
```

```bash
# In Linux / macOS / WSL
vault server -config=vault/configs/vault-dev.hcl
```

### 3.2 Applying and Verifying the Mesh Policy

```powershell
# Set environment variables for local client
$env:VAULT_ADDR = "http://127.0.0.1:8200"

# Initialize and unseal Vault (or use dev token if started with -dev)
# Write the mesh-secrets policy:
vault policy write mesh-secrets vault/policies/mesh-secrets.hcl

# Verify the policy rules
vault policy read mesh-secrets
```

### 3.3 Testing Secret Write and Read

```bash
# Enable KV v2 engine if not already mounted
vault secrets enable -version=2 -path=secret kv

# Store mesh database credentials
vault kv put secret/mesh/database username="mesh-backend" password="pqc-encrypted-sample-password"

# Read mesh database credentials
vault kv get secret/mesh/database
```

---

## 4. Security & Compliance Checklist

- [x] **No Secrets Committed**: Verified repository contains zero tokens, unseal keys, private keys, or passwords.
- [x] **Ignored Storage**: `./vault/data/` is strictly excluded via `.gitignore`.
- [x] **Dev Configuration Scoped**: Bound to `127.0.0.1` to prevent unauthorized cross-network access.
- [x] **Policy Immutability**: `delete` and `destroy` capabilities excluded from mesh workload policy.
- [x] **Roadmap Aligned**: Aligns with Day 2 architecture contract and OPA integration specifications.
