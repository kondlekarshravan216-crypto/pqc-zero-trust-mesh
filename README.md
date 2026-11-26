# Post-Quantum Zero-Trust Microsegmentation Mesh

**A research prototype for identity-aware service communication, hybrid post-quantum key establishment, policy authorization, certificate lifecycle workflows, and security telemetry.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![OPA](https://img.shields.io/badge/Policy-OPA-7D5BA6)](https://www.openpolicyagent.org/)
[![TLS](https://img.shields.io/badge/Transport-TLS%201.3-2563EB)](https://www.rfc-editor.org/rfc/rfc8446)
[![Status](https://img.shields.io/badge/Project-Prototype-orange)](#implementation-status-and-evidence)

> **Evidence-first status:** This repository contains working prototypes and dated verification artefacts. It is not a production-ready, fully integrated PQC Kubernetes service mesh. The current dashboard verification reports Vault in standalone cryptographic emulation mode; current live Vault health was not available on 26 November 2026. See [limitations](#known-limitations) and the [final submission report](reports/FINAL_PROJECT_SUBMISSION_2026-11-26.md).

## At a glance

| Area | What is present | Evidence boundary |
|---|---|---|
| Zero-trust policy | Rego policies for frontend → backend → database authorization | Historical OPA unit/contract and service-path reports; rerun before claiming current pass |
| Workload identity and mTLS | SPIFFE-style URI SANs, TLS 1.3 Envoy configuration, local test CA scripts | Dated Envoy/mTLS evidence; some earlier tests used a TLS stand-in |
| Hybrid PQC | Python X25519 + ML-KEM-768 key-establishment prototype | Five recorded unit tests; dated packet captures show X25519MLKEM768 for specific tested handshakes |
| Certificate lifecycle | Vault API client/dual-mode PKI engine and emulation fallback | Current dashboard showed emulation mode; live Vault was not healthy during 26 Nov check |
| Kubernetes microsegmentation | Architecture and dated Minikube/NetworkPolicy demo artefacts | Not a currently reproducible clean-clone deployment; inspect dated evidence |
| Observability | Local dashboard with status, authorization and telemetry endpoints | Current local dashboard status checked 26 Nov 2026; telemetry includes historical and simulated events |

## Dashboard preview

The dashboard screenshots below are embedded directly in this README so visitors can see them on the repository landing page without opening the `docs/screenshots/` directory.

### 1. Dashboard overview
![Dashboard overview](docs/screenshots/01-dashboard-overview.png)

### 2. Mesh topology
![Mesh topology](docs/screenshots/02-mesh-topology.png)

### 3. OPA authorization
![OPA authorization](docs/screenshots/03-opa-authorization.png)

### 4. Security telemetry
![Security telemetry](docs/screenshots/04-security-telemetry.png)

### 5. Vault PKI status
![Vault PKI status](docs/screenshots/05-vault-pki.png)

[Open the complete screenshot directory](docs/screenshots/).

## Architecture

The intended workload path is:

```text
Frontend workload
    |
    | workload identity + TLS 1.3 mTLS
    v
Frontend Envoy
    |
    | authenticated service request
    v
Backend Envoy -----> OPA authorization decision
    |                    |
    | ALLOW               | DENY
    v                    v
Backend application   HTTP 403 / reject
    |
    | authorized backend-only access
    v
Database service
```

Kubernetes NetworkPolicies are intended to provide network-level segmentation around this application-level identity and authorization model. The above is the design/request path; not every component is currently deployed together in one reproducible Kubernetes environment.

## Main components

- **OPA:** Rego policies and unit/contract tests in `opa/policies/` and `tests/`.
- **Envoy and mTLS:** Proxy configurations in `envoy/`; local test CA scripts and extensions in `pki/`.
- **Hybrid key establishment:** Python prototype in `pqc/hybrid_kem.py`, combining X25519 and ML-KEM-768 secrets through a transcript-bound HKDF-SHA-256 derivation.
- **Vault PKI:** API client/coordinator, policies and development configuration in `vault/`.
- **Dashboard:** `dashboard/server.py`, static UI, and telemetry from `opa/telemetry/audit_log.json`.
- **Kubernetes and integration evidence:** Architecture, integration notes and dated test artefacts under `docs/` and `reports/`.

## Quick start: local dashboard

Tested locally on Kali Linux on 26 November 2026.

Requirements: Python 3 and the dependencies needed by `dashboard/server.py` / `vault/scripts/vault_pki_coordinator.py`.

```bash
git clone https://github.com/kondlekarshravan216-crypto/pqc-zero-trust-mesh.git
cd pqc-zero-trust-mesh

# Optional: create an isolated Python environment
python3 -m venv .venv
source .venv/bin/activate

# Install runtime libraries used by the dashboard and Vault coordinator
python3 -m pip install cryptography requests

# Start the dashboard
bash dashboard/run_dashboard.sh
```

Open: **http://127.0.0.1:8050**

In a second terminal, inspect the read-only status endpoint:

```bash
curl -sS http://127.0.0.1:8050/api/status
curl -sS http://127.0.0.1:8050/api/events
```

The dashboard can use the installed OPA CLI for `/api/evaluate-opa`; if that subprocess path is unavailable, the server has a Python fallback evaluator. Check the returned `evaluator` field before describing a result as an OPA CLI evaluation.

## Full-stack prerequisites

The Compose file defines backend application, frontend/backend Envoy, and OPA services. It expects certificate files in a directory configured through `CERT_DIR` in a local, untracked `.env` file. A sample environment file is provided as `.env.example`.

Before attempting the full stack:

1. Install Docker Engine and the Compose plugin.
2. Generate or obtain the expected test certificates and confirm filenames match the Compose mounts.
3. Set `CERT_DIR` to the absolute certificate directory in your local `.env`.
4. Validate the configuration with `docker compose config`.
5. Start services only after reviewing the local certificate and Vault configuration.

Do not commit private keys, real tokens, Vault unseal material or populated `.env` files. The repository's local development Vault configuration is not a production deployment profile.

## Implementation status and evidence

### Historical automated verification

The dated [OPA/Vault/Dashboard verification report from 5 November 2026](reports/opa-vault-dashboard-verification-20261105.md) records **61/61 checks passed** across the suites listed in that report. Those results are historical and are not a fresh test run on 26 November.

Other dated artefacts include:

- [Hybrid PQC integration validation](reports/pqc-evidence/validation-report.md)
- [Captured hybrid key-share summary](reports/pqc-evidence/hybrid-keyshare.txt)
- [Envoy/mTLS validation log](reports/live-envoy-mtls-validation.txt)
- [Kubernetes microsegmentation demo log](reports/live-kubernetes-demo-20261030.txt)
- [OPA and secret-management verification](docs/AUTHORIZATION_AND_SECRET_MANAGEMENT_VERIFICATION.md)

### Current dashboard check — 26 November 2026

The local `/api/status` response reported:

- Dashboard: `healthy`
- OPA CLI installed: `true` (installation check only)
- Telemetry events: 150 total — 97 genuine-tagged and 53 simulated-tagged
- Vault engine: `STANDALONE_CRYPTOGRAPHIC_EMULATION`
- Live Vault health: `false`

The stored telemetry contains historic records and simulated events. Event counts are not a real-time threat rate or proof of newly generated live traffic.

## Cryptographic scope: important distinction

- The Python prototype combines X25519 and ML-KEM-768 and derives a 32-byte key using HKDF-SHA-256.
- Dated packet-capture reports record the hybrid TLS 1.3 group `X25519MLKEM768` in specific test handshakes. This does not prove every service connection or every deployment negotiates that group.
- The current mTLS certificate profiles use ECDSA P-256. **ML-DSA certificate signatures are not implemented/verified in the current mTLS certificate chain.**
- A dashboard label or algorithm name alone is not cryptographic handshake evidence. Use the packet capture and exact test context when making a PQC claim.

## Known limitations

1. **Vault:** The 26 November dashboard check used standalone cryptographic emulation; live Vault health was false at that time.
2. **OPA path:** Dashboard status confirms the OPA executable is installed, not that the live Envoy `ext_authz` request path is currently healthy. The evaluator can fall back to a Python implementation; inspect its `evaluator` field.
3. **PQC:** Hybrid key-establishment prototype and specific TLS handshake artefacts exist, but end-to-end hybrid negotiation is not established for every path. ML-DSA signatures on workload certificates remain unimplemented.
4. **Kubernetes:** Dated Minikube/NetworkPolicy results are historical evidence; they are not a repeatable current cluster deployment.
5. **Production hardening:** Local dev Vault settings, test CA material and static certificate delivery require hardening before any production use.

## Project documentation

| Resource | Description |
|---|---|
| [Final submission report](reports/FINAL_PROJECT_SUBMISSION_2026-11-26.md) | Current submission summary, dashboard evidence and limitations |
| [Architecture v1](docs/architecture/architecture-v1.md) | High-level architecture and intended request flow |
| [OPA integration contract](docs/architecture/opa-integration-contract.md) | Authorization contract |
| [Integration notes](docs/INTEGRATION.md) | Cross-component status and evidence boundaries |
| [Vault documentation](vault/README.md) | Vault policies, dev configuration and PKI workflow |
| [OPA documentation](opa/README.md) | Rego policies and tests |
| [Team status](TEAM_STATUS.md) | Team workstream and pending items |

## Repository layout

```text
.
├── backend/          # Demo backend service
├── dashboard/        # Local security observability dashboard
├── docs/             # Architecture, integration and screenshots
├── envoy/            # Envoy proxy configurations
├── opa/              # Rego policies and telemetry data
├── pki/              # Local test CA extensions and scripts
├── pqc/              # Hybrid key-establishment prototype
├── reports/          # Dated validation and submission reports
├── tests/            # Policy, service-path, PKI and PQC tests
└── vault/            # Vault development configuration and PKI tooling
```

## Disclaimer

This is an academic/research prototype for controlled testing. It has not been independently security-audited and must not be deployed as a production service mesh without threat modelling, key-management hardening, reproducible integration tests, monitoring, and operational review.
