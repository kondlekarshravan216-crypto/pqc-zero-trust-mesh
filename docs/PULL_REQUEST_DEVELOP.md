# Pull Request: OPA Authorization, Live Vault PKI Integration & Observability Dashboard (`feature/opa-vault` -> `develop`)

**Source Branch**: `feature/opa-vault`  
**Target Branch**: `develop`  
**Author**: Member 5 — Manideep (OPA, Vault & Dashboard Lead)  
**Date**: 10 November 2026  

---

## 1. Summary

This PR integrates and verifies the **OPA Authorization Policies**, **HashiCorp Vault PKI REST API Engine**, and **Security Observability Dashboard** into `develop`, including fixes for all runtime integration issues and test count mismatches identified during end-to-end verification.

### Key Deliverables
- **OPA Three-Tier Microsegmentation & Request-Path Enforcement**:
  - `opa/policies/authz.rego` & `opa/policies/authorization.rego` enforcing deny-by-default (`frontend` -> `backend` -> `database`), read-only method constraints, SPIFFE SVID allowlists, and Envoy `ext_authz` `CheckRequest` attributes.
  - Automated unit, contract, and live service-path mTLS + OPA `ext_authz` suites (`28/28` OPA tests + `15/15` service-path tests).
- **Live HashiCorp Vault PKI REST API Integration**:
  - `vault/scripts/vault_pki_coordinator.py` implementing `VaultAPIClient` (`/v1/sys/mounts/pki_mesh`, `/v1/pki_mesh/root/generate/internal`, `/v1/pki_mesh/roles/mesh-workload`, `/v1/pki_mesh/issue/mesh-workload`, `/v1/pki_mesh/revoke`, `/v1/pki_mesh/crl/pem`, `/v1/pki_mesh/ca/pem`, `/v1/sys/health`) with automatic fallback to `STANDALONE_CRYPTOGRAPHIC_EMULATION` when no Vault daemon is reachable.
  - Least-privilege Vault HCL policies (`vault/policies/mesh-pki.hcl`, `vault/policies/mesh-secrets.hcl`) and loopback dev configuration (`vault/configs/vault-dev.hcl`).
  - Live Vault PKI lifecycle suite (`tests/test_vault_pki.py`, `14/14` PASS in `LIVE_VAULT_HTTP_API` mode).
- **Observability & Security Dashboard**:
  - `dashboard/server.py`, `dashboard/index.html`, `dashboard/js/app.js`, `dashboard/css/index.css` providing live `/api/status`, `/api/vault/status`, `/api/events`, `/api/evaluate-opa`, `/api/vault/issue`, `/api/vault/revoke`, `/api/simulate`, and `/api/run-tests`.
  - Genuine vs. simulated provenance badges, filters, live SVG topology animation, and automated runtime test suite (`tests/test_dashboard.py`, `4/4` PASS).

---

## 2. Integration Fixes & Test Count Reconciliation

1. **Genuine OPA CLI Evaluation in Dashboard (`dashboard/server.py`)**:
   - Fixed `evaluate_opa_policy()` to pass `--stdin-input` instead of `--input -` (OPA v1.21.1 rejects `--input -`), eliminating silent fallback to `rego_embedded_engine` and recording genuine `opa_cli_v1` decisions (`isGenuine: true`).
2. **Live Vault Certificate Revocation & CRL Verification (`vault/scripts/vault_pki_coordinator.py`, `tests/test_vault_pki.py`)**:
   - Added `_format_vault_serial()` so plain hex serials are sent as hyphen-separated octets (`aa-bb-cc-...`) expected by Vault's `POST /v1/pki_mesh/revoke` endpoint (resolving `HTTP 400 Bad Request`).
   - Removed silent exception swallowing during live Vault revocation when no emulation CA key exists, and updated `is_revoked()` + `Test 9` to cryptographically parse Vault's returned PEM CRL.
3. **Dashboard Runtime Synchronization (`dashboard/server.py`, `dashboard/js/app.js`, `dashboard/index.html`)**:
   - Added `get_pki_coordinator()` so the dashboard dynamically detects Vault availability across requests instead of freezing startup mode.
   - Fixed `/api/vault/revoke` when triggered prior to manual issuance in a fresh session.
   - Wired `/api/status` polling into `dashboard/js/app.js` to display live CA serial, Vault API mode, OPA CLI liveness, active leaf count, and fixed the filtered audit table JSON modal index bug.
   - Added `"opa"` and `"dashboard"` test runner handlers and UI controls.
4. **Test Count Mismatches Resolved**:
   - Updated `dashboard/index.html` (`11 Tests` -> `14 Tests` for Vault PKI suite), fixed tab-escaped links in `README.md`, added `tests/test_dashboard.py`, and aligned `README.md`, `TEAM_STATUS.md`, `docs/VAULT_PKI_AND_OPA_INTEGRATION_STATUS_MONTH2_DAY1.md`, and verification reports to **61/61 (100% PASS)**.

---

## 3. Test Evidence (61/61 Passing)

| Suite | Command | Result | Report |
|:---|:---|:---:|:---|
| OPA Unit + Contract Tests | `powershell -ExecutionPolicy Bypass -File tests/test_opa.ps1` | **28/28 PASS** (18 unit + 10 eval) | `reports/opa-vault-dashboard-verification-20261110.md` |
| Service Path Authz & Secret Lifecycle | `python tests/test_service_path.py` | **15/15 PASS** | `tests/results-service-authz.md` |
| Vault PKI Live API & CRL Rotation | `python tests/test_vault_pki.py` (`LIVE_VAULT_HTTP_API`) | **14/14 PASS** | `tests/results-vault-pki.md` |
| Dashboard Runtime Telemetry & API | `python tests/test_dashboard.py` | **4/4 PASS** | `tests/results-dashboard.md` |
| **Total** | — | **61/61 PASS (100%)** | `reports/opa-vault-dashboard-verification-20261110.md` |

---

## 4. Reviewer Checklist

- [ ] `powershell -ExecutionPolicy Bypass -File tests/test_opa.ps1` passes (18/18 unit + 10/10 eval)
- [ ] `python tests/test_service_path.py` passes (15/15)
- [ ] `python tests/test_vault_pki.py` passes (14/14, including live Vault mode when `vault server -dev` is running)
- [ ] `python tests/test_dashboard.py` passes (4/4)
- [ ] No private keys, tokens, or `.exe` binaries tracked in git
- [ ] Merge `feature/opa-vault` -> `develop` via GitHub Pull Request
