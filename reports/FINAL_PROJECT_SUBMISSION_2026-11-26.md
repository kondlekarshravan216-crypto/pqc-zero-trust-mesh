# Post-Quantum Zero-Trust Microsegmentation Mesh
## Final Project Submission Report

**Project Lead:** Shravan Kondlekar  
**Date:** 26 November 2026  
**Repository:** https://github.com/kondlekarshravan216-crypto/pqc-zero-trust-mesh

## 1. Project Overview

The Post-Quantum Zero-Trust Microsegmentation Mesh is a security architecture designed to secure workload-to-workload communication using post-quantum cryptography, identity-based authorization, mutual TLS, certificate lifecycle management, and network microsegmentation.

## 2. Architecture and Components

- Hybrid ECDH-P256 and ML-KEM-768 key establishment.
- ML-DSA-65 cryptographic algorithm support in the project design.
- Open Policy Agent (OPA) for authorization.
- Envoy Proxy for service communication and mTLS integration.
- Vault PKI for certificate lifecycle management.
- SPIFFE-based workload identities.
- Kubernetes NetworkPolicy-based microsegmentation.
- Dashboard for security telemetry and monitoring.

## 3. Zero-Trust Authorization

The intended service architecture follows:

Frontend -> Backend -> Database

Authorization policies cover permitted service communication, denial of unauthorized workload identities, and prevention of direct frontend-to-database access.

## 4. Historical Test Evidence

The existing verification report dated 5 November 2026 records:

| Test category | Reported result |
|---|---:|
| OPA unit tests | 18/18 passed |
| OPA contract tests | 10/10 passed |
| Service-path tests | 15/15 passed |
| Vault PKI tests | 14/14 passed |
| Dashboard checks | 4/4 passed |
| Total | 61/61 passed |

These are historical results from the earlier report, not a fresh test run on the submission date.

Reference: `reports/opa-vault-dashboard-verification-20261105.md`

## 5. Dashboard Verification — 26 November 2026

A local dashboard snapshot was collected on 26 November 2026, before the subsequent dashboard provenance/security fixes were committed.

The original status response reported:
- Dashboard endpoint: healthy
- OPA CLI installed: true (installation check only)
- Telemetry file: available
- Stored events: 150
- Vault engine mode: `STANDALONE_CRYPTOGRAPHIC_EMULATION`
- Live Vault health: false

The original endpoint also reported 97 events as “genuine” and 53 as “simulated”. That split used a legacy boolean flag and was not a reliable measure of live component activity: emulation, test-harness and unclassified legacy events were not separated. The updated dashboard code classifies live Vault API records, local OPA CLI evaluations, test-harness records, cryptographic emulation, explicit simulation and unclassified legacy records separately. Pull the latest `main` branch before relying on the updated status endpoint.

### Event distribution in the local snapshot

| Event type | Count |
|---|---:|
| Key/certificate rotation | 78 |
| Allowed requests | 29 |
| Denied requests | 22 |
| Failed authentication | 21 |
| Total | 150 |

### Event status distribution in the local snapshot

| Status | Count |
|---|---:|
| SUCCESS | 62 |
| REVOKED | 16 |
| Missing status field | 72 |

These are stored historical records, not a live attack rate or evidence of newly generated traffic. The event log in the local working copy may differ from the telemetry file committed to GitHub.

## 6. Cryptographic Scope

- The Python key-establishment prototype in `pqc/hybrid_kem.py` combines **X25519 + ML-KEM-768** and derives a session key using transcript-bound HKDF-SHA-256. Five focused unit tests are recorded in `hybrid-kem-test-results.txt`.
- The Envoy TLS configurations advertise `X25519MLKEM768` before classical fallback groups. Dated runtime notes and packet captures contain evidence for specific test handshakes; they do not prove that every current connection negotiates the hybrid group.
- The workload certificate profiles use **ECDSA P-256 / ECDSA-SHA256**. This is separate from TLS session key establishment.
- **ML-DSA certificate signatures are not implemented** in the current workload certificate chain.

## 7. Visual Evidence

The following dashboard screenshots were captured on 26 November 2026. They are embedded below so they are visible directly in this report on GitHub.

### 7.1 Dashboard Overview

![Dashboard Overview](../docs/screenshots/01-dashboard-overview.png)

### 7.2 Mesh Topology

![Mesh Topology](../docs/screenshots/02-mesh-topology.png)

### 7.3 OPA Authorization

![OPA Authorization](../docs/screenshots/03-opa-authorization.png)

### 7.4 Security Telemetry

![Security Telemetry](../docs/screenshots/04-security-telemetry.png)

### 7.5 Vault PKI

![Vault PKI](../docs/screenshots/05-vault-pki.png)

## 8. Other Project Evidence

- `docs/architecture/architecture-v1.md`
- `docs/architecture/opa-integration-contract.md`
- `docs/AUTHORIZATION_AND_SECRET_MANAGEMENT_VERIFICATION.md`
- `reports/pqc-evidence/validation-report.md`
- `reports/live-envoy-mtls-validation.txt`
- `reports/live-kubernetes-demo-20261030.txt`
- `reports/evidence/mesh-topology-and-authz-flow.svg`

## 9. Current Engineering Gaps

1. Live Vault health was false in the 26 November dashboard snapshot; the dashboard used standalone cryptographic emulation.
2. The dashboard's local OPA CLI/Python evaluator is not proof of a live Envoy-to-OPA gRPC `ext_authz` request path.
3. The Python hybrid key-establishment prototype is not yet an authenticated peer-to-peer protocol with identity binding and key confirmation.
4. The workload certificate chain remains ECDSA P-256; ML-DSA certificate signatures are not implemented.
5. Envoy file-mounted test certificates are separate from Vault PKI issuance; automated SDS certificate delivery/rotation is not currently implemented.
6. Kubernetes NetworkPolicy manifests and a reproducible clean-clone cluster deployment are not present in the repository. Dated Minikube logs are historical evidence only.
7. The 61/61 result belongs to the historical 5 November verification report; it is not a fresh test run for this submission.
8. The dashboard status and telemetry snapshot must be regenerated after pulling the latest code, because provenance classification and API safety controls have since changed.

## 10. Conclusion

The project integrates post-quantum cryptographic design, zero-trust authorization, workload identity, certificate lifecycle management, microsegmentation, and security observability.

Historical test reports document successful verification of OPA, service-path, Vault PKI, and dashboard components. The final dashboard check confirms that the dashboard is operational and stored telemetry is accessible, while identifying the current Vault emulation limitation.
