
# Architecture v1
## Post-Quantum Zero-Trust Microsegmentation Mesh

### 1. Objective
Build a prototype combining post-quantum cryptography,
Zero-Trust authorization, and Kubernetes microsegmentation.

### 2. Core Components
- Kubernetes: Runs the application services.
- NetworkPolicies: Restricts pod-to-pod communication.
- ECDH + ML-KEM: Hybrid session key establishment.
- Certificate Authority: Issues service identity certificates.
- Envoy: Handles service proxying and mTLS.
- OPA: Evaluates authorization policies.
- Vault: Manages secrets and supports certificate lifecycle workflows.
- Dashboard: Displays security events and test results.

### 3. Request Flow
1. A source service sends a request.
2. NetworkPolicies restrict permitted network communication.
3. Envoy establishes or validates the service connection.
4. The cryptographic layer provides the configured session security.
5. OPA evaluates the authorization decision.
6. The destination service accepts or rejects the request.
7. Security events are recorded for dashboard visibility.

### 4. Security Tests
- Allowed and denied network traffic
- Valid and invalid service identities
- OPA ALLOW and DENY decisions
- Cryptographic correctness and performance
- Certificate or key rotation
- Compromised-service isolation
- Network partition behavior

### 5. Implementation Status and Verification Boundaries

- Component prototypes and regression tests are present; the latest GitHub Actions workflow passed on 26 November 2026 at commit `b7eb4eb`.
- The Python X25519 + ML-KEM-768 key-establishment prototype has focused unit tests. This does not prove every Envoy service connection negotiates the hybrid group.
- Live Vault health was unavailable during the 26 November dashboard check; the dashboard selected standalone cryptographic emulation.
- Current workload certificate profiles use ECDSA P-256. ML-DSA certificate signatures are not implemented.
- Live Envoy SDS rotation and a reproducible full Kubernetes deployment remain open integration tasks.
- This is a prototype, not a production-ready fully integrated PQC Kubernetes service mesh. See the root README and final submission report for dated evidence.
