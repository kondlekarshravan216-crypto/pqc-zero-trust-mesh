# pqc-zero-trust-mesh
Enterprise-oriented prototype implementing a Post-Quantum Zero-Trust Kubernetes microsegmentation mesh with hybrid ECDH + ML-KEM, mTLS, OPA policy enforcement, secret management, and security observability.

## Components
- **OPA Policy Enforcement**: [`opa/README.md`](opa/README.md) - Decentralized authorization policies (`authorization.rego`, `authz.rego`), unit tests, test inputs, and security dashboard telemetry events.
- **Vault Secret Management**: [`vault/README.md`](vault/README.md) - HashiCorp Vault server dev configuration, least-privilege mesh secrets access policy (`mesh-secrets.hcl`), and security architecture review.
- **Automated Test Suite**: [`tests/test_opa.ps1`](tests/test_opa.ps1) & [`tests/test_opa.sh`](tests/test_opa.sh) - End-to-end automated test scripts verifying OPA unit tests and contract evaluations.
