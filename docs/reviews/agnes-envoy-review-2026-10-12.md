# Agnes Envoy/PKI Review — 12 October 2026

## Scope
Reviewed remote branch `feature/agnes-envoy-mtls`,
commit `96569aa`, in an isolated directory at
`/tmp/agnes-review`. The project branch was not modified
during the initial review.

## Reproduced checks
- PKI certificate-chain and key/certificate matching checks passed.
- Certificate-purpose, SAN separation, expiry, and negative
  TLS/mTLS checks passed in the OpenSSL-based test harness.
- The original test run reported 24 PASS, 1 FAIL, 1 NOT RUN,
  and 1 informational PQC probe.
- The reported Compose failure was caused by the missing
  Docker Compose command (`docker compose` was unavailable).
- After installing Kali's standalone `docker-compose` package,
  `docker-compose config -q` returned exit code 0.
- Fresh local test CA, frontend certificate, and backend
  certificate were generated under
  `/tmp/agnes-review-runtime-pki`, outside the Git repository.
- Local PKI verification was run separately during this review.

## Findings and limitations
- Compose references host certificate paths under
  `/home/agnes/pki-mtls-secure/`, which do not exist on this
  Kali machine. Do not start the stack unchanged.
- Envoy's actual configuration validation has not yet been
  performed with an Envoy binary.
- Live Compose deployment and end-to-end Envoy-to-Envoy mTLS
  have not yet been verified.
- The current implementation uses classical ECDSA P-256
  certificates and TLS 1.3. It must not be described as
  hybrid post-quantum mTLS.
- The local OpenSSL PQC capability probe reported ML-KEM/Kyber
  availability and acceptance of the X25519MLKEM768 group.
  This is a capability observation only; it does not prove
  the Envoy deployment uses hybrid PQC.

## Next actions
1. Adapt certificate mounts for a reproducible test environment.
2. Validate both Envoy configurations with the actual Envoy binary.
3. Run the Compose stack and test authenticated and unauthenticated
   traffic, recording logs and results.
4. Keep PQC integration marked pending until hybrid key
   establishment and the actual data path are demonstrated.

## Review conclusion
The PKI scripts and OpenSSL-based negative tests show useful
foundational work. Compose syntax is valid, but runtime Envoy
integration and hybrid PQC remain unverified. Further evidence
is required before merging the feature as a completed integration.
