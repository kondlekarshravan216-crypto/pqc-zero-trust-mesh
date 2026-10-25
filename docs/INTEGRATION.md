# Integration requirements

## Kubernetes teammate

*(Names/ports are assumptions pending the official architecture.)*

| Item | Value |
|---|---|
| Namespace / trust domain | `demo` / `pqzt.local` |
| Services | `backend` (Envoy mTLS listener **8443**, app 8080 pod-local), `frontend` (Envoy egress listener **8080**) |
| Cert mounts (read-only) | backend pod: `backend.crt`, `backend.key`, `ca.crt` → `/etc/pqzt/certs/`; frontend pod: `frontend.crt`, `frontend.key`, `ca.crt` |
| Secrets | one `kubernetes.io/tls`-style Secret per service (+ `ca.crt`); **never** mount `ca.key` in a pod |
| Envoy config | ConfigMaps from `envoy/*.yaml`; in a sidecar layout change cluster `backend-app`/`backend-envoy` addresses to `127.0.0.1` / the `backend` Service DNS |
| NetworkPolicy | allow frontend→backend TCP 8443 only; deny other ingress to 8443; backend app 8080 reachable only from the pod itself |
| Cert SANs | already include `<svc>.demo.svc.cluster.local`; if names/namespace change, edit `pki/ext/*.ext` **and** the SAN matchers in the Envoy YAML |
| Certificate lifetime | 90 d, static files — rotation needs pod restart (no SDS/cert-manager yet) |

Needed from you: confirm namespace, Service names, sidecar vs. standalone Envoy, and secret-delivery method (cert-manager would replace `scripts/`).

## PQC teammate

**Environment facts vary by test environment.** Earlier offline tests used OpenSSL 3.0.13 and did not support `X25519MLKEM768`; live frontend upstream Envoy statistics confirmed `cluster.backend_mtls.ssl.curves.X25519MLKEM768: 3`, `cluster.backend_mtls.ssl.versions.TLSv1.3: 3`, and `cluster.backend_mtls.ssl.handshake: 3`, with zero connection and certificate-verification errors.

**PQC status: HYBRID KEY-EXCHANGE NEGOTIATION VERIFIED for the tested frontend-Envoy-to-backend-Envoy connection.**

Classical fallback was verified in an isolated Envoy-to-Envoy test: the temporary backend was restricted to X25519, the frontend request returned HTTP 200, and frontend statistics reported `cluster.backend_mtls.ssl.curves.X25519: 1` and `cluster.backend_mtls.ssl.handshake: 1`. This verifies fallback for the isolated test configuration; it does not establish that the original live stack was changed or that hybrid negotiation was disabled there. ML-DSA certificate signatures remain unimplemented.

What exists today is classical: ECDSA P-256 certs, TLS 1.3, X25519, AES-256-GCM. Certificates and mTLS *authentication* are independent of key establishment; a quantum adversary recording traffic today can break X25519 later. Hybrid key exchange (e.g. `X25519MLKEM768`) protects confidentiality only; certificates stay classical (ECDSA) unless PQ signatures are added separately.

Open items before any PQC claim:

1. Choose the TLS stack: Envoy build whose BoringSSL supports the hybrid group, and/or OpenSSL ≥ 3.5 or OpenSSL 3.x + oqs-provider for test clients. *(From general knowledge; versions not verified offline — check release notes.)*
2. Add the hybrid group to `ecdh_curves` in both Envoy configs and validate with `envoy --mode validate`.
3. Prove it: handshake capture / `s_client -groups <hybrid>` showing the negotiated group; add a test and keep the classical-fallback behaviour explicit.
4. Decide policy: hybrid-only vs. fallback to X25519 (fallback permits downgrade).
5. PQ signatures (ML-DSA) for certificates are a separate, larger dependency; not scoped here.

Interfaces for PQC work: `envoy/*.yaml` → `tls_params.ecdh_curves`; test harness `tests/run-tests.sh` (Part D probe prints actual support).

## Final mTLS Verification — 2026-10-13

The recorded end-to-end tests validate both Envoy configurations, frontend routing, valid client authentication, and rejection of missing, unsuitable, and untrusted-CA client certificates. Detailed results are in `tests/results-20261013-final.md`.

Hybrid post-quantum key exchange and ML-DSA certificate integration through the running Envoy services remain unverified. Do not claim PQC integration is complete without direct handshake and certificate evidence.

## Certificate Loading and Rotation

### Current implementation

- Docker Compose mounts backend and frontend certificate chains, private keys, and CA certificates read-only under `/etc/pqzt/certs/`.
- Envoy loads these files through `tls_certificates` and `validation_context.trusted_ca` in `envoy/backend-envoy.yaml` and `envoy/frontend-envoy.yaml`.
- Backend Envoy requires client certificates and checks the trusted CA and frontend SPIFFE URI SAN.
- File-based TLS secrets are used. SDS and automated certificate rotation are not implemented; replacing a host file alone must not be assumed to reload an active Envoy secret.

### Proposed rotation approach — not implemented or tested

1. Issue replacement certificates and verify validity, SANs, EKUs, and private-key match before deployment.
2. Prefer Envoy Secret Discovery Service (SDS) with a secured, authenticated provider for certificate and validation-context updates. Keep CA private keys outside service containers.
3. Without SDS, install replacement files through a controlled deployment and restart or roll Envoy to reload them.
4. Verify the replacement certificate and trust chain; test valid and untrusted clients and the expected SPIFFE identity.
5. Define expiry monitoring, rollback, and CA rotation procedures before production use.

### Verification status

- **Verified:** Envoy configuration validation passed; a request through frontend Envoy returned HTTP 200 with `{"service":"backend","status":"ok"}`.
- **Verified (live test):** a request using a client certificate issued by `Untrusted Test CA` reached backend Envoy with server hostname verification enabled, then failed with TLS alert `unknown CA`. The test certificate chain also failed local verification against the configured backend CA. Backend Envoy logs produced no additional entries during the check, so the TLS alert is the available rejection evidence.
- **Not implemented/tested:** SDS-based rotation and automatic certificate reload.

## Runtime verification update — 2026-10-16

| Check | Result | Evidence boundary |
|---|---|---|
| Compose configuration | Previously reported PASS | Re-run validation before release. |
| Both Envoy configurations | Previously reported standalone validation PASS | Syntax/schema validation does not prove upstream negotiation. |
| Frontend request through local stack | Previously reported HTTP 200 | Re-run against the current runtime. |
| Trusted client certificate | Previously reported mTLS HTTP 200 | Re-run against the current runtime. |
| Client certificate from unrelated CA | Previously reported rejected with `unknown ca` | Re-run against the current runtime. |
| Direct OpenSSL client to backend | Previously reported TLS 1.3 with `X25519MLKEM768` | Does not prove Envoy-to-Envoy hybrid negotiation. |
| Frontend Envoy to backend Envoy hybrid group | NOT VERIFIED | Capture evidence from that exact upstream connection. |
| ML-DSA certificate signatures | NOT IMPLEMENTED / NOT VERIFIED | Current certificates use ECDSA P-256. |

Do not claim end-to-end hybrid key exchange or ML-DSA certificate support without specific runtime evidence. Re-run the checks against the current repository before treating the historical results above as current results.