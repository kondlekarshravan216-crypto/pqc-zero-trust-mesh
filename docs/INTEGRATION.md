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
**Environment facts vary by test environment.** Earlier offline tests used OpenSSL 3.0.13 and did not support `X25519MLKEM768`; live frontend upstream Envoy statistics confirm `cluster.backend_mtls.ssl.curves.X25519MLKEM768: 3`, `cluster.backend_mtls.ssl.versions.TLSv1.3: 3`, and `cluster.backend_mtls.ssl.handshake: 3`, with zero connection and certificate-verification errors. **PQC status: HYBRID KEY-EXCHANGE NEGOTIATION VERIFIED for the tested frontend-Envoy-to-backend-Envoy connection.** Classical fallback was verified in an isolated Envoy-to-Envoy test: the temporary backend was restricted to X25519, the frontend request returned HTTP 200, and frontend statistics reported `cluster.backend_mtls.ssl.curves.X25519: 1` and `cluster.backend_mtls.ssl.handshake: 1`. This verifies fallback for the isolated test configuration; it does not establish that the original live stack was changed or that hybrid negotiation was disabled there. ML-DSA certificate signatures remain unimplemented.
What exists today is classical: ECDSA P-256 certs, TLS 1.3, X25519, AES-256-GCM. Certificates and mTLS *authentication* are
independent of key establishment; a quantum adversary recording traffic today can break X25519 later. Hybrid key exchange
(e.g. X25519MLKEM768) protects confidentiality only; certificates stay classical (ECDSA) unless PQ signatures are added separately.
Open items before any PQC claim:
1. Choose the TLS stack: Envoy build whose BoringSSL supports the hybrid group, and/or OpenSSL ≥ 3.5 or OpenSSL 3.x + oqs-provider for test clients. *(From general knowledge; versions not verified offline — check release notes.)*
2. Add the hybrid group to `ecdh_curves` in both Envoy configs and validate with `envoy --mode validate`.
3. Prove it: handshake capture / `s_client -groups <hybrid>` showing the negotiated group; add a test and keep the classical-fallback behaviour explicit.
4. Decide policy: hybrid-only vs. fallback to X25519 (fallback permits downgrade).
5. PQ signatures (ML-DSA) for certificates are a separate, larger dependency; not scoped here.
Interfaces for PQC work: `envoy/*.yaml` → `tls_params.ecdh_curves`; test harness `tests/run-tests.sh` (Part D probe prints actual support).

## Final mTLS Verification — 2026-10-13

The recorded end-to-end tests validate both Envoy configurations,
frontend routing, valid client authentication, and rejection of missing,
unsuitable, and untrusted-CA client certificates. Detailed results are
in `tests/results-20261013-final.md`.

Hybrid post-quantum key exchange and ML-DSA certificate integration
through the running Envoy services remain unverified. Do not claim PQC
integration is complete without direct handshake and certificate evidence.
