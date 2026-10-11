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
**Environment facts (probed, not assumed):** OpenSSL 3.0.13, default provider only; no ML-KEM/Kyber KEM listed; no
`X25519MLKEM768` group usable. Envoy pinned in compose: `v1.31.0` (not run). **PQC status: NOT INTEGRATED.**
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
