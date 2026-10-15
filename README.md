# Post-Quantum Zero-Trust Microsegmentation Mesh (`pqc-zero-trust-mesh`)

Enterprise-oriented prototype implementing a Post-Quantum Zero-Trust Kubernetes microsegmentation mesh with hybrid ECDH + ML-KEM, mTLS, OPA policy enforcement, secret management, and security observability.

---

## Architecture & System Components

1. **OPA Policy Enforcement**: [`opa/README.md`](opa/README.md) - Decentralized authorization policies (`authorization.rego`, `authz.rego`), unit tests, test inputs, and security dashboard telemetry events.
2. **Vault Secret Management & Rotation**: [`vault/README.md`](vault/README.md) - HashiCorp Vault server dev configuration, least-privilege mesh secrets access policy (`mesh-secrets.hcl`), and security architecture review. Detailed rotation blueprint in [`docs/integration_and_rotation_plan.md`](docs/integration_and_rotation_plan.md).
3. **Automated Test Suite**: [`tests/test_opa.ps1`](tests/test_opa.ps1) & [`tests/test_opa.sh`](tests/test_opa.sh) - End-to-end automated test scripts verifying OPA unit tests and contract evaluations.
4. **CA, Service Identity, Envoy & mTLS Module**: [`pki/`](pki/), [`envoy/`](envoy/), [`scripts/`](scripts/) - Local test CA, SPIFFE service identities, Envoy sidecar configurations, and mTLS verification suite.

---

## CA, Service Identity, Envoy & mTLS Module Details

Part of the *Post-Quantum Zero-Trust Microsegmentation Mesh*. Owner role: CA / Service Identity / Envoy / mTLS.

> **Read first — status and limits**
> * No `CLAUDE.md`, project spec or architecture document was available when this was built. Requirements come from the
>   task brief only; service names, ports, trust domain and namespace below are **assumptions** to reconcile with the official spec.
> * **Classical mTLS only.** ECDSA P-256 certificates + TLS 1.3 with X25519 key exchange. **This is not post-quantum secure.**
>   No PQC/hybrid key establishment was implemented or tested. See `docs/INTEGRATION.md`.
> * Envoy and Docker were **not available** in the authoring environment, so `envoy/*.yaml` and `docker-compose.yml` are
>   written but **unexecuted and unvalidated** (YAML syntax checked only). The mTLS behaviour was proven with `openssl s_server`
>   as a stand-in enforcing the same policy (TLS 1.3, client cert required). SAN allow-listing in Envoy is therefore untested.

### Architecture / request flow
```
client -> [frontend-envoy :8080 plain HTTP] ==mTLS (TLS1.3)==> [backend-envoy :8443] -> backend-app :8080 (plain, private net)
            presents frontend cert                              requires client cert from mesh CA
            checks backend chain + SAN spiffe://.../sa/backend  allows only SAN spiffe://.../sa/frontend
```

### Trust model & identities
| Item | Value |
|---|---|
| Root CA | `CN=PQZT Local Test Root CA`, ECDSA P-256, 10 y, `CA:TRUE, pathlen:0`, keyCertSign/cRLSign. **Test CA only** — not for production. |
| frontend | SAN `URI:spiffe://pqzt.local/ns/demo/sa/frontend`, `DNS:frontend`, `DNS:frontend.demo.svc.cluster.local`; EKU **clientAuth** only; 90 d |
| backend | SAN `URI:spiffe://pqzt.local/ns/demo/sa/backend`, `DNS:backend`, `DNS:backend.demo.svc.cluster.local`; EKU **serverAuth** only; 90 d |
Identity = URI SAN (SPIFFE-style). Separate EKUs mean a stolen server cert cannot be used as a client cert (tested).
The CA key (`pki/out/ca/ca.key`) is never mounted into any service. Service dirs contain only their own key + the CA cert.
No revocation (CRL/OCSP) is implemented; rely on short lifetimes.

### Commands
```bash
cd pki-mtls
bash scripts/gen-ca.sh                 # idempotent; refuses to overwrite existing CA
bash scripts/issue-cert.sh frontend    # refuses to overwrite existing creds
bash scripts/issue-cert.sh backend
bash scripts/verify-pki.sh             # chain, validity, key match, EKU, SAN
bash tests/run-tests.sh                # 27 checks, writes tests/results.md; exit code = number of FAILs
# With Docker (UNTESTED here):
export LOCAL_UID=$(id -u) LOCAL_GID=$(id -g)
docker compose config -q && docker compose up -d
curl -s http://127.0.0.1:8080/                       # expect {"service":"backend","status":"ok"}
openssl s_client -connect 127.0.0.1:8443 </dev/null  # no client cert => must be rejected
# Envoy validation (UNTESTED here): docker run --rm -v $PWD/envoy:/c envoyproxy/envoy:v1.31.0 --mode validate -c /c/backend-envoy.yaml
```
Rotate: delete the specific service dir yourself, re-run `issue-cert.sh <name>`, restart Envoy (static files; no SDS).

### Test results (actually executed; details in `tests/results.md`)
27 checks: **24 PASS, 0 FAIL, 2 NOT RUN, 1 INFO**; three consecutive runs identical.
Verified: chain, key/cert match, SAN/EKU, expiry; successful mTLS (HTTP 200); rejections for no client cert (`certificate required`),
rogue-CA client with correct SAN (`unknown ca`), expired client cert, wrong-EKU client cert (`unsupported certificate`),
client not trusting server, hostname mismatch, rogue-CA server cert, expired server cert, TLS 1.2 downgrade (`protocol version` alert).
Negotiated (actual): **TLSv1.3, TLS_AES_256_GCM_SHA384, X25519, ECDSA signature**.
**NOT RUN:** `envoy --mode validate`; Docker Compose/live Envoy end-to-end (tools absent).
**Not testable with the stand-in:** Envoy `match_typed_subject_alt_names` (rejecting a valid-CA cert with a *different* identity).

### Troubleshooting
* `certificate required` / `unknown ca` → client cert missing or not signed by mesh CA. `unsupported certificate` → wrong EKU.
* Envoy `permission denied` on key → set `LOCAL_UID/LOCAL_GID`; keys are 0600.
* `UPSTREAM_TRANSPORT_FAILURE_REASON` in the frontend access log shows upstream TLS failures; backend log shows `peer_uri_san`.
* Envoy does not check hostnames by itself; identity is enforced only by the `match_typed_subject_alt_names` entries.

### Security considerations
Test CA key unprotected on disk; no HSM/passphrase. No revocation. Demo keys are 0600 and git-ignored (`pki/out/`).
Backend app traffic behind Envoy is plaintext on the private network. Admin interfaces bind to 127.0.0.1.

### Delivery and validation note
This package combines the original module archive with the later hardened PKI scripts and test utilities. The official project specification was not included in the supplied archives, so service identities, namespace, trust domain, ports, and deployment topology remain provisional. The saved test reports describe earlier sandbox runs; they are not proof that Envoy or Docker integration has run on your machine. Review the configuration against the official specification before generating certificates or deploying.

