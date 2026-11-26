# Repository Technical Audit

**Repository:** `kondlekarshravan216-crypto/pqc-zero-trust-mesh`  
**Audit date:** 26 November 2026  
**Scope:** Public repository tree, README, selected architecture/integration files, dashboard server, Compose file, PQC prototype, OPA/Vault reports, screenshot evidence and ignore rules.

## Executive assessment

The repository is a substantial academic prototype with useful component implementations and dated test artefacts. It should be presented as a **research prototype with independently verifiable components**, not as a fully integrated production-ready post-quantum Kubernetes service mesh.

The most important submission-quality improvement is evidence discipline: distinguish code present, component tests passed historically, specific live handshakes captured, current dashboard state, and planned/incomplete integrations.

## Findings

### High priority

1. **README overclaimed integration and mixed test totals.** The previous README described the mesh as implemented and integrated, while `docs/INTEGRATION.md` explicitly retained limitations around Envoy hybrid negotiation and ML-DSA signatures. The previous headline total (57/57) also differed from the dated OPA/Vault/Dashboard report (61/61). Updated README removes the unsupported aggregate headline and points to each dated report with its date and scope.
2. **Vault live mode must not be implied by historical tests.** The 26 Nov dashboard response reported `STANDALONE_CRYPTOGRAPHIC_EMULATION` and `live_vault_healthy=false`. This is now prominent in README and the submission report.
3. **ML-DSA is not implemented in the current mTLS certificate chain.** The integration notes say workload certs use ECDSA P-256 and ML-DSA certificate signatures remain unimplemented. README now states this explicitly.
4. **Hybrid PQC evidence is path- and date-specific.** The repository contains a Python X25519 + ML-KEM-768 prototype with a five-test recorded result and dated packet-capture evidence for `X25519MLKEM768`. These do not establish that all live service connections use hybrid negotiation. README restricts the claim to the prototype and specific captured handshakes.
5. **OPA dashboard evaluator has a Python fallback.** `dashboard/server.py` first attempts `opa eval`, then returns `evaluator: rego_embedded_engine` if CLI evaluation is unavailable. A healthy dashboard or installed OPA executable alone does not prove Envoy's live `ext_authz` call path. README explains the evaluator field.

### Medium priority

6. **README quick-start was not Linux-friendly.** The previous README pointed to a PowerShell launcher. It now documents `bash dashboard/run_dashboard.sh`, loopback URL and read-only status/event endpoints.
7. **Full stack has local prerequisites.** The Compose file expects `CERT_DIR` and certificate files for Envoy mounts. README now separates dashboard quick-start from full-stack prerequisites and warns that a clean clone needs certificate setup first.
8. **Screenshots were buried in docs.** Five verified screenshot paths are now embedded inline in README with relative image links. The source images remain in `docs/screenshots/`.
9. **Historical evidence is mixed across dates and test harnesses.** README labels results by report/date and avoids treating stored telemetry or historical suite outputs as current runtime status.

## Verified facts from inspected files

- `pqc/hybrid_kem.py` uses X25519, `pqcrypto.kem.ml_kem_768`, transcript binding and HKDF-SHA-256.
- `hybrid-kem-test-results.txt` records five passing tests.
- `reports/pqc-evidence/validation-report.md` records specific TLS 1.3 captures with `X25519MLKEM768` and limits the scope to the tested connection.
- `pki/ext/frontend.ext` and `pki/ext/backend.ext` specify ECDSA-era X.509 usage profiles and SPIFFE URI SANs; integration notes state ECDSA P-256 signatures.
- `docker-compose.yml` defines backend app, OPA and Envoy services and requires certificate mounts from `CERT_DIR`.
- `dashboard/server.py` includes an OPA CLI attempt and a Python policy-equivalent fallback.
- The 26 Nov dashboard status response provided by the project operator reports 150 stored telemetry events (97 genuine-tagged, 53 simulated-tagged), Vault emulation mode, and false live Vault health.

## Remaining engineering work (recommended order)

1. Add a reproducible CI workflow that runs Rego unit tests, shell contract tests, Python unit tests, Python PQC tests and static YAML validation on every push.
2. Add a single top-level validation script with explicit prerequisites and separate exit statuses for unit, integration and live-service tests.
3. Add a machine-readable evidence index containing test name, date, environment, command, result and whether the result is live, simulated or a stand-in.
4. Add a dashboard API test that asserts the evaluator backend (`opa_cli_v1` vs `rego_embedded_engine`) rather than treating any fallback decision as a live OPA result.
5. Add a live Envoy-to-OPA gRPC `ext_authz` smoke test and capture the actual policy decision on the live request path.
6. Add an authenticated peer handshake that verifies the hybrid Python key-establishment prototype is bound to the expected peer identity; the prototype alone should not be treated as an authenticated protocol.
7. Implement or explicitly remove ML-DSA certificate claims until a CA/certificate chain and verifier support it.
8. Re-run Vault API tests against an actual disposable Vault dev server in a documented environment; preserve emulation tests as a distinct suite.
9. Re-run Kubernetes NetworkPolicy tests from manifests against a disposable cluster and publish the cluster version, manifests, commands and exact allow/deny observations.
10. Add production-readiness controls only if production deployment is in scope: TLS for Vault, non-dev storage/seal strategy, protected CA keys, least-privilege service auth, secret rotation, telemetry integrity and threat model.

## Changes made during this audit

- Replaced the landing-page README with an evidence-labelled project overview.
- Embedded all five existing screenshots directly in README so they render on the repository front page.
- Added direct report and architecture links.
- Added this audit report.

## Audit limitations

This review inspected the public GitHub repository files listed above. It did not execute code, start Docker/Vault/Kubernetes, regenerate certificates, or re-run test suites. Runtime dashboard values are reported from the user's 26 Nov local API output. The source screenshot pixels were not visually re-inspected in this review; their repository paths and file presence were verified.
