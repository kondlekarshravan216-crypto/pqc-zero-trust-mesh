# Final mTLS Verification — 2026-10-13

- Backend Envoy configuration validation: PASS
- Frontend Envoy configuration validation: PASS
- Frontend route: PASS
- Valid client certificate: PASS
- Missing client certificate: REJECTED
- Unsuitable client certificate: REJECTED
- Client certificate signed by temporary untrusted CA: REJECTED

TLS 1.3 was observed in earlier test evidence. Recheck the negotiated
version when collecting new handshake evidence.

Hybrid post-quantum key exchange and ML-DSA certificate integration
through the running Envoy services remain UNVERIFIED.
Successful configuration validation does not establish PQC support.
