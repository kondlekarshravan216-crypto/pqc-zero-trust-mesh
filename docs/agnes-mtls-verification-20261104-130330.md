# Agnes — CA, Certificates, Envoy & mTLS Verification
Date: 2026-11-04T13:03:30+00:00
Branch: feature/agnes-pqc-status-pr

## 1. Locate Compose configuration
BLOCKED: No Compose file found.


## Final Envoy-to-Envoy hybrid verification — 2026-11-04

- Result: PASS.
- Packet capture of actual frontend Envoy to backend Envoy upstream traffic showed backend ServerHello from 172.26.0.3 to frontend 172.26.0.4.
- ServerHello supported_versions: TLS 1.3 (0x0304).
- ServerHello key_share: X25519MLKEM768 (group 4588).
- This confirms the hybrid group was negotiated between the two Envoy services.
