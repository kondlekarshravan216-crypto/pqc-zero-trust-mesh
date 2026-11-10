# PQC Zero-Trust Mesh – Integration Validation

**Date:** 5 November 2026

## 1. Envoy Service Connectivity
- Frontend-to-backend request completed successfully.
- HTTP response: `200 OK`
- Backend response: `{"service":"backend","status":"ok"}`

## 2. Mutual TLS Validation
- TLS version observed in Envoy logs: TLS 1.3
- Backend Envoy recorded the authenticated frontend identity:
  `spiffe://pqzt.local/ns/demo/sa/frontend`
- Backend Envoy requires a client certificate.

## 3. Hybrid Key Exchange Evidence
Packet capture: `pqc-envoy-handshake.pcapng`

TShark analysis of the ServerHello showed:
- Key exchange group: `X25519MLKEM768`
- Named group ID: `4588`
- Key Exchange length: `1120` bytes
- TLS version: TLS 1.3 (`0x0304`)

See `hybrid-keyshare.txt` for the concise packet-analysis result.

## 4. Result
The tested Envoy connection returned HTTP 200, used TLS 1.3 with the expected frontend SPIFFE identity, and the captured ServerHello contained the `X25519MLKEM768` hybrid key-share group.

These results apply to the captured test connection and do not establish that every connection or deployment environment uses the same negotiated group.

---

## 5. Vault v4 Integration Validation

**Date:** 7 November 2026

### 5.1 Vault v4 PKI
- Fresh Vault v4 instance used with separate storage.
- New Root CA: PQC Zero Trust Mesh Root CA v4.
- Frontend and backend workload certificates issued through Vault PKI.
- Both certificates verified successfully against the Vault v4 Root CA.
- Workload certificates contain their expected SPIFFE URI SANs.

### 5.2 Envoy Connectivity
- Frontend-to-backend HTTP request completed successfully.
- HTTP response: 200 OK.
- Backend response: {"service":"backend","status":"ok"}

### 5.3 Mutual TLS
- TLS version: TLS 1.3.
- Backend Envoy authenticated the frontend SPIFFE identity:
  spiffe://pqzt.local/ns/demo/sa/frontend
- OpenSSL client certificate verification: OK.

### 5.4 Fresh Hybrid PQC Handshake
- Packet capture: vault-v4-hybrid-handshake.pcap
- Negotiated TLS version: TLS 1.3 (0x0304).
- Hybrid key exchange: X25519MLKEM768.
- Named group ID: 4588.
- Key Exchange length: 1120 bytes.
- Cipher suite: TLS_AES_256_GCM_SHA384.
- OpenSSL independently reported X25519MLKEM768 as the negotiated TLS 1.3 group.

### 5.5 Evidence Integrity
- PCAP SHA256:
  bba742263752fab845f24ce9386950e84c57b62bab54a50783bac964912c050b
- TShark successfully decoded the ServerHello key-share group and supported TLS version.

### 5.6 Result
The tested Vault v4 deployment successfully completed frontend-to-backend communication using TLS 1.3 mutual authentication. The backend recorded the expected frontend SPIFFE identity. A fresh captured ServerHello confirmed negotiation of the X25519MLKEM768 hybrid key-share group.

These results apply to the tested connection and captured environment. They do not establish that every connection or deployment environment negotiates the same hybrid group.
