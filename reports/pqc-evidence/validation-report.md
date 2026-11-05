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
