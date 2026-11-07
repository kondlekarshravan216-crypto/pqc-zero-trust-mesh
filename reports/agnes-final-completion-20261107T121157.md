# Agnes – Corrected Final Verification
- Date: 2026-11-07T12:11:57+00:00

## Backend peer certificate: live TLS capture on host port 18443
subject=O=PQZT Demo, CN=backend
issuer=O=PQZT Demo, CN=PQZT Local Test Root CA
X509v3 Subject Alternative Name:
    URI:spiffe://pqzt.local/ns/demo/sa/backend, DNS:backend, DNS:backend.demo.svc.cluster.local
PASS: Live backend certificate chain verified and exact backend SPIFFE identity confirmed.

## Frontend-to-backend application request
HTTP_STATUS=200
{"service":"backend","status":"ok"}

## Final status
Backend SPIFFE identity: PASS
Frontend-to-backend route: PASS
Vault PKI issuance and rotation: PENDING Manideep's handover.
Agnes CA / SPIFFE / Envoy / mTLS verification: COMPLETED.
