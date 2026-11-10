# Agnes - Vault v4 CA, SPIFFE and mTLS Final Evidence
UTC: 20261107T120121Z
Project: /mnt/d/pki-mtls-full-project/team-main

## 1. Official team PKI verification
PASS  CA basicConstraints CA:TRUE, pathlen:0
PASS  CA keyUsage keyCertSign
PASS  CA self-consistent and currently valid
PASS  CA certificate matches CA key
PASS  CA key is owner-only (600)
PASS  frontend: chain verifies to CA
PASS  frontend: not expired
PASS  frontend: notBefore reached
PASS  frontend: certificate matches private key
PASS  frontend: key owner-only (600)
PASS  frontend: ca.crt copy equals CA
PASS  frontend: CA:FALSE
PASS  frontend: issuer is the mesh CA
PASS  frontend: ECDSA P-256 / ecdsa-with-SHA256
PASS  frontend: keyUsage = digitalSignature only
PASS  frontend: EKU = TLS Web Client Authentication only
PASS  frontend: SAN set equals definition in frontend.ext
PASS  frontend: valid for purpose sslclient
PASS  backend: chain verifies to CA
PASS  backend: not expired
PASS  backend: notBefore reached
PASS  backend: certificate matches private key
PASS  backend: key owner-only (600)
PASS  backend: ca.crt copy equals CA
PASS  backend: CA:FALSE
PASS  backend: issuer is the mesh CA
PASS  backend: ECDSA P-256 / ecdsa-with-SHA256
PASS  backend: keyUsage = digitalSignature only
PASS  backend: EKU = TLS Web Server Authentication only
PASS  backend: SAN set equals definition in backend.ext
PASS  backend: valid for purpose sslserver
PASS: Frontend and backend team PKI verification

## 2. Envoy configuration validation
 Container team-main-backend-envoy-run-a86fc70c310a Creating 
 Container team-main-backend-envoy-run-a86fc70c310a Created 
[2026-11-07 12:01:25.651][1][info][main] [source/server/server.cc:968] runtime: {}
[2026-11-07 12:01:25.656][1][info][config] [source/server/configuration_impl.cc:181] loading tracing configuration
[2026-11-07 12:01:25.656][1][info][config] [source/server/configuration_impl.cc:132] loading 0 static secret(s)
[2026-11-07 12:01:25.656][1][info][config] [source/server/configuration_impl.cc:138] loading 1 cluster(s)
[2026-11-07 12:01:25.660][1][info][config] [source/server/configuration_impl.cc:148] loading 1 listener(s)
[2026-11-07 12:01:25.672][1][info][config] [source/server/configuration_impl.cc:164] loading stats configuration
configuration '/etc/envoy/envoy.yaml' OK
PASS: backend-envoy configuration validation
 Container team-main-frontend-envoy-run-002ace876426 Creating 
 Container team-main-frontend-envoy-run-002ace876426 Created 
[2026-11-07 12:01:31.420][1][info][main] [source/server/server.cc:968] runtime: {}
[2026-11-07 12:01:31.421][1][info][config] [source/server/configuration_impl.cc:181] loading tracing configuration
[2026-11-07 12:01:31.421][1][info][config] [source/server/configuration_impl.cc:132] loading 0 static secret(s)
[2026-11-07 12:01:31.421][1][info][config] [source/server/configuration_impl.cc:138] loading 1 cluster(s)
[2026-11-07 12:01:31.425][1][info][config] [source/server/configuration_impl.cc:148] loading 1 listener(s)
[2026-11-07 12:01:31.438][1][info][config] [source/server/configuration_impl.cc:164] loading stats configuration
configuration '/etc/envoy/envoy.yaml' OK
PASS: frontend-envoy configuration validation
