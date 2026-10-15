# Test results

Generated: 2026-10-11T12:32:30Z | OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)

| # | Test | Command | Expected | Actual | Status |
|---|------|---------|----------|--------|--------|
| 1 | Chain: frontend -> CA | `openssl verify -CAfile /tmp/verify/pki-mtls/pki/out/ca/ca.crt /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt` | OK | rc=0 /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt: OK | **PASS** |
| 2 | Chain: backend -> CA | `openssl verify -CAfile /tmp/verify/pki-mtls/pki/out/ca/ca.crt /tmp/verify/pki-mtls/pki/out/backend/backend.crt` | OK | rc=0 /tmp/verify/pki-mtls/pki/out/backend/backend.crt: OK | **PASS** |
| 3 | Key matches cert (frontend) | `[ "$(openssl x509 -in /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt -noout -pubkey\|openssl sha256)" = "$(openssl pkey -in /tmp/verify/pki-mtls/pki/out/frontend/frontend.key -pubout\|openssl sha256)" ]` | public keys identical | rc=0  | **PASS** |
| 4 | Not expired (frontend) | `openssl x509 -in /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt -noout -checkend 0` | valid now | rc=0 Certificate will not expire | **PASS** |
| 5 | Key matches cert (backend) | `[ "$(openssl x509 -in /tmp/verify/pki-mtls/pki/out/backend/backend.crt -noout -pubkey\|openssl sha256)" = "$(openssl pkey -in /tmp/verify/pki-mtls/pki/out/backend/backend.key -pubout\|openssl sha256)" ]` | public keys identical | rc=0  | **PASS** |
| 6 | Not expired (backend) | `openssl x509 -in /tmp/verify/pki-mtls/pki/out/backend/backend.crt -noout -checkend 0` | valid now | rc=0 Certificate will not expire | **PASS** |
| 7 | Full PKI verification script | `bash /tmp/verify/pki-mtls/scripts/verify-pki.sh` | all PASS (EKU, SAN, CA flags) | rc=0 PASS  CA basicConstraints CA:TRUE
PASS  frontend chain verifies against CA
PASS  frontend  | **PASS** |
| 8 | Cert/key mismatch detected (frontend cert vs backend key) | `[ "$(openssl x509 -in /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt -noout -pubkey\|openssl sha256)" = "$(openssl pkey -in /tmp/verify/pki-mtls/pki/out/backend/backend.key -pubout\|openssl sha256)" ]` | mismatch detected | rc=1 (rejected)  | **PASS** |
| 9 | Frontend cert does NOT carry backend identity | `openssl x509 -in /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt -noout -ext subjectAltName \| grep -q 'sa/backend'` | no backend SAN in frontend cert | rc=1 (rejected)  | **PASS** |
| 10 | Backend cert not valid for clientAuth purpose | `openssl verify -CAfile /tmp/verify/pki-mtls/pki/out/ca/ca.crt -purpose sslclient /tmp/verify/pki-mtls/pki/out/backend/backend.crt` | rejected (EKU serverAuth only) | rc=2 (rejected) O = PQZT Demo, CN = backend
error 26 at 0 depth lookup: unsuitable certificate purpose
err | **PASS** |
| 11 | Frontend cert valid for clientAuth purpose | `openssl verify -CAfile /tmp/verify/pki-mtls/pki/out/ca/ca.crt -purpose sslclient /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt` | OK | rc=0 /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt: OK | **PASS** |
| 12 | Frontend cert not valid for serverAuth purpose | `openssl verify -CAfile /tmp/verify/pki-mtls/pki/out/ca/ca.crt -purpose sslserver /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt` | rejected (EKU clientAuth only) | rc=2 (rejected) O = PQZT Demo, CN = frontend
error 26 at 0 depth lookup: unsuitable certificate purpose
er | **PASS** |
| 13 | mTLS success: trusted frontend cert -> backend (HTTP 200) | `[ "$(cu --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt --key /tmp/verify/pki-mtls/pki/out/frontend/frontend.key)" = 200 ]` | HTTP 200 | rc=0  | **PASS** |
| 14 | No client certificate | `[ "$(cu --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt)" = 200 ]` | handshake/request rejected, no 200 | rc=1 (rejected) curl: (56) OpenSSL SSL_read: OpenSSL/3.0.13: error:0A00045C:SSL routines::tlsv13 alert cer | **PASS** |
| 15 | Client cert from untrusted (rogue) CA, correct SAN | `[ "$(cu --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/tests/work/rogue-frontend.crt --key /tmp/verify/pki-mtls/tests/work/rogue-frontend.key)" = 200 ]` | rejected, no 200 | rc=1 (rejected) curl: (56) OpenSSL SSL_read: OpenSSL/3.0.13: error:0A000418:SSL routines::tlsv1 alert unkn | **PASS** |
| 16 | Expired client cert (real CA) | `[ "$(cu --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/tests/work/expired-frontend.crt --key /tmp/verify/pki-mtls/tests/work/expired-frontend.key)" = 200 ]` | rejected, no 200 | rc=1 (rejected) curl: (56) OpenSSL SSL_read: OpenSSL/3.0.13: error:0A000415:SSL routines::sslv3 alert cert | **PASS** |
| 17 | Wrong-purpose client cert (backend serverAuth cert as client) | `[ "$(cu --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/pki/out/backend/backend.crt --key /tmp/verify/pki-mtls/pki/out/backend/backend.key)" = 200 ]` | rejected (EKU), no 200 | rc=1 (rejected) curl: (56) OpenSSL SSL_read: OpenSSL/3.0.13: error:0A000413:SSL routines::sslv3 alert unsu | **PASS** |
| 18 | Client does not trust server (empty trust: rogue CA only) | `[ "$(cu --cacert /tmp/verify/pki-mtls/tests/work/rogue-ca.crt --cert /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt --key /tmp/verify/pki-mtls/pki/out/frontend/frontend.key)" = 200 ]` | client aborts: unknown issuer | rc=1 (rejected) curl: (60) SSL certificate problem: self-signed certificate in certificate chain
More deta | **PASS** |
| 19 | Server hostname/SAN mismatch (connect as 'evil') | `curl -sS -m 5 -o /dev/null --resolve evil:18443:127.0.0.1 --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt --key /tmp/verify/pki-mtls/pki/out/frontend/frontend.key https://evil:18443/` | client aborts: name mismatch | rc=60 (rejected) curl: (60) SSL: no alternative certificate subject name matches target host name 'evil'
Mo | **PASS** |
| 20 | Legacy TLS 1.2 client refused (server TLS1.3-only): protocol_version alert | `{ echo \| openssl s_client -connect 127.0.0.1:18443 -tls1_2 -CAfile /tmp/verify/pki-mtls/pki/out/ca/ca.crt -cert /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt -key /tmp/verify/pki-mtls/pki/out/frontend/frontend.key 2>&1 \|\| true; } \| grep -q 'alert protocol version'` | server sends protocol_version alert | rc=0  | **PASS** |
| 21 | Server presents cert from untrusted CA | `curl -sS -m 5 -o /dev/null --resolve backend:18444:127.0.0.1 --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt --key /tmp/verify/pki-mtls/pki/out/frontend/frontend.key https://backend:18444/` | client rejects server | rc=60 (rejected) curl: (60) SSL certificate problem: self-signed certificate in certificate chain
More deta | **PASS** |
| 22 | Server presents expired cert | `curl -sS -m 5 -o /dev/null --resolve backend:18445:127.0.0.1 --cacert /tmp/verify/pki-mtls/pki/out/ca/ca.crt --cert /tmp/verify/pki-mtls/pki/out/frontend/frontend.crt --key /tmp/verify/pki-mtls/pki/out/frontend/frontend.key https://backend:18445/` | client rejects expired server | rc=60 (rejected) curl: (60) SSL certificate problem: certificate has expired
More details here: https://cur | **PASS** |
| 23 | Negotiated parameters (hostname verified) | `openssl s_client ... -verify_hostname backend -tls1_3` | TLS1.3, verify OK | New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384; Server Temp Key: X25519, 253 bits; Peer signature type: ECDSA; Verification: OK | **PASS** |
| 24 | Envoy/Compose YAML syntax + mTLS flag present | `python3 -c "import yaml;[yaml.safe_load(open('/tmp/verify/pki-mtls/'+f)) for f in ['envoy/backend-envoy.yaml','envoy/frontend-envoy.yaml','docker-compose.yml']];c=yaml.safe_load(open('/tmp/verify/pki-mtls/envoy/backend-envoy.yaml'))['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config'];assert c['require_client_certificate'] is True"` | parses; require_client_certificate: true | rc=0  | **PASS** |
| 25 | Envoy config validation (envoy --mode validate) | `envoy --mode validate -c envoy/*.yaml` | configuration OK | envoy binary not installed in this environment | **NOT RUN** |
| 26 | Docker Compose config / live Envoy mTLS | `docker compose up; curl localhost:8080` | 200 via Envoy; unauth rejected | docker not installed in this environment | **NOT RUN** |
| 27 | PQC capability probe (informational) | `openssl list -kem-algorithms; s_client -groups X25519MLKEM768` | report support truthfully | no ML-KEM/Kyber KEM in OpenSSL providers; X25519MLKEM768 not usable | **INFO** |
