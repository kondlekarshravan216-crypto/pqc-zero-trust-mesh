# Agnes - Live Envoy mTLS Test Results

- Date UTC: 20261106T111125Z
- Passed: 4
- Failed: 0
- Test log directory: /tmp/agnes-mtls-tests.Qx8F5W

## Test output
```text
curl: (56) OpenSSL SSL_read: OpenSSL/3.5.5: error:0A00045C:SSL routines::tlsv13 alert certificate required, errno 0
curl: (56) OpenSSL SSL_read: OpenSSL/3.5.5: error:0A000418:SSL routines::tlsv1 alert unknown ca, errno 0
```

## Interpretation
See terminal output and Docker Envoy logs for handshake evidence.
Vault CA integration remains pending the team's Vault endpoint and authorized PKI access.
