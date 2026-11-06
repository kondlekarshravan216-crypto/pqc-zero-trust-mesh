# Daily Integration Update — 6 November 2026

## 1. PQC Hybrid TLS Handshake Verification

- Reviewed the captured Envoy handshake PCAP.
- Verified TLS 1.3 in the captured ServerHello.
- Confirmed hybrid key exchange group: X25519MLKEM768.
- Named group ID: 4588.
- Key exchange length: 1120 bytes.
- Cipher suite: TLS_AES_128_GCM_SHA256.

## 2. Evidence Review

Reviewed the following existing evidence:

- reports/pqc-evidence/pqc-envoy-handshake.pcapng
- reports/pqc-evidence/hybrid-keyshare.txt
- reports/pqc-evidence/validation-report.md

The validation report accurately limits its conclusions to the captured test connection.

## 3. Vault Recovery Investigation

- Restarted the existing Vault server using its original configuration.
- Confirmed Vault was initialized but sealed.
- Seal type: Shamir.
- Total key shares: 1.
- Unseal threshold: 1.
- Existing unseal key could not be located.
- Auto-unseal configuration was not present.

## 4. Vault Data Backup

Created a backup outside the Git repository:

~/vault-backups/vault-data-backup-20261106.tar.gz

- Backup archive size: approximately 29 KB.
- Archive contents listing verified.
- Original Vault data was preserved.
- No reinitialization or deletion was performed.

## 5. Pending Work

- Investigate further recovery options for the original Vault.
- If recovery is not possible, configure a separate fresh Vault storage.
- Issue fresh workload certificates.
- Revalidate Envoy mTLS and hybrid key exchange.
- Complete final integration documentation.

## 6. Current Status

PQC hybrid key exchange evidence is verified for the captured TLS 1.3 handshake.

Original Vault remains initialized but sealed. Its recovery is pending.
