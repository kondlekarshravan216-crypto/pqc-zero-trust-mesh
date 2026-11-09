
# X25519 + ML-KEM-768 Hybrid KEM Verification Report

## 1. Objective
Validate the hybrid key establishment implementation.

## 2. Environment
- Operating System: Kali Linux
- Python Version:
- cryptography Version:
- pqcrypto Version:
- pytest Version:

## 3. Algorithms
- Classical: X25519
- Post-Quantum: ML-KEM-768
- Key Derivation: HKDF-SHA256

## 4. Test Results

| Test | Result |
|---|---|
| X25519 key generation | PASS/FAIL |
| X25519 shared secret | PASS/FAIL |
| ML-KEM-768 key generation | PASS/FAIL |
| ML-KEM encapsulation | PASS/FAIL |
| ML-KEM decapsulation | PASS/FAIL |
| Hybrid secret agreement | PASS/FAIL |
| Invalid ciphertext | PASS/FAIL |
| Tampered input | PASS/FAIL |
| Fresh session behavior | PASS/FAIL |

## 5. Shared Secret Verification
- Alice and Bob derived the same X25519 secret: 
- Alice and Bob derived the same ML-KEM secret:
- Alice and Bob derived the same hybrid session key:

Do not include actual secret values.

## 6. Test Execution
Command:
python -m pytest -v

Number of tests:
Passed:
Failed:

## 7. Security Observations
- Fresh ephemeral X25519 keys are used.
- ML-KEM-768 is used for post-quantum encapsulation.
- Both secrets are combined using the documented construction.
- HKDF derives the final session key.
- Invalid input handling was tested.

## 8. Limitations
Document any untested integration, interoperability,
or production-security requirements.

## 9. Conclusion
Summarize the actual verification results.
