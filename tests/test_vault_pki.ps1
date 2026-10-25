# PowerShell Wrapper for Vault PKI Setup and Rotation Test Suite
# Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
# Member 5: Manideep (OPA, Vault & Dashboard)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   PQC Zero-Trust Mesh - Vault PKI & Rotation Suite       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check Python availability
try {
    $pythonVersion = python --version
    Write-Host "[+] Python runtime: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "[-] Python is not installed or accessible in PATH."
    exit 1
}

$scriptPath = Join-Path $PSScriptRoot "test_vault_pki.py"
python $scriptPath

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] Vault PKI test suite PASSED (100%)." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[-] Vault PKI test suite FAILED with exit code $LASTEXITCODE." -ForegroundColor Red
    exit $LASTEXITCODE
}
