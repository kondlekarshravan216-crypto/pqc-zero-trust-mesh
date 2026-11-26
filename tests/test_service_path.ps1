# PowerShell Runner for Service Request Path Authorization & Secret Management Test Suite
# Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
# Member 5: Manideep

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PQC Zero-Trust Mesh - Service Request Path & Vault Suite " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Verify Python availability
try {
    $pythonVersion = python --version
    Write-Host "[+] Python environment found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "[-] Python 3 is not found in PATH. Please install Python 3 or ensure it is accessible."
    exit 1
}

# Verify OPA availability
try {
    $opaVersion = opa version
    Write-Host "[+] OPA executable found:" -ForegroundColor Green
    $opaVersion | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
} catch {
    Write-Error "[-] OPA executable is not found in PATH. Please install OPA or ensure it is accessible."
    exit 1
}

Write-Host "`n[+] Executing Python End-to-End Service Path & Vault Test Suite..." -ForegroundColor Yellow
python tests/test_service_path.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[-] Test suite FAILED with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
} else {
    Write-Host "`n[+] End-to-End Service Path & Vault Suite PASSED successfully!" -ForegroundColor Green
    exit 0
}
