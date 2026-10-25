# Launch PQC Zero-Trust Mesh Observability Dashboard
# Member 5: Manideep (OPA, Vault & Dashboard)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   PQC Zero-Trust Mesh - Launching Dashboard Server       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check Python availability
try {
    $pythonVersion = python --version
    Write-Host "[+] Runtime: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "[-] Python runtime not found in PATH."
    exit 1
}

$dashboardDir = $PSScriptRoot
$serverScript = Join-Path $dashboardDir "server.py"

Write-Host "[+] Starting Dashboard Server at http://127.0.0.1:8050" -ForegroundColor Yellow
python $serverScript 8050
