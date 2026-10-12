# Automated Test Script for OPA Authorization Policies
# Post-Quantum Zero-Trust Microsegmentation Mesh (pqc-zero-trust-mesh)
# Day 2 Verification Suite

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   PQC Zero-Trust Mesh - Automated OPA Test Suite         " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Verify OPA command availability
try {
    $opaVersion = opa version
    Write-Host "[+] OPA binary found:" -ForegroundColor Green
    $opaVersion | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
} catch {
    Write-Error "[-] OPA executable is not found in PATH. Please install OPA or ensure it is accessible."
    exit 1
}

$totalTests = 0
$passedTests = 0
$failedTests = 0

function Run-OpaEvalTest {
    param (
        [string]$TestName,
        [string]$PolicyPath,
        [string]$InputPath,
        [string]$Query,
        [bool]$ExpectedValue
    )

    $script:totalTests++
    Write-Host "`n[TEST $script:totalTests] $TestName" -ForegroundColor Yellow
    Write-Host "  Policy: $PolicyPath" -ForegroundColor Gray
    Write-Host "  Input:  $InputPath" -ForegroundColor Gray
    Write-Host "  Query:  $Query (Expected: $ExpectedValue)" -ForegroundColor Gray

    try {
        $rawOutput = opa eval --data $PolicyPath --input $InputPath $Query 2>&1
        $json = $rawOutput | Out-String | ConvertFrom-Json
        $actualValue = $json.result[0].expressions[0].value

        if ($actualValue -eq $ExpectedValue) {
            Write-Host "  RESULT: PASS (Output: $actualValue)" -ForegroundColor Green
            $script:passedTests++
        } else {
            Write-Host "  RESULT: FAIL (Expected $ExpectedValue, got $actualValue)" -ForegroundColor Red
            $script:failedTests++
        }
    } catch {
        Write-Host "  RESULT: ERROR ($($_.Exception.Message))" -ForegroundColor Red
        $script:failedTests++
    }
}

Write-Host "`n--- Part 1: Policy Unit Tests (opa test) ---" -ForegroundColor Cyan
try {
    $unitTestOutput = opa test opa/policies/ -v 2>&1
    Write-Host ($unitTestOutput | Out-String)
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] All policy unit tests passed successfully." -ForegroundColor Green
    } else {
        Write-Host "[-] Policy unit tests failed." -ForegroundColor Red
        $failedTests++
    }
} catch {
    Write-Host "[-] Error executing opa test: $($_.Exception.Message)" -ForegroundColor Red
    $failedTests++
}

Write-Host "`n--- Part 2: Integration Contract Tests (tests/opa/*.json) ---" -ForegroundColor Cyan

# Test 1: Frontend to Backend (Allow)
Run-OpaEvalTest `
    -TestName "Contract Test 1: Frontend -> Backend [ALLOW]" `
    -PolicyPath "opa/policies/authorization.rego" `
    -InputPath "tests/opa/allow-frontend-backend.json" `
    -Query "data.mesh.authz.allow" `
    -ExpectedValue $true

# Test 2: Backend to Database (Allow)
Run-OpaEvalTest `
    -TestName "Contract Test 2: Backend -> Database [ALLOW]" `
    -PolicyPath "opa/policies/authorization.rego" `
    -InputPath "tests/opa/allow-backend-database.json" `
    -Query "data.mesh.authz.allow" `
    -ExpectedValue $true

# Test 3: Frontend to Database (Deny - lateral movement prevented)
Run-OpaEvalTest `
    -TestName "Contract Test 3: Frontend -> Database [DENY]" `
    -PolicyPath "opa/policies/authorization.rego" `
    -InputPath "tests/opa/deny-frontend-database.json" `
    -Query "data.mesh.authz.allow" `
    -ExpectedValue $false

# Test 4: Unknown to Backend (Deny - unapproved source)
Run-OpaEvalTest `
    -TestName "Contract Test 4: Unknown -> Backend [DENY]" `
    -PolicyPath "opa/policies/authorization.rego" `
    -InputPath "tests/opa/deny-unknown-backend.json" `
    -Query "data.mesh.authz.allow" `
    -ExpectedValue $false

Write-Host "`n--- Part 3: Identity Tests (opa/inputs/*.json) ---" -ForegroundColor Cyan

Run-OpaEvalTest `
    -TestName "Identity Test 1: Simple Verified Identity [ALLOW]" `
    -PolicyPath "opa/policies/authz.rego" `
    -InputPath "opa/inputs/allowed.json" `
    -Query "data.authz.allow" `
    -ExpectedValue $true

Run-OpaEvalTest `
    -TestName "Identity Test 2: Simple Unapproved Identity [DENY]" `
    -PolicyPath "opa/policies/authz.rego" `
    -InputPath "opa/inputs/denied.json" `
    -Query "data.authz.allow" `
    -ExpectedValue $false

Write-Host "`n--- Part 4: SPIFFE SVID Request Envelope Tests (opa/tests/*.json) ---" -ForegroundColor Cyan

Run-OpaEvalTest `
    -TestName "SPIFFE SVID Test 1: Full SVID URI Allowed [ALLOW]" `
    -PolicyPath "opa/policies/authz.rego" `
    -InputPath "opa/tests/input_allowed.json" `
    -Query "data.authz.allow" `
    -ExpectedValue $true

Run-OpaEvalTest `
    -TestName "SPIFFE SVID Test 2: Rogue SVID URI Denied [DENY]" `
    -PolicyPath "opa/policies/authz.rego" `
    -InputPath "opa/tests/input_denied.json" `
    -Query "data.authz.allow" `
    -ExpectedValue $false

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "                   SUMMARY OF RESULTS                     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Total Evaluation Tests: $totalTests"
Write-Host "Passed:                 $passedTests" -ForegroundColor Green
Write-Host "Failed:                 $failedTests" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })

if ($failedTests -gt 0) {
    Write-Host "`n[-] Test suite FAILED with $failedTests failures." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n[+] All tests PASSED successfully!" -ForegroundColor Green
    exit 0
}
