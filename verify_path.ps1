# verify_path.ps1
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      System Diagnostic Tool" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check current session
Write-Host "Checking current session..." -NoNewline
if (Get-Command cmd -ErrorAction SilentlyContinue) {
    Write-Host "[OK] 'cmd' is available." -ForegroundColor Green
} else {
    Write-Host "[FAIL] 'cmd' is NOT found in current session." -ForegroundColor Red
}

# 2. Check Registry (System)
Write-Host "`nChecking System Registry..." -NoNewline
$sysPath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path
if ($sysPath -like "*C:\Windows\System32*") {
    Write-Host "[OK] 'System32' is present in System Registry." -ForegroundColor Green
} else {
    Write-Host "[FAIL] 'System32' MISSING from System Registry." -ForegroundColor Red
    Write-Host "    Current System Path: $sysPath" -ForegroundColor Gray
}

# 3. Diagnosis
Write-Host "`nDiagnosis:" -ForegroundColor Cyan
if ((Get-Command cmd -ErrorAction SilentlyContinue)) {
    Write-Host "Everything looks good! If Arduino IDE still fails, RESTART YOUR COMPUTER." -ForegroundColor Green
} elseif ($sysPath -like "*C:\Windows\System32*") {
    Write-Host "The fix is SAVED in the registry, but not active yet." -ForegroundColor Yellow
    Write-Host "YOU MUST RESTART YOUR COMPUTER." -ForegroundColor White -BackgroundColor Red
} else {
    Write-Host "The path is still missing. Please try adding 'C:\Windows\System32' again." -ForegroundColor Red
}

Write-Host "`nPress Enter to close..."
Read-Host
