# One-shot check that the artifact catalog landed intact and is ready to commit.
# Safe to re-run. Changes nothing except regenerating the export feeds.
#
#   .\setup.ps1
#
# If PowerShell blocks it:
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Fail($msg) { Write-Host $msg -ForegroundColor Red; exit 1 }

Write-Host "==> Checking layout"
foreach ($d in @("artifacts\catalog", "artifacts\scripts", "artifacts\schema",
                 "skills\agent-artifact-catalog")) {
    if (-not (Test-Path $d)) { Fail "MISSING: $d" }
}
Write-Host "    ok"

Write-Host "==> Locating Python"
$py = $null
foreach ($candidate in @("python", "py", "python3")) {
    try {
        $version = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0) { $py = $candidate; break }
    } catch { }
}
if (-not $py) { Fail "Python not found on PATH. Install Python 3.11+ from python.org and reopen your terminal." }
Write-Host "    using '$py' ($version)"

Write-Host "==> Python dependencies"
& $py -m pip install -q -r artifacts\requirements.txt
if ($LASTEXITCODE -ne 0) { Fail "pip install failed" }
Write-Host "    ok"

Push-Location artifacts

Write-Host "==> Validating catalog and detections"
& $py scripts\validate.py
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "Validation failed. Fix before committing - this is the gate CI runs." }

Write-Host "==> Checking for vocabulary drift"
& $py scripts\normalize.py
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "normalize.py failed" }

Write-Host "==> Regenerating export feeds"
& $py scripts\export.py
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "export.py failed" }
& $py scripts\export_forensicartifacts.py
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "export_forensicartifacts.py failed" }

$entries = (Get-ChildItem catalog\*.yml).Count
$sigma   = (Get-ChildItem detections\sigma\*.yml).Count

Pop-Location

Write-Host ""
Write-Host "==> Ready." -ForegroundColor Green
Write-Host "    Entries:  $entries"
Write-Host "    Sigma:    $sigma"
Write-Host ""
Write-Host "    Next:  see PUBLISH_TODAY.md"
Write-Host "           git checkout -b artifact-catalog"
