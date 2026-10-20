<#
  Runs the same stages as the Jenkinsfile without Jenkins (demo fallback / quick check).

  usage: powershell -ExecutionPolicy Bypass -File scripts\run_pipeline_local.ps1 -Target app
         powershell -ExecutionPolicy Bypass -File scripts\run_pipeline_local.ps1 -Target app_secure
#>
param(
    [ValidateSet("app", "app_secure")] [string]$Target = "app",
    [switch]$SkipSetup
)
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:TARGET_APP = $Target
$env:PYTHONDONTWRITEBYTECODE = "1"   # keep .pyc files out of the scanned source tree
$PyCmd = if ($env:PY_CMD) { $env:PY_CMD } else { "py -3" }

$Tools    = Join-Path $Root "tools"
$ToolsPy  = Join-Path $Root ".venv-tools\Scripts"
$AppVenv  = Join-Path $Root ".venv-$Target"
$Reports  = Join-Path $Root "reports"

function Stage($Name) { Write-Host "`n==================== $Name ====================" -ForegroundColor Cyan }

Stage "Setup"
if (-not $SkipSetup) { powershell -ExecutionPolicy Bypass -File scripts\setup_tools.ps1 }
if (-not (Test-Path "$AppVenv\Scripts\python.exe")) { Invoke-Expression "$PyCmd -m venv `"$AppVenv`"" }
& "$AppVenv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r "$Target\requirements.txt" pytest
Remove-Item $Reports -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Reports | Out-Null

Stage "Unit Tests"
& "$AppVenv\Scripts\python.exe" -m pytest tests -q -p no:cacheprovider --junitxml=reports\junit.xml
if ($LASTEXITCODE -ne 0) { Write-Host "Unit tests failed" -ForegroundColor Red; exit 1 }

Stage "Secret Scan (Gitleaks)"
& "$Tools\gitleaks.exe" dir $Target --config security\.gitleaks.toml --report-format json --report-path reports\gitleaks.json --no-banner --exit-code 0

Stage "SAST (Bandit)"
& "$ToolsPy\bandit.exe" -r $Target -f json -o reports\bandit.json -q
& "$ToolsPy\bandit.exe" -r $Target -f txt -q --exit-zero | Select-Object -Last 12

Stage "SCA (pip-audit)"
& "$ToolsPy\pip-audit.exe" -r "$Target\requirements.txt" --no-deps --disable-pip -f json -o reports\pip-audit.json --progress-spinner off

Stage "SCA / IaC / Secrets (Trivy)"
& "$Tools\trivy.exe" fs --scanners vuln,secret,misconfig --cache-dir "$Tools\trivy-cache" --format json --output reports\trivy.json --skip-dirs "**/__pycache__" --exit-code 0 --quiet $Target
Write-Host "Trivy report written to reports\trivy.json"

Stage "DAST (dynamic probe)"
& "$ToolsPy\python.exe" security\dast_probe.py --app-dir $Target --python "$AppVenv\Scripts\python.exe" --out reports\dast.json

Stage "Security Report"
& "$ToolsPy\python.exe" security\generate_report.py --reports reports

Stage "Quality Gate"
& "$ToolsPy\python.exe" security\quality_gate.py --reports reports
$gate = $LASTEXITCODE
Write-Host "`nHTML report: $Reports\security-report.html"
exit $gate
