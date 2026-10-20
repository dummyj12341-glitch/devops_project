<#
  Installs every tool the DevSecOps pipeline needs (idempotent - safe to re-run).

    .venv-tools\   Python venv with Bandit + pip-audit
    tools\         Gitleaks and Trivy Windows binaries + Trivy DB cache

  usage: powershell -ExecutionPolicy Bypass -File scripts\setup_tools.ps1
#>
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # makes Invoke-WebRequest much faster
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root  = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root "tools"
New-Item -ItemType Directory -Force $Tools | Out-Null

$GitleaksVersion = "8.30.1"
$TrivyVersion    = "0.76.0"
$BanditVersion   = "1.9.4"
$PipAuditVersion = "2.10.1"

# Use the Windows "py" launcher so a native CPython is picked (not MSYS/Cygwin builds).
# Override with $env:PY_CMD, e.g. "py -3.12".
$PyCmd = if ($env:PY_CMD) { $env:PY_CMD } else { "py -3" }

function Get-ZipTool($Name, $Url, $Exe) {
    $target = Join-Path $Tools $Exe
    if (Test-Path $target) { Write-Host "[ok] $Name already installed"; return }
    Write-Host "[..] Downloading $Name from $Url"
    $zip = Join-Path $Tools "$Name.zip"
    Invoke-WebRequest -Uri $Url -OutFile $zip -UseBasicParsing
    $tmp = Join-Path $Tools "$Name-extract"
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    Copy-Item (Get-ChildItem $tmp -Recurse -Filter $Exe | Select-Object -First 1).FullName $target
    Remove-Item $zip, $tmp -Recurse -Force
    Write-Host "[ok] $Name installed -> $target"
}

# --- Python scanner venv ---
$venv = Join-Path $Root ".venv-tools"
if (-not (Test-Path "$venv\Scripts\python.exe")) {
    Write-Host "[..] Creating scanner venv $venv"
    Invoke-Expression "$PyCmd -m venv `"$venv`""
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
}
& "$venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check `
    "bandit==$BanditVersion" "pip-audit==$PipAuditVersion"
if ($LASTEXITCODE -ne 0) { throw "pip install of scanners failed" }
Write-Host "[ok] Bandit $BanditVersion and pip-audit $PipAuditVersion ready"

# --- Binary scanners ---
Get-ZipTool "gitleaks" "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion/gitleaks_${GitleaksVersion}_windows_x64.zip" "gitleaks.exe"
Get-ZipTool "trivy" "https://github.com/aquasecurity/trivy/releases/download/v$TrivyVersion/trivy_${TrivyVersion}_windows-64bit.zip" "trivy.exe"

& "$Tools\gitleaks.exe" version
& "$Tools\trivy.exe" --version | Select-Object -First 1
Write-Host "All DevSecOps tools are installed."
