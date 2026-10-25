<#
  One-time SonarQube setup through its REST API (idempotent):
    * replaces the default admin/admin password
    * creates an analysis token for Jenkins and stores it in infra\.env (SONAR_TOKEN)
    * creates the webhook that reports quality gate results back to Jenkins
    * creates the "DevSecOps" quality gate on overall code and makes it the default

  Called by up.ps1.
#>
$ErrorActionPreference = "Stop"
$Root    = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $Root "infra\.env"
$Sonar   = "http://localhost:9000"
. (Join-Path $PSScriptRoot "common.ps1")

function Invoke-Sonar($Method, $Path, $Auth, $Body = @{}) {
    $h = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Auth)) }
    Invoke-RestMethod -Method $Method -Uri "$Sonar/api/$Path" -Headers $h -Body $Body
}

function Test-Login($Auth) {
    try { return [bool](Invoke-Sonar Get "authentication/validate" $Auth).valid } catch { return $false }
}

Write-Host "[..] Waiting for SonarQube (the first start takes 1-3 minutes)"
$deadline = (Get-Date).AddMinutes(8)
do {
    Start-Sleep 5
    try { $st = (Invoke-RestMethod "$Sonar/api/system/status" -TimeoutSec 5).status } catch { $st = "DOWN" }
} until ($st -eq "UP" -or (Get-Date) -gt $deadline)
if ($st -ne "UP") { throw "SonarQube did not start (docker logs sonarqube)" }
Write-Host "[ok] SonarQube is up"

# --- admin password (SonarQube asks to change the default) ---
$pw = Get-EnvValue $EnvFile "SONAR_ADMIN_PASSWORD"
if (-not $pw) { $pw = "DevSecOps-Demo-2026!"; Set-EnvValue $EnvFile "SONAR_ADMIN_PASSWORD" $pw }
$admin = "admin:$pw"
if (-not (Test-Login $admin)) {
    Invoke-Sonar Post "users/change_password" "admin:admin" @{ login = "admin"; previousPassword = "admin"; password = $pw } | Out-Null
    if (-not (Test-Login $admin)) { throw "could not log in to SonarQube as admin" }
    Write-Host "[ok] SonarQube admin password set"
}

# --- analysis token for Jenkins ---
$token = Get-EnvValue $EnvFile "SONAR_TOKEN"
if (-not $token -or -not (Test-Login "${token}:")) {
    $name = "jenkins-" + (Get-Date -Format "yyyyMMddHHmmss")
    $token = (Invoke-Sonar Post "user_tokens/generate" $admin @{ name = $name }).token
    Set-EnvValue $EnvFile "SONAR_TOKEN" $token
    Write-Host "[ok] SonarQube token '$name' created"
}

# --- webhook to Jenkins (lets waitForQualityGate finish) ---
$hooks = @((Invoke-Sonar Get "webhooks/list" $admin).webhooks)
if (-not ($hooks | Where-Object { $_.name -eq "jenkins" })) {
    Invoke-Sonar Post "webhooks/create" $admin @{ name = "jenkins"; url = "http://jenkins:8080/sonarqube-webhook/" } | Out-Null
    Write-Host "[ok] SonarQube webhook to Jenkins created"
}

# --- quality gate on overall code (the built-in "Sonar way" gate only checks new code) ---
$gates = @((Invoke-Sonar Get "qualitygates/list" $admin).qualitygates)
if (-not ($gates | Where-Object { $_.name -eq "DevSecOps" })) {
    Invoke-Sonar Post "qualitygates/create" $admin @{ name = "DevSecOps" } | Out-Null
    Invoke-Sonar Post "qualitygates/create_condition" $admin @{ gateName = "DevSecOps"; metric = "security_rating"; op = "GT"; error = "1" } | Out-Null
    Invoke-Sonar Post "qualitygates/create_condition" $admin @{ gateName = "DevSecOps"; metric = "reliability_rating"; op = "GT"; error = "3" } | Out-Null
    Write-Host "[ok] Quality gate 'DevSecOps' created (security rating A, reliability rating C or better)"
}
Invoke-Sonar Post "qualitygates/set_as_default" $admin @{ name = "DevSecOps" } | Out-Null
Write-Host "[ok] SonarQube configured"
