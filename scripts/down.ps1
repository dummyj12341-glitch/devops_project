<#
  Stops the DevSecOps platform.
    default : stops Jenkins, SonarQube and the cluster node (all data is kept)
    -Purge  : also deletes the kind cluster, all volumes (Jenkins builds, SonarQube data) and infra\.env

  usage: powershell -ExecutionPolicy Bypass -File scripts\down.ps1 [-Purge]
#>
param([switch]$Purge)
$Root    = Split-Path -Parent $PSScriptRoot
$Infra   = Join-Path $Root "infra"
$Compose = Join-Path $Infra "docker-compose.yml"
. (Join-Path $PSScriptRoot "common.ps1")

if ($Purge) {
    docker compose -f $Compose down -v
    kind delete cluster --name devsecops
    Remove-Item (Join-Path $Infra ".env"), (Join-Path $Infra ".secrets") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Everything removed."
} else {
    docker compose -f $Compose stop
    docker stop devsecops-control-plane | Out-Null
    Write-Host "Stopped. Start again with scripts\up.ps1"
}
