<#
  Starts the whole DevSecOps platform on Docker Desktop (idempotent - safe to re-run):

    1. kind Kubernetes cluster "devsecops" with namespaces staging + production
    2. Jenkins (pre-configured with JCasC) + SonarQube + Postgres via docker compose
    3. SonarQube bootstrap: admin password, Jenkins token, webhook, quality gate

  usage: powershell -ExecutionPolicy Bypass -File scripts\up.ps1 [-Branch main] [-Repo <git url>]
#>
param(
    [string]$Branch = "",
    [string]$Repo = ""
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Root    = Split-Path -Parent $PSScriptRoot
$Infra   = Join-Path $Root "infra"
$EnvFile = Join-Path $Infra ".env"
$Compose = Join-Path $Infra "docker-compose.yml"
$Cluster = "devsecops"
. (Join-Path $PSScriptRoot "common.ps1")

# --- 1. Docker Desktop ---
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[..] Starting Docker Desktop"
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    $deadline = (Get-Date).AddMinutes(4)
    do { Start-Sleep 5; docker info *> $null } until ($LASTEXITCODE -eq 0 -or (Get-Date) -gt $deadline)
    if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is not running - start it and re-run this script" }
}
Write-Host "[ok] Docker is running"

# --- 2. Kubernetes cluster ---
if (-not ((kind get clusters 2>$null) -contains $Cluster)) {
    Write-Host "[..] Creating kind cluster '$Cluster'"
    kind create cluster --config (Join-Path $Root "k8s\kind-config.yaml") --wait 120s
    if ($LASTEXITCODE -ne 0) { throw "kind create cluster failed" }
} else {
    docker start "$Cluster-control-plane" | Out-Null
}
$deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep 2
    kubectl --context "kind-$Cluster" apply -f (Join-Path $Root "k8s\namespaces.yaml") 2>$null | Out-Null
} until ($LASTEXITCODE -eq 0 -or (Get-Date) -gt $deadline)
if ($LASTEXITCODE -ne 0) { throw "Kubernetes API is not reachable" }
Write-Host "[ok] Kubernetes cluster '$Cluster' ready (namespaces staging, production)"

# Jenkins reaches the API server over the docker "kind" network, so it gets the internal kubeconfig
New-Item -ItemType Directory -Force (Join-Path $Infra ".secrets") | Out-Null
Write-Utf8 (Join-Path $Infra ".secrets\kubeconfig") ((kind get kubeconfig --internal --name $Cluster) -join "`n")

# --- 3. Jenkins + SonarQube ---
if (-not $Repo)   { $Repo = (git -C $Root remote get-url origin).Trim() }
if (-not $Branch) { $Branch = (git -C $Root rev-parse --abbrev-ref HEAD).Trim() }
Set-EnvValue $EnvFile "DEVSECOPS_REPO" $Repo
Set-EnvValue $EnvFile "DEVSECOPS_BRANCH" $Branch

Write-Host "[..] Building and starting Jenkins + SonarQube (the first run downloads about 2 GB)"
docker compose -f $Compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

& (Join-Path $PSScriptRoot "bootstrap_sonar.ps1")

# recreates Jenkins only if the SonarQube token in .env changed
docker compose -f $Compose up -d jenkins
if ($LASTEXITCODE -ne 0) { throw "docker compose up jenkins failed" }
Wait-Http "http://localhost:8080/login" "Jenkins" 5

Write-Host ""
Write-Host "DevSecOps platform is up:"
Write-Host "  Jenkins    : http://localhost:8080   (admin / admin)   job: devsecops-pipeline ($Repo @ $Branch)"
Write-Host "  SonarQube  : http://localhost:9000   (admin / $(Get-EnvValue $EnvFile 'SONAR_ADMIN_PASSWORD'))"
Write-Host "  Staging    : http://localhost:30080  (Kubernetes namespace staging)"
Write-Host "  Production : http://localhost:30081  (Kubernetes namespace production)"
Write-Host "Stop with: scripts\down.ps1"
