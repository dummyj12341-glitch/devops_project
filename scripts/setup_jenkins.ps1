<#
  Downloads and starts a local Jenkins LTS (no Docker, no installer) that is
  fully pre-configured for this project:

    * plugins from jenkins-config\plugins.txt
    * admin user (default admin / admin)  -- local demo only
    * "devsecops-pipeline" job pointing at this git repository

  JENKINS_HOME is jenkins\home inside the project (git-ignored).

  usage: powershell -ExecutionPolicy Bypass -File scripts\setup_jenkins.ps1 [-Port 8080] [-Branch main]
#>
param(
    [int]$Port = 8080,
    [string]$Branch = "",
    [string]$AdminPassword = "admin"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root        = Split-Path -Parent $PSScriptRoot
$JenkinsDir  = Join-Path $Root "jenkins"
$JenkinsHome = Join-Path $JenkinsDir "home"
$War         = Join-Path $JenkinsDir "jenkins.war"
$PluginTool  = Join-Path $JenkinsDir "jenkins-plugin-manager.jar"
$PluginToolVersion = "2.15.0"
New-Item -ItemType Directory -Force $JenkinsHome | Out-Null

if (-not $Branch) { $Branch = (git -C $Root rev-parse --abbrev-ref HEAD).Trim() }

if (-not (Test-Path $War)) {
    Write-Host "[..] Downloading Jenkins LTS war"
    Invoke-WebRequest "https://get.jenkins.io/war-stable/latest/jenkins.war" -OutFile $War -UseBasicParsing
}
if (-not (Test-Path $PluginTool)) {
    Write-Host "[..] Downloading Jenkins plugin manager $PluginToolVersion"
    Invoke-WebRequest "https://github.com/jenkinsci/plugin-installation-manager-tool/releases/download/$PluginToolVersion/jenkins-plugin-manager-$PluginToolVersion.jar" -OutFile $PluginTool -UseBasicParsing
}

$PluginDir = Join-Path $JenkinsHome "plugins"
if (-not (Test-Path (Join-Path $PluginDir "workflow-aggregator.jpi"))) {
    Write-Host "[..] Installing plugins (this takes a few minutes the first time)"
    java -jar $PluginTool --war $War --plugin-download-directory $PluginDir --plugin-file (Join-Path $Root "jenkins-config\plugins.txt")
    if ($LASTEXITCODE -ne 0) { throw "plugin installation failed" }
}

# Init scripts create the admin user and the pipeline job on startup
Copy-Item (Join-Path $Root "jenkins-config\init.groovy.d") $JenkinsHome -Recurse -Force

$env:JENKINS_HOME           = $JenkinsHome
$env:JENKINS_ADMIN_PASSWORD = $AdminPassword
$env:DEVSECOPS_REPO         = "file:///" + ($Root -replace '\\', '/')
$env:DEVSECOPS_BRANCH       = $Branch

# Windows PowerShell 5.1 does not quote Start-Process arguments, so quote each one here
$javaArgs = @(
    "-Djenkins.install.runSetupWizard=false",
    # allow the job to clone this repository from a local file:// path
    "-Dhudson.plugins.git.GitSCM.ALLOW_LOCAL_CHECKOUT=true",
    # let the HTML Publisher report use its inline CSS (local demo setting)
    "-Dhudson.model.DirectoryBrowserSupport.CSP=sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline';",
    "-jar", $War, "--httpPort=$Port"
) | ForEach-Object { '"' + $_ + '"' }
$log = Join-Path $JenkinsDir "jenkins.log"
Write-Host "[..] Starting Jenkins on http://localhost:$Port  (log: $log)"
Start-Process java -ArgumentList $javaArgs -RedirectStandardOutput $log -RedirectStandardError "$log.err" -WindowStyle Hidden

$deadline = (Get-Date).AddMinutes(4)
do {
    Start-Sleep -Seconds 5
    try { $code = (Invoke-WebRequest "http://localhost:$Port/login" -UseBasicParsing -TimeoutSec 5).StatusCode } catch { $code = 0 }
} until ($code -eq 200 -or (Get-Date) -gt $deadline)

if ($code -ne 200) { throw "Jenkins did not come up in time; check $log.err" }
Write-Host ""
Write-Host "Jenkins is ready:  http://localhost:$Port"
Write-Host "  login : admin / $AdminPassword   (local demo credentials)"
Write-Host "  job   : http://localhost:$Port/job/devsecops-pipeline/   (branch $Branch)"
Write-Host "Stop it with: scripts\stop_jenkins.ps1"
