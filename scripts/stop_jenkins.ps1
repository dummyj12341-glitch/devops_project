# Stops the local Jenkins started by setup_jenkins.ps1
$procs = Get-CimInstance Win32_Process -Filter "Name='java.exe'" | Where-Object { $_.CommandLine -like '*jenkins.war*' }
if (-not $procs) { Write-Host "Jenkins is not running"; exit 0 }
$procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Host "Stopped Jenkins (PID $($_.ProcessId))" }
