# Shared helpers for up.ps1, down.ps1 and bootstrap_sonar.ps1

# winget adds kind/kubectl to PATH for new shells only; pick up the current values
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [Environment]::GetEnvironmentVariable("Path", "User") + ";" +
            "C:\Program Files\Docker\Docker\resources\bin"

function Write-Utf8($Path, $Text) {
    # UTF-8 without BOM, LF line endings (read by Linux containers)
    [IO.File]::WriteAllText($Path, ($Text -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
}

function Get-EnvValue($File, $Key) {
    if (-not (Test-Path $File)) { return "" }
    $line = Get-Content $File | Where-Object { $_ -like "$Key=*" } | Select-Object -First 1
    if ($line) { return $line.Substring($Key.Length + 1) } else { return "" }
}

function Set-EnvValue($File, $Key, $Value) {
    $lines = @()
    if (Test-Path $File) { $lines = @(Get-Content $File | Where-Object { $_ -notlike "$Key=*" }) }
    $lines += "$Key=$Value"
    Write-Utf8 $File (($lines -join "`n") + "`n")
}

function Wait-Http($Url, $Name, $Minutes) {
    Write-Host "[..] Waiting for $Name ($Url)"
    $deadline = (Get-Date).AddMinutes($Minutes)
    do {
        Start-Sleep 5
        try { $code = (Invoke-WebRequest $Url -UseBasicParsing -TimeoutSec 5).StatusCode } catch { $code = 0 }
    } until ($code -eq 200 -or (Get-Date) -gt $deadline)
    if ($code -ne 200) { throw "$Name did not come up in time (see docker logs)" }
    Write-Host "[ok] $Name is up"
}
