$ErrorActionPreference = "Stop"
$GenDir = Join-Path $PSScriptRoot "generated"
$PidFile = Join-Path $GenDir "pids.json"

if (-not (Test-Path $PidFile)) {
    Write-Host "No running demo PID file at $PidFile."
    exit 0
}

$pids = Get-Content -Path $PidFile -Raw | ConvertFrom-Json
foreach ($name in @("entry", "middle", "exit", "dest")) {
    $procId = $pids.$name
    if ($procId) {
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped $name (PID=$procId)"
        }
    }
}

Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue
Write-Host "Demo processes stopped cleanly."
