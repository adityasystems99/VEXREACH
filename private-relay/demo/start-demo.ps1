param(
    [switch]$RotateKeys,
    [int]$DestTimeoutMs = 3000
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$TargetBin = Join-Path $RepoRoot "target\debug"
$GenDir = Join-Path $PSScriptRoot "generated"
$LogDir = Join-Path $PSScriptRoot "logs"
$PidFile = Join-Path $GenDir "pids.json"

function Wait-TcpPort {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$ErrLogPath,
        [string]$HostAddr,
        [int]$Port,
        [int]$TimeoutMs = 8000
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        if ($Process.HasExited) {
            $errMsg = if (Test-Path $ErrLogPath) { Get-Content -Path $ErrLogPath -Raw } else { "" }
            throw "Process exited early (code $($Process.ExitCode)) before listening on ${HostAddr}:${Port}. $errMsg"
        }
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($HostAddr, $Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(150)) {
                $client.EndConnect($iar)
                return
            }
        }
        catch { }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for ${HostAddr}:${Port} to listen"
}

$StartedProcs = @()
Push-Location $RepoRoot
try {
    if (Test-Path $PidFile) {
        Write-Host "Stopping existing demo processes cleanly first..."
        & (Join-Path $PSScriptRoot "stop-demo.ps1")
    }

    & cargo build --offline --bins
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build --offline --bins failed"
    }

    if ($RotateKeys -or -not (Test-Path (Join-Path $GenDir "entry.toml"))) {
        & (Join-Path $PSScriptRoot "generate-identities.ps1") -DestTimeoutMs $DestTimeoutMs
    }

    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $DestOut = Join-Path $LogDir "demo-dest.out.log"
    $DestErr = Join-Path $LogDir "demo-dest.err.log"
    $ExitOut = Join-Path $LogDir "relay-exit.out.log"
    $ExitErr = Join-Path $LogDir "relay-exit.err.log"
    $MidOut  = Join-Path $LogDir "relay-middle.out.log"
    $MidErr  = Join-Path $LogDir "relay-middle.err.log"
    $EntOut  = Join-Path $LogDir "relay-entry.out.log"
    $EntErr  = Join-Path $LogDir "relay-entry.err.log"

    $DestCfgArg = "`"" + (Join-Path $PSScriptRoot "configs\destination.toml") + "`""
    $ExitCfgArg = "`"" + (Join-Path $GenDir "exit.toml") + "`""
    $MidCfgArg  = "`"" + (Join-Path $GenDir "middle.toml") + "`""
    $EntCfgArg  = "`"" + (Join-Path $GenDir "entry.toml") + "`""

    $DestProc = Start-Process -FilePath (Join-Path $TargetBin "demo-dest.exe") `
        -ArgumentList @("--config", $DestCfgArg) `
        -RedirectStandardOutput $DestOut -RedirectStandardError $DestErr -PassThru -WindowStyle Hidden
    $StartedProcs += $DestProc
    Wait-TcpPort -Process $DestProc -ErrLogPath $DestErr -HostAddr "127.0.0.1" -Port 9000

    $ExitProc = Start-Process -FilePath (Join-Path $TargetBin "relay-exit.exe") `
        -ArgumentList @("--config", $ExitCfgArg) `
        -RedirectStandardOutput $ExitOut -RedirectStandardError $ExitErr -PassThru -WindowStyle Hidden
    $StartedProcs += $ExitProc
    Wait-TcpPort -Process $ExitProc -ErrLogPath $ExitErr -HostAddr "127.0.0.1" -Port 9103

    $MidProc = Start-Process -FilePath (Join-Path $TargetBin "relay-middle.exe") `
        -ArgumentList @("--config", $MidCfgArg) `
        -RedirectStandardOutput $MidOut -RedirectStandardError $MidErr -PassThru -WindowStyle Hidden
    $StartedProcs += $MidProc
    Wait-TcpPort -Process $MidProc -ErrLogPath $MidErr -HostAddr "127.0.0.1" -Port 9102

    $EntProc = Start-Process -FilePath (Join-Path $TargetBin "relay-entry.exe") `
        -ArgumentList @("--config", $EntCfgArg) `
        -RedirectStandardOutput $EntOut -RedirectStandardError $EntErr -PassThru -WindowStyle Hidden
    $StartedProcs += $EntProc
    Wait-TcpPort -Process $EntProc -ErrLogPath $EntErr -HostAddr "127.0.0.1" -Port 9101

    $pidMap = @{
        dest   = $DestProc.Id
        exit   = $ExitProc.Id
        middle = $MidProc.Id
        entry  = $EntProc.Id
    }
    $pidMap | ConvertTo-Json | Set-Content -Path $PidFile -Encoding UTF8

    Write-Host "Started independent OS processes:"
    Write-Host "  demo-dest    PID=$($DestProc.Id)  127.0.0.1:9000"
    Write-Host "  relay-exit   PID=$($ExitProc.Id)  127.0.0.1:9103"
    Write-Host "  relay-middle PID=$($MidProc.Id)  127.0.0.1:9102"
    Write-Host "  relay-entry  PID=$($EntProc.Id)  127.0.0.1:9101"
}
catch {
    foreach ($p in $StartedProcs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
finally {
    Pop-Location
}
