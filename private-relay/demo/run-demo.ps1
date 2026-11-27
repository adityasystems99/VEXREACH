param(
    [switch]$AutoStartStop
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$TargetBin = Join-Path $RepoRoot "target\debug"
$ClientExe = Join-Path $TargetBin "relay-client.exe"
$ClientCfg = Join-Path $PSScriptRoot "generated\client.toml"

function Invoke-Case {
    param([string]$Label, [string[]]$ClientArgs, [bool]$ExpectSuccess)
    Write-Host "`n=== $Label ==="
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $ClientExe @ClientArgs 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevPref
    $output | ForEach-Object { Write-Host $_ }
    if ($ExpectSuccess -and $code -ne 0) {
        throw "Expected success for '$Label' but exited $code"
    }
    if (-not $ExpectSuccess -and $code -eq 0) {
        throw "Expected failure for '$Label' but exited 0"
    }
}

if ($AutoStartStop) {
    & (Join-Path $PSScriptRoot "start-demo.ps1") -RotateKeys -DestTimeoutMs 2500
}

try {
    if (-not (Test-Path $ClientExe)) {
        throw "Missing $ClientExe. Run demo\start-demo.ps1 first."
    }

    Invoke-Case "1. Empty raw request (0 bytes)" @("--config", $ClientCfg, "--target", "127.0.0.1:9000", "--data-bytes", "0") $true
    Invoke-Case "2. Health check HTTP URL (/health)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9000/health") $true
    Invoke-Case "3. Medium HTTP response (12 KiB multi-chunk)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9000/medium") $true
    Invoke-Case "4. Exact 64 KiB (65,536B) raw request + response" @("--config", $ClientCfg, "--target", "127.0.0.1:9000", "--data-bytes", "65536") $true
    Invoke-Case "5. Exact 64 KiB HTTP response (/max-64kib)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9000/max-64kib") $true
    Invoke-Case "6. Redirect non-follow check (/redirect-ssrf -> returns 302 directly)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9000/redirect-ssrf") $true
    Invoke-Case "7. Oversized request (65,537B rejected locally)" @("--config", $ClientCfg, "--target", "127.0.0.1:9000", "--data-bytes", "65537") $false
    Invoke-Case "8. Exit policy SSRF/allowlist denial (unlisted target 127.0.0.1:9099)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9099/health") $false
    Invoke-Case "9. Oversized destination response blocked at Exit (/oversized)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9000/oversized") $false
    Invoke-Case "10. Slow destination timeout enforced at Exit (/slow)" @("--config", $ClientCfg, "--url", "http://127.0.0.1:9000/slow") $false

    $LogDir = Join-Path $PSScriptRoot "logs"
    Write-Host "`n=== Multi-Process Relay Log Verification ==="
    foreach ($node in @("entry", "middle", "exit")) {
        $outLog = Get-Content -Path (Join-Path $LogDir "relay-$node.out.log") -Raw
        $errLog = Get-Content -Path (Join-Path $LogDir "relay-$node.err.log") -Raw
        if ($outLog -notmatch "STATUS=READY" -or $errLog -notmatch "relay node started" -or $errLog -notmatch "circuit hop established") {
            throw "Multi-process log proof failed for relay-$node"
        }
        $hopCount = ([regex]::Matches($errLog, "circuit hop established")).Count
        Write-Host ("  relay-{0}: STATUS=READY, circuit_hops={1}" -f $node, $hopCount)
    }

    Write-Host "`nALL MULTI-PROCESS DEMO SCENARIOS PASSED."
}
finally {
    if ($AutoStartStop) {
        & (Join-Path $PSScriptRoot "stop-demo.ps1")
    }
}
