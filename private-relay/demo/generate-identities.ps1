param(
    [int]$DestTimeoutMs = 3000
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$TargetBin = Join-Path $RepoRoot "target\debug"
$OutDir = Join-Path $PSScriptRoot "generated"

Push-Location $RepoRoot
try {
    & cargo build --offline --bin relay-keygen
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build --offline --bin relay-keygen failed"
    }

    $KeygenExe = Join-Path $TargetBin "relay-keygen.exe"
    & $KeygenExe `
        --out-dir $OutDir `
        --entry-addr "127.0.0.1:9101" `
        --middle-addr "127.0.0.1:9102" `
        --exit-addr "127.0.0.1:9103" `
        --allow-target "127.0.0.1:9000" `
        --dest-timeout-ms $DestTimeoutMs
    if ($LASTEXITCODE -ne 0) {
        throw "relay-keygen failed"
    }
    Write-Host "Generated fresh ephemeral demo configs in $OutDir (never tracked by git)."
}
finally {
    Pop-Location
}
