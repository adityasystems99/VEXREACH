param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Invoke-DockerClientCase {
    param([string]$Label, [string[]]$ClientArgs, [bool]$ExpectSuccess)
    Write-Host "`n=== $Label ==="
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & docker compose run --rm --no-deps relay-client @ClientArgs 2>&1
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

Push-Location $RepoRoot
try {
    & docker compose config --quiet
    if ($LASTEXITCODE -ne 0) { throw "docker compose config failed" }

    if (-not $SkipBuild) {
        & docker compose build
        if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }
    }

    & docker compose down -v --remove-orphans | Out-Null

    & docker compose up -d --wait demo-dest relay-exit relay-middle relay-entry
    if ($LASTEXITCODE -ne 0) { throw "docker compose up -d --wait failed" }

    Write-Host "`n=== Container Health & Topology Status ==="
    & docker compose ps -a

    Invoke-DockerClientCase "1. Empty raw request (0 bytes)" @("--config", "/cfg/client.toml", "--target", "demo-dest:9000", "--data-bytes", "0") $true
    Invoke-DockerClientCase "2. Health check HTTP URL (/health)" @("--config", "/cfg/client.toml", "--url", "http://demo-dest:9000/health") $true
    Invoke-DockerClientCase "3. Medium HTTP response (12 KiB multi-chunk)" @("--config", "/cfg/client.toml", "--url", "http://demo-dest:9000/medium") $true
    Invoke-DockerClientCase "4. Exact 64 KiB (65,536B) raw request + response" @("--config", "/cfg/client.toml", "--target", "demo-dest:9000", "--data-bytes", "65536") $true
    Invoke-DockerClientCase "5. Exact 64 KiB HTTP response (/max-64kib)" @("--config", "/cfg/client.toml", "--url", "http://demo-dest:9000/max-64kib") $true
    Invoke-DockerClientCase "6. Redirect non-follow check (/redirect-ssrf -> returns 302 directly)" @("--config", "/cfg/client.toml", "--url", "http://demo-dest:9000/redirect-ssrf") $true
    Invoke-DockerClientCase "7. Oversized request (65,537B rejected locally)" @("--config", "/cfg/client.toml", "--target", "demo-dest:9000", "--data-bytes", "65537") $false
    Invoke-DockerClientCase "8a. Private RFC1918 SSRF denied (10.0.0.1:80)" @("--config", "/cfg/client.toml", "--url", "http://10.0.0.1:80/health") $false
    Invoke-DockerClientCase "8b. Loopback SSRF denied inside container (127.0.0.1:9000)" @("--config", "/cfg/client.toml", "--url", "http://127.0.0.1:9000/health") $false
    Invoke-DockerClientCase "8c. Cloud metadata SSRF denied (169.254.169.254:80)" @("--config", "/cfg/client.toml", "--url", "http://169.254.169.254/latest/meta-data/") $false
    Invoke-DockerClientCase "9. Oversized destination response blocked at Exit (/oversized)" @("--config", "/cfg/client.toml", "--url", "http://demo-dest:9000/oversized") $false
    Invoke-DockerClientCase "10. Slow destination timeout enforced at Exit (/slow)" @("--config", "/cfg/client.toml", "--url", "http://demo-dest:9000/slow") $false

    Write-Host "`n=== Separate Container Relay Log Verification ==="
    foreach ($svc in @("relay-entry", "relay-middle", "relay-exit")) {
        $logs = (& docker compose logs --no-color $svc) -join "`n"
        if ($logs -notmatch "STATUS=READY" -or $logs -notmatch "relay node started" -or $logs -notmatch "circuit hop established") {
            throw "Container log proof failed for $svc"
        }
        if ($logs -match "172\." -or $logs -match "private-relay-demo-dest" -or $logs -match "/health") {
            throw "Sensitive target/IP/payload leaked into $svc container logs!"
        }
        $hopCount = ([regex]::Matches($logs, "circuit hop established")).Count
        Write-Host ("  {0}: STATUS=READY, circuit_hops={1}" -f $svc, $hopCount)
    }

    Write-Host "`nALL DOCKER CONTAINER INTEGRATION TESTS PASSED."
}
finally {
    Write-Host "`n=== Shutting Down Containers Cleanly ==="
    & docker compose stop
    & docker compose logs --tail 3 relay-entry relay-middle relay-exit demo-dest
    & docker compose down -v --remove-orphans
    Pop-Location
}
