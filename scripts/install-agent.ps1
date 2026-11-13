# install-agent.ps1 — install clanker-guard-agent on Windows with hash verification.
#
#   iwr <base-url>/install-agent.ps1 -UseBasicParsing | iex
#   # or, with parameters:
#   .\install-agent.ps1 -Version 0.1.0 -BaseUrl https://github.com/bgdnvk/clanker/releases/download
#
# Security properties:
#   * The artifact is verified against its published SHA-256 before it is used.
#   * No service, no scheduled task, no auto-update, no telemetry.
#   * Uninstall with: clanker-guard-agent uninstall --yes

[CmdletBinding()]
param(
    [string]$Version = $env:CLANKER_GUARD_VERSION,
    [string]$BaseUrl = $(if ($env:CLANKER_GUARD_BASE_URL) { $env:CLANKER_GUARD_BASE_URL } else { "https://github.com/bgdnvk/clanker/releases/download" }),
    [string]$BinDir = $(if ($env:CLANKER_GUARD_BIN_DIR) { $env:CLANKER_GUARD_BIN_DIR } else { Join-Path $env:LOCALAPPDATA "clanker-guard\bin" }),
    [switch]$Scan,
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"

if (-not $Version) {
    throw "A release version is required: -Version 0.1.0 (or set CLANKER_GUARD_VERSION)"
}

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
$artifact = "clanker-guard-agent_windows_${arch}.exe"

if ($BaseUrl -like "https://github.com/*/releases/download") {
    $urlBase = "$BaseUrl/v$Version"
} else {
    $urlBase = $BaseUrl
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("clanker-guard-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $artifactPath = Join-Path $work $artifact
    $shaPath = "$artifactPath.sha256"

    Write-Host "clanker-guard-agent $Version (windows/$arch)"
    Write-Host "downloading: $urlBase/$artifact"
    Invoke-WebRequest -Uri "$urlBase/$artifact" -OutFile $artifactPath -UseBasicParsing
    try {
        Invoke-WebRequest -Uri "$urlBase/$artifact.sha256" -OutFile $shaPath -UseBasicParsing
    } catch {
        # fall back to the aggregate checksum file
        $sumsPath = Join-Path $work "SHA256SUMS"
        Invoke-WebRequest -Uri "$urlBase/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
        $shaPath = $sumsPath
    }

    $lines = Get-Content $shaPath
    $expected = $null
    foreach ($line in $lines) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $artifact) { $expected = $parts[0]; break }
    }
    if (-not $expected) { $expected = ($lines | Select-Object -First 1).Split(' ')[0] }
    if (-not $expected) { throw "No SHA-256 checksum published for $artifact; refusing to install." }

    $actual = (Get-FileHash -Path $artifactPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        throw "SHA-256 mismatch for $artifact (expected $expected, got $actual). Refusing to install."
    }
    Write-Host "verified SHA-256 $actual"

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    $dest = Join-Path $BinDir "clanker-guard-agent.exe"
    Copy-Item -Path $artifactPath -Destination $dest -Force

    Write-Host "installed: $dest"
    & $dest version

    if ($AddToPath) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$BinDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
            Write-Host "added $BinDir to the user PATH (open a new shell to pick it up)"
        }
    } else {
        Write-Host "note: $BinDir is not on your PATH by default; pass -AddToPath to add it"
    }

    Write-Host ""
    Write-Host "Next steps (nothing runs automatically):"
    Write-Host "  clanker-guard-agent scan --local --format json --output findings.json"
    Write-Host "  clanker-guard-agent feeds update --with-osv"
    Write-Host "  clanker-guard-agent uninstall --yes"

    if ($Scan) {
        Write-Host ""
        & $dest scan --local
    }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
