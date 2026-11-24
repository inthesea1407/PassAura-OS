$ErrorActionPreference = "Stop"

$ReleaseDir = Split-Path -Parent $PSScriptRoot
$ChecksumFile = Join-Path $ReleaseDir "SHA256SUMS"

$ExpectedFiles = @(
    "pos-gate-linux-x86_64",
    "pos-cli-linux-x86_64",
    "pos-gate-windows-x86_64.exe",
    "pos-cli-windows-x86_64.exe"
)

if (-not (Test-Path -LiteralPath $ChecksumFile -PathType Leaf)) {
    Write-Error "Missing SHA256SUMS"
    exit 1
}

$ChecksumEntries = @{}

foreach ($Line in Get-Content -LiteralPath $ChecksumFile) {
    if ($Line -notmatch '^([A-Fa-f0-9]{64})\s+\*?(.+)$') {
        Write-Error "Invalid checksum line: $Line"
        exit 1
    }

    $Hash = $Matches[1].ToLowerInvariant()
    $FileName = $Matches[2]

    if ([System.IO.Path]::IsPathRooted($FileName) -or
        $FileName.Contains("/") -or
        $FileName.Contains("\")) {
        Write-Error "Unsafe filename in checksum file: $FileName"
        exit 1
    }

    if ($ChecksumEntries.ContainsKey($FileName)) {
        Write-Error "Duplicate checksum entry: $FileName"
        exit 1
    }

    $ChecksumEntries[$FileName] = $Hash
}

foreach ($FileName in $ExpectedFiles) {
    if (-not $ChecksumEntries.ContainsKey($FileName)) {
        Write-Error "Missing checksum entry: $FileName"
        exit 1
    }

    $FilePath = Join-Path $ReleaseDir $FileName

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        Write-Error "Missing release file: $FileName"
        exit 1
    }

    $ActualHash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $ExpectedHash = $ChecksumEntries[$FileName]

    if ($ActualHash -ne $ExpectedHash) {
        Write-Error "Checksum mismatch: $FileName"
        exit 1
    }

    Write-Output "OK: $FileName"
}

Write-Output "SUCCESS: Release checksum verification passed."

Validation status

Draft — not ready to activate

These files are written but not validated against the live PassAura OS repository.

Release workflow design
Offline signing separation
SHA256 verification scripts
Linux + Windows release artifacts
No signing key in CI
Tag-triggered release
Read-only permissions for build jobs
Pin action references to actual commit SHAs
Validate workflow syntax
Run both verification scripts
Test release workflow against actual workspace
Independently test reproducibility
