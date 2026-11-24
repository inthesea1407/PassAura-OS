[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId,
 
    [Parameter(Mandatory = $true)]
    [string]$AllowlistPath
)
 
$ExitOk = 0
$ExitNotAllowed = 2
$ExitBadAllowlist = 3
$ExitBadId = 4
 
function Write-AuditLine {
    param(
        [string]$Id,
        [string]$Decision
    )
 
    try {
        $root = Join-Path $env:ProgramData 'PassAura'
        if (-not (Test-Path $root)) {
            New-Item -ItemType Directory -Path $root -Force | Out-Null
        }
 
        $logPath = Join-Path $root 'audit.log'
        $timestamp = (Get-Date).ToUniversalTime().ToString("o")
        Add-Content -Path $logPath -Value "$timestamp`t$Id`t$Decision"
    }
    catch {
        Write-Verbose "Audit write failed: $_"
    }
}
 
if ($PackageId -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-]{1,100}$') {
    Write-AuditLine -Id $PackageId -Decision 'BAD_ID'
    exit $ExitBadId
}
 
if (-not (Test-Path -LiteralPath $AllowlistPath)) {
    Write-AuditLine -Id $PackageId -Decision 'BAD_ALLOWLIST'
    exit $ExitBadAllowlist
}
 
try {
    $allowlist = Get-Content -LiteralPath $AllowlistPath -Raw | ConvertFrom-Json
 
    if (-not $allowlist.issued_at -or -not $allowlist.entries) {
        throw "Missing required fields."
    }
 
    $issuedAt = :Parse($allowlist.issued_at)
    $maxAge = (Get-Date).ToUniversalTime().AddDays(-30)
 
    if ($issuedAt.UtcDateTime -lt $maxAge) {
        throw "Allowlist expired."
    }
}
catch {
    Write-AuditLine -Id $PackageId -Decision 'BAD_ALLOWLIST'
    exit $ExitBadAllowlist
}
 
$allowed = $false
 
foreach ($entry in $allowlist.entries) {
    if ($entry.id -eq $PackageId) {
        $allowed = $true
        break
    }
}
 
if (-not $allowed) {
    Write-AuditLine -Id $PackageId -Decision 'DENY'
    exit $ExitNotAllowed
}
 
$wingetArgs = @(
    'install'
    '--id'
    $PackageId
    '--exact'
    '--accept-package-agreements'
    '--accept-source-agreements'
)
 
if ($PSCmdlet.ShouldProcess($PackageId, 'Install via winget')) {
    & winget @wingetArgs
    $wingetExit = $LASTEXITCODE
 
    if ($wingetExit -eq 0) {
        Write-AuditLine -Id $PackageId -Decision 'ALLOW'
        exit $ExitOk
    }
 
    Write-AuditLine -Id $PackageId -Decision 'ALLOW'
    exit $wingetExit
}
else {
    Write-AuditLine -Id $PackageId -Decision 'WHATIF'
    exit $ExitOk
}
