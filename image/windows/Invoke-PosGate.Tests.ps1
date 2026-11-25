# Runs Invoke-PosGate.ps1 in a child pwsh process so its `exit` codes are
# real exit codes. winget is replaced by a fake winget.cmd found first on PATH.
# This tests the wrapper's own logic only. It does not verify any signature.

BeforeAll {
    $script:Script = Join-Path $PSScriptRoot 'Invoke-PosGate.ps1'
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ("posgate-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work | Out-Null
    $script:Marker = Join-Path $script:Work 'winget-called.txt'
    Set-Content -Path (Join-Path $script:Work 'winget.cmd') -Value "@echo off`r`necho called> `"$($script:Marker)`"`r`nexit /b 0"

    function script:New-Allowlist([string[]]$Ids, [int]$AgeDays = 0) {
        $path = Join-Path $script:Work ([guid]::NewGuid().ToString('N') + '.json')
        @{
            issued_at = (Get-Date).ToUniversalTime().AddDays(-$AgeDays).ToString('o')
            entries   = @($Ids | ForEach-Object { @{ id = $_ } })
        } | ConvertTo-Json -Depth 5 | Set-Content -Path $path
        return $path
    }

    function script:Invoke-Gate([string]$PackageId, [string]$Allowlist, [switch]$WhatIf) {
        $env:PATH = "$($script:Work);$env:PATH"
        $argList = @('-NoProfile', '-File', $script:Script, '-PackageId', $PackageId, '-AllowlistPath', $Allowlist)
        if ($WhatIf) { $argList += '-WhatIf' }
        & pwsh @argList *> $null
        return $LASTEXITCODE
    }
}

AfterAll {
    Remove-Item -Recurse -Force -Path $script:Work -ErrorAction SilentlyContinue
}

Describe 'Invoke-PosGate' {
    BeforeEach {
        Remove-Item -Path $script:Marker -ErrorAction SilentlyContinue
    }

    It 'rejects an invalid package id with exit code 4' {
        $list = New-Allowlist @('Microsoft.VisualStudioCode')
        Invoke-Gate '!bad!' $list | Should -Be 4
    }

    It 'rejects a missing allowlist file with exit code 3' {
        Invoke-Gate 'Microsoft.VisualStudioCode' (Join-Path $script:Work 'missing.json') | Should -Be 3
    }

    It 'rejects an expired allowlist with exit code 3' {
        $list = New-Allowlist @('Microsoft.VisualStudioCode') 60
        Invoke-Gate 'Microsoft.VisualStudioCode' $list | Should -Be 3
    }

    It 'rejects a package that is not in the allowlist with exit code 2' {
        $list = New-Allowlist @('Git.Git')
        Invoke-Gate 'Microsoft.VisualStudioCode' $list | Should -Be 2
        Test-Path $script:Marker | Should -BeFalse
    }

    It 'calls winget for an approved package' {
        $list = New-Allowlist @('Microsoft.VisualStudioCode')
        Invoke-Gate 'Microsoft.VisualStudioCode' $list | Should -Be 0
        Test-Path $script:Marker | Should -BeTrue
    }

    It 'does not call winget with -WhatIf' {
        $list = New-Allowlist @('Microsoft.VisualStudioCode')
        Invoke-Gate 'Microsoft.VisualStudioCode' $list -WhatIf | Should -Be 0
        Test-Path $script:Marker | Should -BeFalse
    }
}
