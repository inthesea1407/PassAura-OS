$ScriptPath = Join-Path $PSScriptRoot 'Invoke-PosGate.ps1'
 
Describe 'Invoke-PosGate' {
 
    BeforeEach {
        $ValidAllowlist = @{
            issued_at = (Get-Date).ToUniversalTime().ToString("o")
            entries   = @(
                @{ id = "Microsoft.VisualStudioCode" }
            )
        } | ConvertTo-Json -Depth 5
 
        Mock Test-Path { $true }
        Mock Get-Content { $ValidAllowlist }
        Mock winget { }
    }
 
    It 'rejects invalid package id with exit code 4' {
        $result = powershell.exe -NoProfile -File $ScriptPath `
            -PackageId '!bad!' `
            -AllowlistPath 'allowlist.json'
 
        $LASTEXITCODE | Should -Be 4
    }
 
    It 'rejects missing allowlist with exit code 3' {
        Mock Test-Path { $false }
 
        try {
            & $ScriptPath -PackageId 'Microsoft.VisualStudioCode' -AllowlistPath 'missing.json'
        }
        catch {}
 
        $LASTEXITCODE | Should -Be 3
    }
 
    It 'rejects package not in allowlist with exit code 2' {
        $json = @{
            issued_at = (Get-Date).ToUniversalTime().ToString("o")
            entries   = @(
                @{ id = "Git.Git" }
            )
        } | ConvertTo-Json -Depth 5
 
        Mock Get-Content { $json }
 
        try {
            & $ScriptPath -PackageId 'Microsoft.VisualStudioCode' -AllowlistPath 'allowlist.json'
        }
        catch {}
 
        $LASTEXITCODE | Should -Be 2
    }
 
    It 'invokes winget for approved package' {
        & {
            function global:winget {
                $script:WingetCalled = $true
                $global:LASTEXITCODE = 0
            }
 
            $tmp = New-TemporaryFile
 
            @{
                issued_at = (Get-Date).ToUniversalTime().ToString("o")
                entries   = @(
                    @{ id = "Microsoft.VisualStudioCode" }
                )
            } | ConvertTo-Json -Depth 5 | Set-Content $tmp
 
            try {
                & $ScriptPath `
                    -PackageId 'Microsoft.VisualStudioCode' `
                    -AllowlistPath $tmp
            }
            catch {}
 
            $script:WingetCalled | Should -BeTrue
        }
    }
 
    It 'supports WhatIf without invoking winget' {
        & {
            function global:winget {
                throw 'winget should not be called'
            }
 
            $tmp = New-TemporaryFile
 
            @{
                issued_at = (Get-Date).ToUniversalTime().ToString("o")
                entries   = @(
                    @{ id = "Microsoft.VisualStudioCode" }
                )
            } | ConvertTo-Json -Depth 5 | Set-Content $tmp
 
            try {
                & $ScriptPath `
                    -PackageId 'Microsoft.VisualStudioCode' `
                    -AllowlistPath $tmp `
                    -WhatIf
            }
            catch {}
 
            $LASTEXITCODE | Should -Be 0
        }
    }
}
