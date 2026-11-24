#requires -Version 5.1
<#
.SYNOPSIS
    Verifies the PassAura OS (POS) Windows hardening profile and exits non-zero on drift.
.DESCRIPTION
    Supports -DryRun mode for CI/non-enforced environments as well as live inspection
    of Microsoft Defender ASR rules, registry baseline values, and AppLocker policy XML.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SimulateDrift,
    [string]$ProfileDir = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PosHardeningState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [Parameter(Mandatory = $true)]
        [bool]$IsDryRun,
        [Parameter(Mandatory = $true)]
        [bool]$InjectDrift
    )

    $asrPath = Join-Path -Path $BasePath -ChildPath 'asr-rules.psd1'
    $regPath = Join-Path -Path $BasePath -ChildPath 'registry-baseline.psd1'
    $appLockerPath = Join-Path -Path $BasePath -ChildPath 'applocker-policy.xml'
    $manifestPath = Join-Path -Path $BasePath -ChildPath 'profile.json'

    $asrData = Import-PowerShellDataFile -Path $asrPath
    $regData = Import-PowerShellDataFile -Path $regPath
    [xml]$appLockerXml = Get-Content -Path $appLockerPath -Raw
    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json

    $driftFindings = New-Object System.Collections.Generic.List[string]

    if ($null -eq $appLockerXml.AppLockerPolicy) {
        $driftFindings.Add('AppLocker policy root element missing.')
    }

    if ($null -eq $manifest.checks -or @($manifest.checks).Count -eq 0) {
        $driftFindings.Add('profile.json contains no checks.')
    }

    if ($IsDryRun) {
        Write-Information -MessageData ('[VERIFY][DRY-RUN] Validated profile definitions ({0} ASR rules, {1} registry keys, {2} manifest checks).' -f @($asrData.Rules).Count, @($regData.Settings).Count, @($manifest.checks).Count) -InformationAction Continue
        if ($InjectDrift) {
            $driftFindings.Add('Simulated drift triggered in dry-run verification.')
        }
    }
    else {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $actualIds = @($mpPref.AttackSurfaceReductionRules_Ids)
        $actualActions = @($mpPref.AttackSurfaceReductionRules_Actions)

        for ($i = 0; $i -lt @($asrData.Rules).Count; $i++) {
            $expectedRule = $asrData.Rules[$i]
            $idx = [array]::IndexOf($actualIds, $expectedRule.Id)
            if ($idx -lt 0) {
                $driftFindings.Add(("Missing ASR rule {0} ({1})." -f $expectedRule.Id, $expectedRule.Name))
            }
            elseif ([int]$actualActions[$idx] -ne [int]$expectedRule.ActionCode) {
                $driftFindings.Add(("ASR drift for {0}: expected {1}, got {2}." -f $expectedRule.Id, $expectedRule.ActionCode, $actualActions[$idx]))
            }
        }

        foreach ($entry in $regData.Settings) {
            if (-not (Test-Path -Path $entry.Path)) {
                $driftFindings.Add(("Missing registry path: {0}" -f $entry.Path))
                continue
            }
            $item = Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                $driftFindings.Add(("Missing registry value: {0}\{1}" -f $entry.Path, $entry.Name))
                continue
            }
            $actualVal = $item.($entry.Name)
            if ([string]$actualVal -ne [string]$entry.ExpectedValue) {
                $driftFindings.Add(("Registry drift at {0}\{1}: expected '{2}', got '{3}'." -f $entry.Path, $entry.Name, $entry.ExpectedValue, $actualVal))
            }
        }
    }

    if ($driftFindings.Count -gt 0) {
        foreach ($finding in $driftFindings) {
            Write-Warning -Message ("[DRIFT] {0}" -f $finding)
        }
        return 1
    }

    Write-Information -MessageData '[VERIFY] Passed with zero drift.' -InformationAction Continue
    return 0
}

$exitCode = Test-PosHardeningState -BasePath $ProfileDir -IsDryRun ([bool]$DryRun) -InjectDrift ([bool]$SimulateDrift)
exit $exitCode

