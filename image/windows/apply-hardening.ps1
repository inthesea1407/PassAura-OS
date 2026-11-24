#requires -Version 5.1
<#
.SYNOPSIS
    Applies the PassAura OS (POS) Windows hardening profile (ASR, registry, AppLocker).
.DESCRIPTION
    Defaults to safe dry-run / WhatIf mode unless -Apply is explicitly provided.
    Uses free built-in tooling and makes no external network calls or secret accesses.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Apply,
    [switch]$DryRun = $true,
    [string]$ProfileDir = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PosWindowsHardening {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ShouldMutate,
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $asrPath = Join-Path -Path $BasePath -ChildPath 'asr-rules.psd1'
    $regPath = Join-Path -Path $BasePath -ChildPath 'registry-baseline.psd1'
    $appLockerPath = Join-Path -Path $BasePath -ChildPath 'applocker-policy.xml'

    $asrData = Import-PowerShellDataFile -Path $asrPath
    $regData = Import-PowerShellDataFile -Path $regPath
    [xml]$appLockerXml = Get-Content -Path $appLockerPath -Raw

    $ruleIds = @($asrData.Rules | ForEach-Object { $_.Id })
    $ruleActions = @($asrData.Rules | ForEach-Object { [int]$_.ActionCode })

    foreach ($rule in $asrData.Rules) {
        Write-Information -MessageData ("[ASR] {0} ({1}) -> {2} ({3})" -f $rule.Name, $rule.Id, $rule.Mode, $rule.ActionCode) -InformationAction Continue
    }

    if ($ShouldMutate) {
        if ($PSCmdlet.ShouldProcess('Microsoft Defender ASR', 'Set Attack Surface Reduction rules')) {
            if (Get-Command -Name 'Set-MpPreference' -ErrorAction SilentlyContinue) {
                Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $ruleActions
            }
            else {
                Write-Warning -Message 'Set-MpPreference not available on this host; skipped live ASR mutation.'
            }
        }
    }
    else {
        Write-Information -MessageData '[DRY-RUN] Skipped Defender ASR mutation (pass -Apply to enforce).' -InformationAction Continue
    }

    foreach ($entry in $regData.Settings) {
        Write-Information -MessageData ("[REG] {0}\{1} = {2} ({3})" -f $entry.Path, $entry.Name, $entry.ExpectedValue, $entry.Type) -InformationAction Continue
        if ($ShouldMutate) {
            if ($PSCmdlet.ShouldProcess(("{0}\{1}" -f $entry.Path, $entry.Name), ("Set value to {0}" -f $entry.ExpectedValue))) {
                if (-not (Test-Path -Path $entry.Path)) {
                    $null = New-Item -Path $entry.Path -Force
                }
                $null = New-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.ExpectedValue -PropertyType $entry.Type -Force
            }
        }
    }

    $ruleCount = @($appLockerXml.AppLockerPolicy.RuleCollection | ForEach-Object { @($_.FilePathRule) + @($_.FilePublisherRule) }).Count
    Write-Information -MessageData ("[APPLOCKER] Loaded policy '{0}' with {1} rule entries." -f $appLockerPath, $ruleCount) -InformationAction Continue
    if ($ShouldMutate -and (Get-Command -Name 'Set-AppLockerPolicy' -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess($appLockerPath, 'Apply AppLocker policy')) {
            Set-AppLockerPolicy -XmlPolicy $appLockerPath -ErrorAction Stop
        }
    }
    elseif ($ShouldMutate) {
        Write-Warning -Message 'Set-AppLockerPolicy not available on this host; skipped live AppLocker enforcement.'
    }
}

$effectiveMutate = [bool]$Apply -and (-not $DryRun -or $PSBoundParameters.ContainsKey('Apply'))
if (-not $PSBoundParameters.ContainsKey('Apply')) {
    $effectiveMutate = $false
}

Invoke-PosWindowsHardening -ShouldMutate $effectiveMutate -BasePath $ProfileDir

