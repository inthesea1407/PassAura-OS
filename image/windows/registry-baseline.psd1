@{
    Settings = @(
        @{
            Id            = 'REG-001'
            Name          = 'DisableSMB1'
            Path          = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Type          = 'DWord'
            ExpectedValue = 0
            Severity      = 'critical'
            Description   = 'Disables legacy SMBv1 server protocol.'
        },
        @{
            Id            = 'REG-002'
            Name          = 'EnableLUA'
            Path          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Type          = 'DWord'
            ExpectedValue = 1
            Severity      = 'high'
            Description   = 'Keeps User Account Control (UAC) enabled.'
        },
        @{
            Id            = 'REG-003'
            Name          = 'EnableScriptBlockLogging'
            Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Type          = 'DWord'
            ExpectedValue = 1
            Severity      = 'medium'
            Description   = 'Enables PowerShell ScriptBlock logging for audit visibility.'
        }
    )
}

