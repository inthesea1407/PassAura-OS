@{
    Rules = @(
        @{
            Id          = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
            Name        = 'Block credential stealing from the Windows local security authority subsystem'
            Mode        = 'Block'
            ActionCode  = 1
            Severity    = 'critical'
        },
        @{
            Id          = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
            Name        = 'Block execution of potentially obfuscated scripts'
            Mode        = 'Block'
            ActionCode  = 1
            Severity    = 'high'
        },
        @{
            Id          = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            Name        = 'Block all Office applications from creating child processes'
            Mode        = 'Block'
            ActionCode  = 1
            Severity    = 'high'
        },
        @{
            Id          = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
            Name        = 'Block executable content from email client and webmail'
            Mode        = 'Block'
            ActionCode  = 1
            Severity    = 'high'
        },
        @{
            Id          = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
            Name        = 'Block persistence through WMI event subscription'
            Mode        = 'Audit'
            ActionCode  = 2
            Severity    = 'medium'
        },
        @{
            Id          = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'
            Name        = 'Block use of copied or impersonated system tools'
            Mode        = 'Audit'
            ActionCode  = 2
            Severity    = 'medium'
        }
    )
}

