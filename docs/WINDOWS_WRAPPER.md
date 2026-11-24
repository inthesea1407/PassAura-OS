Requires a JSON allowlist file.
Refuses execution if the allowlist:
Is missing.
Is malformed.
Lacks issued_at or entries.
Is older than 30 days.
Checks requested package ID against entries[].id.
Invokes winget using an argument array.
Does not use string concatenation to build commands.
Does not use Invoke-Expression.
Supports -WhatIf.
Supports -Verbose.
Writes minimal audit records.
Allowlist Format
JSON
{
  "issued_at": "2026-01-01T00:00:00Z",
  "entries": [
    {
      "id": "Microsoft.VisualStudioCode"
    },
    {
      "id": "Git.Git"
    }
  ]
}
Usage
PowerShell
.\Invoke-PosGate.ps1 `
  -PackageId Microsoft.VisualStudioCode `
  -AllowlistPath .\allowlist.json

Dry run:

PowerShell
.\Invoke-PosGate.ps1 `
  -PackageId Microsoft.VisualStudioCode `
  -AllowlistPath .\allowlist.json `
  -WhatIf

Verbose mode:

PowerShell
.\Invoke-PosGate.ps1 `
  -PackageId Microsoft.VisualStudioCode `
  -AllowlistPath .\allowlist.json `
  -Verbose
Audit Log

Location:

Plain Text
%ProgramData%\PassAura\audit.log

Fields:

Plain Text
timestamp<TAB>package_id<TAB>decision

No package metadata, command lines, usernames, secrets, or additional installation details are recorded.

Exit Codes
Code	Meaning
0	Success
2	Package not allowed
3	Invalid, missing, malformed, or expired allowlist
4	Invalid package identifier




Message Copilot
Copilot is an AI and may make mistakes.
