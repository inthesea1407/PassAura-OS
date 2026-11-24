# Security

PassAura OS has not been independently audited. Treat every build as experimental.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository (Security tab, "Report a vulnerability"). Do not open a public issue or post details publicly.

Include the affected crate or path, commit, steps to reproduce, and expected versus actual behavior.

## Process

1. Maintainers acknowledge receipt when possible.
2. The default coordinated disclosure window is 90 days. We aim to ship a fix or mitigation in that window and will say so if we need longer.
3. Public disclosure waits for a fix or the end of the window, whichever comes first, unless agreed otherwise.

## Scope

- Bypass of the install gate, policy engine, signature checks, or the Android/Windows/Linux enforcement code.
- Secrets or credentials accidentally present in the repository.

Out of scope: general OS installer bugs, host compromise after install, and theoretical issues with no practical impact.

## Bounty

There is no bug bounty and no payment for reports.
