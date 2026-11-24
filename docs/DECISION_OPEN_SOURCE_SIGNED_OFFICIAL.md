# Decision: open source code, enforcing official signed builds (owner, 12:52)

- All source is open (MIT). Anyone may read, build, modify and redistribute.
- Official PassAura OS builds are signed with the PassAura key. Only official builds:
  - enforce the rules (no other password manager installs, signed-apps-only, entitlements),
  - connect to the PassAura store, updates and registry (invite codes, seed members),
  - include PassAura Premium.
- No ads anywhere (policy default).

## Honest caveats (state to users)
1. A fork can remove the block. The block binds official builds only. Users who install a fork get no store, updates or Premium from us.
2. Enforcement holds only where the boot chain trusts PassAura keys (own-key verified boot). On stock Samsung/Oppo it is a managed-device layer, weaker.
3. MIT permits others to copy the code, including the gate, and ship their own signed OS. We protect the name/trademark and the signing key, not the code.
4. Consider a trademark policy: forks must not call themselves "PassAura OS".
5. License choice: MIT lets companies close forks. If the owner wants forks to stay open, AGPL/GPL is the alternative; MIT stays until he says otherwise.
6. Legal/policy risk: blocking competing password managers may attract platform, store or competition-law scrutiny in some countries. Get legal review before launch.
