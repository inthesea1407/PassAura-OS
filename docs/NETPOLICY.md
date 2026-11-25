# Per-UID network policy generator (`pos-netpolicy`)

Status: review draft. Tested on Linux with Rust 1.100.0 (no minimum Rust version declared or tested).
The crate has no dependencies. It only builds text. It never runs `nft` or `systemctl`, never reads or writes a
file and never opens a socket (a test checks the source for that). Windows is not covered. No security-audit
or certification claim is made.

## What the generated rules do

For ONE dedicated **numeric** uid (UID 0 and 4294967295 are refused), the nftables script limits what that
uid may **send** (OUTPUT). Packets with a local socket owned by that uid are matched with `meta skuid`:

- allowed: the destination IP/CIDR networks you list, plus the explicit exceptions you turn on;
- everything else from that uid is dropped (the uid chain ends in `drop`, so an empty list blocks all its traffic).

Packets from every other uid are not touched (base chain `policy accept`).

Nothing else is claimed. These rules **do not**:

- isolate or protect INPUT, and they do not isolate hosts or apps from each other;
- hide identity or traffic; they are not anonymity;
- set a global default-drop for the host (that would cut the host off the network; any such profile is a
  design note only, not generated here);
- make a host name safe: host names are rejected, only IP/CIDR is accepted;
- affect traffic that is not tied to a local socket owned by the uid. Kernel-generated packets such as IPv6
  neighbor discovery have no socket owner, so `skuid` does not match them. The ND and DHCP exceptions matter
  only for a program running as that uid that sends such packets itself;
- take effect in any other way than the operator loading the script. This crate applies nothing.

## Table handling

The script starts with `add table inet passaura_netpolicy` then `delete table inet passaura_netpolicy`, then
defines the table. In one `nft -f` load this replaces only that table, atomically. It contains no `flush`,
touches no other table or chain and creates no rule in `inet filter` or any host table. `render_nft_remove()`
produces a script that removes only that table (and is harmless when it is absent).

An accept in this table does not override a drop in another table's hook, and other tables can still drop
the uid's traffic. This table can only add restrictions for the uid.

## Inputs

| Field | Meaning | Default |
|---|---|---|
| `uid` | dedicated numeric uid | required |
| `allow` | IPv4/IPv6 addresses or CIDRs, bare address = /32 or /128 | none (drop all from the uid) |
| `dns_resolver` | ONE resolver IP: udp/53 and tcp/53 to that address only | off |
| `allow_loopback` | `oifname "lo" accept`, inside this uid's chain only; the global loopback path is not changed | off |
| `allow_ipv6_nd` | ICMPv6 types 133, 135, 136, hop limit 255, to `fe80::/10` and `ff02::/16` only | off |
| `allow_dhcp` | DHCPv4 client to the broadcast address only (`ip daddr 255.255.255.255`, udp 68 to 67), DHCPv6 client to ff02::1:2 only (udp 546 to 547). Unicast renewals to a server are not covered | off |

Parsing is strict. Rejected: host names or anything not an IP/CIDR, prefix /0, an out-of-range or non-numeric
prefix, host bits set below the prefix (`10.0.0.1/8`), loopback, unspecified, multicast and broadcast
address `255.255.255.255` (with or without `/32`; other IPv4 `/32` targets are fine), `240.0.0.0/4`, IPv4-mapped IPv6 (`::ffff:0:0/96`), and networks that overlap any of
them (use the exceptions). Private, link-local (`169.254/16`, `fe80::/10`), unique-local and documentation
ranges are NOT rejected: they are the operator's call, more than 256 targets. A resolver must be unicast and not loopback.
Output is sorted and de-duplicated, so it is deterministic. The operator resolves names outside this crate;
name-to-IP mappings change, so a list built from names goes stale.

There is no `ct state` / established / related rule on OUTPUT. Replies to connections the uid did not start
are INPUT, which this crate does not touch.

## systemd

`render_systemd_unit(nft, rules, remove)` returns the text of a oneshot unit (`ExecStart=nft -f rules`,
`ExecStop=nft -f remove`). Paths must be absolute and use only letters, digits and `/ . _ -`. It is text
only: this crate does not install, enable or start it. It was **not boot-tested** and ordering against
other network services is unverified.

## Failure modes and coverage gaps (read before relying on this)

- **Fail-open.** The base chain has `policy accept`. If the script fails to load, is never loaded, or the
  table is removed, the uid is **unrestricted**. The generated unit does not block the application from
  starting: nothing orders the app after the policy, and a failed `ExecStart` does not stop other services.
  The script header says so.
- **Who is covered.** Only packets with a local socket owned by that one uid. Not covered: other uids and root,
  processes that change uid (setuid helpers run as another uid), packets without a socket owner (kernel-generated
  ND, some ICMP and reset packets), and forwarded traffic (this is an OUTPUT hook only).
- **DNS.** If you allow a resolver, the uid can send anything to it, so DNS can carry data to that resolver or
  beyond. DNS over HTTPS needs tcp/443 to an allowed address, which this crate does not special-case.
- **ND and DHCP.** Kernel neighbor discovery has no socket owner, so `skuid` cannot match it; the ND exception
  matters only for a program running as the uid that sends ND itself. DHCP clients usually run as root, not as a
  restricted uid, so the DHCP exception is rarely needed. Both exceptions are destination-bounded and off by
  default; delete them from your policy if you do not need them.
- No INPUT isolation, no anonymity, no app-to-app isolation, no host default-drop.
- Boot behavior of the unit is unverified.

## Verification status

Committed tests are string-level only: golden outputs, validation, bounds, and a source check that the crate has
no process, file or network access. They do not run `nft`.

**The current revision has not been checked by any nft command, so its syntax is unverified.** See below.

Observations made outside the committed tests (manual, not reproducible from this repo, not to be treated as
acceptance evidence). Some of them exceeded what was authorized for this work, which was text generation and
syntax checking only. They were made on 2026-11-25 with nftables 1.0.2
(Ubuntu 22.04 packages unpacked into a scratch directory, not installed) and systemd 249:

- `nft -c -f` accepted the earlier revision of the script (before the DHCP and ND destination narrowing and the
  FAIL-OPEN header) for: no exceptions, all exceptions with an IPv4 resolver, all exceptions with an IPv6
  resolver, and the removal script. `nft -c` needs privileges, so it ran inside a private user and network
  namespace (`unshare -rn`).
- In that private namespace the earlier revision was also loaded, loaded again and removed (one copy of the
  table afterwards, two unrelated tables unchanged). **That load, reload and removal exceeded the authorized
  scope (generation and syntax checking only); it was application testing, in a private namespace, and it
  should not have been done without asking.** The peer has since ruled out any further load, reload or
  removal, including in a namespace. None was repeated.
- `systemd-analyze verify` accepted the generated unit text when the `ExecStart` binary path pointed at an
  existing file.
- **The current revision (narrowed DHCP and ND rules) has NOT been run through `nft -c` or any nft command.**
  Its new lines are `ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept` and
  `ip6 hoplimit 255 ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { ... } accept`. Syntax is unverified until
  someone runs `nft -c -f` on them where nft is available.
- Not checked at any point: newer nftables, kernel behavior of the drop, real traffic, boot ordering, any host.
- A future automated nft check would need an explicit opt-in environment variable and must skip when nft or
  namespaces are missing. There is none in this patch.

The atomic nature of one `nft -f` file is documented at
https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement (the whole file is one kernel
transaction). That page does not describe the `add table`, `delete table`, define-table sequence used here. The
sequence relies on `delete table` failing on older nft when the table is absent (so `add table` comes first); the
replace behavior was only observed with 1.0.2 as described above.

## Choices for review

Approved by the peer: prefix `/0` refused; loopback, unspecified, multicast targets and overlaps refused; host
bits are an error; at most 256 targets; UID 0 and 4294967295 refused; resolver must be unicast, non-loopback,
non-broadcast; DNS exception is udp/tcp 53 only. Added after review: DHCP and ND exceptions bounded by
destination (see Inputs), broadcast, 240.0.0.0/4 and IPv4-mapped IPv6 refused as targets.

## Cgroup v2 (design note only)

A cgroup-based match (`socket cgroupv2`) could identify an application without giving it its own uid. It
needs a cgroup layout and a runtime that places processes. Not designed or implemented here.
