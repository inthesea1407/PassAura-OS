#!/usr/bin/env bash
# CI only: checks pos-netpolicy output against the real nft binary and a real kernel,
# inside a throwaway network namespace. Needs sudo, nft, python3, ip, setpriv. Changes nothing outside the namespace.
set -euo pipefail
dir="${1:?rule dir}"
uid="${2:?uid}"
ns=posnp

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# 1. Syntax: every generated file must pass `nft -c`.
for f in deny lo full full6 remove; do
  sudo nft -c -f "$dir/$f.nft" || fail "nft -c rejected $f.nft"
  pass "nft -c accepts $f.nft"
done

# 2. Behaviour inside a namespace.
sudo ip netns add $ns
trap 'sudo ip netns del $ns 2>/dev/null || true; sudo pkill -f "posnp-listener" 2>/dev/null || true' EXIT
sudo ip netns exec $ns ip link set lo up
sudo ip netns exec $ns nft -c -f "$dir/deny.nft" || fail "nft -c inside namespace"

# listener on 127.0.0.1:18080 inside the namespace
sudo ip netns exec $ns python3 -c '
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",18080)); s.listen(16)  # posnp-listener
while True:
    c,_=s.accept(); c.close()
' &
sleep 1

try_connect() { # $1 = uid or root
  local runner=(sudo ip netns exec $ns)
  if [ "$1" != root ]; then runner+=(setpriv --reuid="$1" --regid="$1" --clear-groups); fi
  "${runner[@]}" python3 -c '
import socket,sys
s=socket.socket(); s.settimeout(2)
try:
    s.connect(("127.0.0.1",18080)); sys.exit(0)
except Exception:
    sys.exit(1)'
}

try_connect "$uid" || fail "baseline: uid cannot connect before any rules"
pass "baseline connect works"

sudo ip netns exec $ns nft -f "$dir/deny.nft"
if try_connect "$uid"; then fail "deny.nft: restricted uid still connected"; fi
pass "deny.nft blocks the restricted uid"
try_connect root || fail "deny.nft: root was blocked (rule is not uid-specific)"
pass "deny.nft leaves root alone"
try_connect 65534 || fail "deny.nft: another uid was blocked"
pass "deny.nft leaves other uids alone"

sudo ip netns exec $ns nft -f "$dir/lo.nft"
try_connect "$uid" || fail "lo.nft: loopback exception did not allow"
pass "lo.nft allows loopback for the uid"

sudo ip netns exec $ns nft -f "$dir/full.nft"
try_connect "$uid" || fail "full.nft: loopback exception did not allow"
pass "full.nft loads for real and allows loopback"
sudo ip netns exec $ns nft -f "$dir/full6.nft"
pass "full6.nft loads for real"

sudo ip netns exec $ns nft -f "$dir/deny.nft"
sudo ip netns exec $ns nft -f "$dir/remove.nft"
try_connect "$uid" || fail "remove.nft: still blocked after removal"
pass "remove.nft removes the table"
sudo ip netns exec $ns nft -f "$dir/remove.nft"
pass "remove.nft is harmless when the table is absent"
sudo ip netns exec $ns nft list ruleset | grep -q passaura_netpolicy && fail "table still present" || pass "no leftover table"
echo "netpolicy-live: all checks passed (namespace only, Linux runner kernel)"
