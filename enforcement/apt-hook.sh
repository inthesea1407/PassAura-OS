#!/bin/sh
# Real install-time gate for Debian/Ubuntu. Install as:
#   /usr/local/lib/pos/apt-hook.sh   (needs /usr/local/bin/pos-gate)
#   /etc/apt/apt.conf.d/99pos-gate:
#     DPkg::Pre-Install-Pkgs { "/usr/local/lib/pos/apt-hook.sh"; };
#     DPkg::Pre-Install-Pkgs::Version "3";
# apt passes the .deb paths on stdin (protocol version 3: lines start with
# "...", the .deb path appears as the line's file field). We read each .deb
# itself, so the decision uses what the package really installs.
set -u
rc=0
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
while read -r line; do
  deb=$(printf '%s\n' "$line" | grep -o '/[^ ]*\.deb' | head -1)
  # Lines without a .deb path (protocol header, config lines, removals) are not installs.
  [ -n "$deb" ] || continue
  # A .deb that is named but cannot be read must not be waved through: fail closed.
  if [ ! -f "$deb" ]; then
    echo "pos-gate: cannot read $deb, blocking" >&2
    rc=1
    continue
  fi
  name=$(dpkg-deb -f "$deb" Package) && [ -n "$name" ] || {
    echo "pos-gate: cannot read package name of $deb, blocking" >&2
    rc=1
    continue
  }
  dpkg-deb -c "$deb" | awk '{print $NF}' | sed 's#^\./#/#' > "$TMP/files"
  rm -rf "$TMP/x"; mkdir "$TMP/x"; dpkg-deb -x "$deb" "$TMP/x"
  desk=$(find "$TMP/x" -name '*.desktop' 2>/dev/null)
  # shellcheck disable=SC2086
  pos-gate "$name" "$TMP/files" $desk || rc=1
done
exit $rc
