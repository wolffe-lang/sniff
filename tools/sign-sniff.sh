#!/usr/bin/env bash
# sign-sniff.sh IN OUT: copy the sniff binary IN to OUT and sign OUT ad hoc with the
# debugger entitlement (com.apple.security.cs.debugger), so task_for_pid is granted for
# any non-hardened child, not only those carrying get-task-allow. No identity, no secret,
# no system setting. The unsigned copy IN keeps working for targets that carry get-task-allow.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
[ $# -eq 2 ] || { echo 'usage: sign-sniff.sh IN OUT' >&2; exit 2; }
cp "$1" "$2"
codesign --force --sign - --entitlements "$root/tests/debugger.plist" "$2"
codesign --verify --strict "$2"
codesign -d --entitlements - "$2" 2>&1 | grep -q 'com.apple.security.cs.debugger'
echo "PASS sniff-sign $2"
