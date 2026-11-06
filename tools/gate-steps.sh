# Step helpers sourced by tools/gate. Every END is a real child exit.
step() {
  local name=$1 start=$SECONDS rc=0
  shift
  printf 'START %s\n' "$name"
  "$@" > "target/gate/$name.log" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    sed 's/^/  /' "target/gate/$name.log"
  else
    awk '/^FAIL / {print; next} {print "  " $0}' "target/gate/$name.log"
  fi
  printf 'END %s exit=%s secs=%s\n' "$name" "$rc" "$((SECONDS-start))"
  return "$rc"
}

# One explicit switch, set only by the hosted CI macOS job: no hosted runner
# image carries the pinned macOS oracle binaries. With it, on macOS only, the
# oracle rows print SKIP by name and run nothing; without it they run and
# their pins refuse exactly as before. Nothing here inspects the host.
oracle_skip_reason="hosted-ci: no hosted macOS runner image carries the pinned Apple LLVM 21.0.0 llvm-nm and llvm-dwarfdump binaries (by sha256); the Mac's local gauntlet record carries this row"
oracle_dependent_reason="hosted-ci: consumes only the skipped live-transcript row; the Mac's local gauntlet record carries this row"
oracle_hosted() {
  [ "${mode:-}" = macos ] && [ "${SNIFF_HOSTED_MACOS_CI:-}" = 1 ]
}
oracle_step() {
  if oracle_hosted; then
    printf 'SKIP %s reason=%s\n' "$1" "$oracle_skip_reason"
    return 0
  fi
  step "$@"
}
oracle_dependent_step() {
  if oracle_hosted; then
    printf 'SKIP %s reason=%s\n' "$1" "$oracle_dependent_reason"
    return 0
  fi
  step "$@"
}
