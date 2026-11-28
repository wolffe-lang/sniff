# Ordinary END lines retain the child exit. Explicit report-* leaves retain the original
# command exit on an UNJUDGED line and report only whether collecting that result succeeded.
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

# An explicit local-only list for the two measured host-layout-dependent leaves. No wildcard,
# unknown name or CI override is accepted. Reporting does not turn their output into proof.
host_dependent_validate() {
  local raw=${SNIFF_UNJUDGED_STEPS:-} name seen='|'
  [ -n "$raw" ] || return 0
  if [ "${GITHUB_ACTIONS:-}" = true ]; then
    printf 'FAIL host-dependent-switch reporting is forbidden in hosted CI\n'
    return 2
  fi
  case "$raw" in ,*|*,|*,,*) printf 'FAIL host-dependent-switch malformed list\n'; return 2;; esac
  local -a names
  local IFS=,
  read -r -a names <<< "$raw"
  for name in "${names[@]}"; do
    case "$name" in session-oracle-stable|session-rows) ;;
      *) printf 'FAIL host-dependent-switch unknown leaf %s\n' "$name"; return 2;;
    esac
    case "$seen" in *"|$name|"*) printf 'FAIL host-dependent-switch duplicate leaf %s\n' "$name"; return 2;; esac
    seen="${seen}${name}|"
  done
}

host_dependent_step() {
  host_dependent_validate || return "$?"
  local name=$1 start=$SECONDS rc=0 reported=0
  case ",${SNIFF_UNJUDGED_STEPS:-}," in *",$name,"*) reported=1;; esac
  if [ "$reported" = 0 ]; then step "$@"; return "$?"; fi
  shift
  printf 'START report-%s\n' "$name"
  "$@" > "target/gate/$name.log" 2>&1 || rc=$?
  sed 's/^/  /' "target/gate/$name.log"
  printf '  UNJUDGED %s command-exit=%s: host-dependent output is reported, not judged; hosted CI must judge this leaf.\n' "$name" "$rc"
  local report_rc=0
  [ "$rc" -le 1 ] || report_rc=$rc
  printf 'END report-%s exit=%s secs=%s\n' "$name" "$report_rc" "$((SECONDS-start))"
  return "$report_rc"
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

# The macOS session rows run sniff against signed children and Apple's lldb on a Mac:
# a hosted runner has not been shown to grant task ports, and its lldb is not the pinned one.
live_skip_reason="hosted-ci: the live macOS session rows need task ports for signed children and the pinned Apple lldb; the Mac's local gauntlet record carries this row"
mac_live_step() {
  if oracle_hosted; then
    printf 'SKIP %s reason=%s\n' "$1" "$live_skip_reason"
    return 0
  fi
  step "$@"
}
