# Local host-layout reports, separate from the macOS pinned-oracle switches.
# Source after gate-steps.sh. The original command still runs; no golden changes.
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
