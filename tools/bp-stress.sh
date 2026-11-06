#!/usr/bin/env bash
# bp-stress.sh SNIFF FIXTURES WORK [RUNS]: a breakpoint hit must never be lost.
# Each run skips 9,999 hits of `tick` and continues; the count must read 10000.
# One miss in RUNS (default 200, split over the C and wolf hit loops) fails the step.
set -u
sniff=$1 fx=$2 work=$3 runs=${4:-200}
mkdir -p "$work"
printf 'break tick\nignore 1 9999\nrun\ninfo breakpoints\ncontinue\n' > "$work/stress.cmd"
miss=0 n=0
while [ "$n" -lt "$runs" ]; do
  for w in c/hits/clang-O0/prog wolf/hits/wolf-debug/prog; do
    [ "$n" -ge "$runs" ] && break
    n=$((n+1))
    "$sniff" -batch -x "$work/stress.cmd" "$fx/$w" > "$work/stress.out" 2>&1
    if ! grep -q 'already hit 10000 times' "$work/stress.out"; then
      miss=$((miss+1))
      echo "MISS run=$n $w: $(grep -o 'already hit [0-9]* times' "$work/stress.out")"
    fi
  done
done
echo "bp-stress: misses=$miss runs=$runs"
[ "$miss" -eq 0 ]
