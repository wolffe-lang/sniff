#!/usr/bin/env bash
# build-static-sniff.sh WOLF OUT: sniff as the static ET_EXEC file PAX loads (wolf has no --static:
# it links through the first cc on PATH, so a cc that adds -static goes first). Checked with readelf.
set -euo pipefail
wolf=$1 out=$2
shim=$(dirname "$out")/static-cc
mkdir -p "$shim"
printf '#!/bin/sh\nexec %s -static "$@"\n' "$(command -v cc)" > "$shim/cc"
chmod +x "$shim/cc"
PATH="$shim:$PATH" "$wolf" build --release --no-cache src/main.lu -o "$out"
readelf -hW "$out" | grep -Eq 'Type: +EXEC'
! readelf -lW "$out" | grep -q INTERP
echo "PASS pax-sniff-static $(wc -c < "$out") bytes"
