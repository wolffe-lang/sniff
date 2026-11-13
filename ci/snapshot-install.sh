#!/bin/sh
set -eu
snapshot=$1
shift
exec apt-get install -y --no-install-recommends "$@"
