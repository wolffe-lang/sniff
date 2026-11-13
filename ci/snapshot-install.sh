#!/bin/sh
set -eu
snapshot=$1
shift
exec apt-get --snapshot "$snapshot" install -y --no-install-recommends "$@"
