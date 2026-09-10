#!/usr/bin/env bash
# Runs dist_tls.escript inside the official erlang:<version> images on Docker's
# default bridge network (a network namespace of its own: no host firewall).
# Usage: ./run-docker.sh 27 28 29
set -euo pipefail
cd "$(dirname "$0")"
[ $# -gt 0 ] || { echo "usage: $0 <otp-version>..." >&2; exit 2; }
mkdir -p results
for V in "$@"; do
  OUT="results/otp$V-docker-bridge.txt"
  echo "== erlang:$V (bridge) -> $OUT"
  docker run --rm -v "$PWD/dist_tls.escript:/dist_tls.escript:ro" "erlang:$V" escript /dist_tls.escript 2>&1 | tee "$OUT"
done
