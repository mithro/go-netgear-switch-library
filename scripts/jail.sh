#!/bin/sh
# Run a command under CPU+memory limits so builds/tests/fakes can't
# overwhelm the host. systemd scope when available, ulimit fallback.
set -eu
if command -v systemd-run >/dev/null 2>&1 && \
   systemd-run --user --scope -q true >/dev/null 2>&1; then
    exec systemd-run --user --scope -q \
        -p MemoryMax=4G -p MemorySwapMax=0 -p CPUQuota=400% -- "$@"
fi
ulimit -v 4194304 || true
exec "$@"
