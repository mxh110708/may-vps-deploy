#!/usr/bin/env bash
set -euo pipefail
: "${VPS_MAY_MONITOR_PROGRAM:?}"
python3 -c "$VPS_MAY_MONITOR_PROGRAM"
