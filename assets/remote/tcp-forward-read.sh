#!/usr/bin/env bash
set -euo pipefail
python3 -c "$VPS_TCP_FORWARD_PROGRAM" read
printf '%s\n' 'VPSDEPLOY_TCP_FORWARD_READ'
