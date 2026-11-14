#!/usr/bin/env bash
set -euo pipefail
if [[ "${VPS_PARAM_PROBE_GROUPS:-false}" == true ]]; then
    python3 -c "$VPS_TCP_FORWARD_PROGRAM" probe-groups
else
    python3 -c "$VPS_TCP_FORWARD_PROGRAM" read
fi
printf '%s\n' 'VPSDEPLOY_TCP_FORWARD_READ'
