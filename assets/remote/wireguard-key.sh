#!/usr/bin/env bash
set -euo pipefail
python3 -c "$VPS_WIREGUARD_PROGRAM" key
printf '%s\n' VPSDEPLOY_WIREGUARD_KEY_READY
