#!/usr/bin/env bash
set -euo pipefail
python3 -c "$VPS_UDP_FORWARD_PROGRAM" read
echo VPSDEPLOY_UDP_FORWARD_READ
