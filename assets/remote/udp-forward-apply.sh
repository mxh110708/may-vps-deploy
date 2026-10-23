#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_TRANSACTION:?}"
python3 -c "$VPS_UDP_FORWARD_PROGRAM" apply
echo VPSDEPLOY_UDP_FORWARD_APPLIED
