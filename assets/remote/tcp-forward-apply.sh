#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_TRANSACTION:?}"
python3 -c "$VPS_TCP_FORWARD_PROGRAM" apply
printf '%s\n' 'VPSDEPLOY_TCP_FORWARD_APPLIED'
