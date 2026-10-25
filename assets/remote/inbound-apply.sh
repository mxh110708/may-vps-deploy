#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_TRANSACTION:?}"
python3 -c "$VPS_INBOUND_PROGRAM" apply
printf '%s\n' VPSDEPLOY_INBOUND_APPLIED
