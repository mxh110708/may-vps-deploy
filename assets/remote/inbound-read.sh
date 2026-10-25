#!/usr/bin/env bash
set -euo pipefail
python3 -c "$VPS_INBOUND_PROGRAM" read
if [[ -n "${VPS_PARAM_INBOUND_DOCUMENT_FILE:-}" ]]; then python3 -c "$VPS_INBOUND_PROGRAM" preflight; fi
printf '%s\n' VPSDEPLOY_INBOUND_READ
