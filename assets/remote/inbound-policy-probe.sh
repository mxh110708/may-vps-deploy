#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_INBOUND_DOCUMENT_FILE:?}"
python3 -c "$VPS_INBOUND_POLICY_PROGRAM"
