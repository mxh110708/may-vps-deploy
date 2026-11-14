#!/usr/bin/env bash
set -euo pipefail
python3 -c "$VPS_CERTIFICATE_PROGRAM" read
printf '%s\n' VPSDEPLOY_CERTIFICATE_READ
