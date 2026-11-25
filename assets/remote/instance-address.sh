#!/usr/bin/env bash
set -euo pipefail
python3 - <<'MAY_ADDRESS_LAUNCHER'
raise RuntimeError('Address launcher must be rendered by the reviewed application.')
MAY_ADDRESS_LAUNCHER
printf '%s\n' VPSDEPLOY_ADDRESS_OK
