#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import os
exec(compile(os.environ['VPS_RESOURCE_CERTIFICATES_PROGRAM'], '<resource-certificates>', 'exec'))
PY
