#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_COMPONENT:?}"
: "${VPS_COMPONENT_RELEASE_PROGRAM:?}"
printf '%s\n' "$VPS_COMPONENT_RELEASE_PROGRAM" | python3 -
