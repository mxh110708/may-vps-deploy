#!/usr/bin/env bash
set -euo pipefail
printf '%s\n%s\n' "$VPS_BBR_PROGRAM" "$VPS_KERNEL_PROGRAM" | python3 - Status
