#!/usr/bin/env bash
set -euo pipefail
if ! command -v wg >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  timeout 60 apt-get -o DPkg::Lock::Timeout=20 update -qq
  timeout 90 apt-get -o DPkg::Lock::Timeout=20 install -y --no-install-recommends wireguard-tools
fi
command -v wg >/dev/null
printf '%s\n' VPSDEPLOY_WIREGUARD_TOOLS_READY
