#!/usr/bin/env bash
set -euo pipefail
config='/etc/sysctl.d/99-mxh-vps-deploy.conf'
[[ ! -L "$config" && ( ! -e "$config" || -f "$config" ) ]]
if [[ -e "$config" ]]; then grep -q '^# Managed by May VPS Deploy\.' "$config" || { echo 'Unmanaged sysctl collision.' >&2; exit 1; }; fi
mxh_network preflight /root/vps-deploy-backups/20000101-000000/protocol-lifecycle
