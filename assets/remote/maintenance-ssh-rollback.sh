#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_BACKUP:?}"
if [[ -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" && ! -f /var/lib/may-vps-deploy/transaction.owner ]]; then
  printf '%s\n' 'VPSDEPLOY_SSH_MAINTENANCE_ROLLED_BACK'; exit 0
fi
[[ "$(cat /var/lib/may-vps-deploy/transaction.owner)" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
systemctl start mxh-ssh-maintenance-rollback.service
[[ -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" ]]
systemctl disable --now mxh-ssh-maintenance-rollback.timer >/dev/null
printf '%s\n' 'VPSDEPLOY_SSH_MAINTENANCE_ROLLED_BACK'
