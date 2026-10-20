#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_BACKUP:?}"
exec 9>/var/lib/may-vps-deploy/transaction.lock
flock -n 9 || exit 1
if [[ -f "$VPS_PARAM_EXPECTED_BACKUP/transaction-committed" ]]; then printf '%s\n' 'VPSDEPLOY_SSH_MAINTENANCE_FINALIZED'; exit 0; fi
[[ "$(cat /var/lib/may-vps-deploy/transaction.owner)" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
[[ ! -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" ]]
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.service; then exit 1; fi
systemctl disable --now mxh-ssh-maintenance-rollback.timer >/dev/null
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.timer; then exit 1; fi
date -u +%FT%TZ > "$VPS_PARAM_EXPECTED_BACKUP/transaction-committed"
rm -f /var/lib/may-vps-deploy/transaction.owner
printf '%s\n' 'VPSDEPLOY_SSH_MAINTENANCE_FINALIZED'
