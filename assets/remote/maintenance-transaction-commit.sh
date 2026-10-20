#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_BACKUP:?}"
exec 9>/var/lib/may-vps-deploy/transaction.lock
flock -n 9 || exit 1
if [[ -f "$VPS_PARAM_EXPECTED_BACKUP/transaction-committed" ]]; then printf '%s\n' 'VPSDEPLOY_MAINTENANCE_COMMITTED'; exit 0; fi
[[ "$(cat /var/lib/may-vps-deploy/transaction.owner)" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
[[ ! -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" ]]
if [[ -f "$VPS_PARAM_EXPECTED_BACKUP/deadline-epoch" ]]; then
  deadline="$(cat "$VPS_PARAM_EXPECTED_BACKUP/deadline-epoch")"
  [[ "$deadline" =~ ^[0-9]+$ && "$(date +%s)" -lt "$deadline" ]] || { echo 'Rollback deadline passed; commit refused.' >&2; exit 1; }
fi
if systemctl is-active --quiet mxh-protocol-migration-rollback.service; then exit 1; fi
systemctl stop mxh-protocol-migration-rollback.timer >/dev/null 2>&1 || true
systemctl disable mxh-protocol-migration-rollback.timer >/dev/null 2>&1 || true
systemctl is-active --quiet mxh-protocol-migration-rollback.timer 2>/dev/null && exit 1 || true
date -u +%FT%TZ > "$VPS_PARAM_EXPECTED_BACKUP/transaction-committed"
rm -f /var/lib/may-vps-deploy/transaction.owner
printf '%s\n' 'VPSDEPLOY_MAINTENANCE_COMMITTED'
