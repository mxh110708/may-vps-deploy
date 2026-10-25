#!/usr/bin/env bash
set -euo pipefail
action="${VPS_PARAM_ACTION:-Status}"
owner=/var/lib/may-vps-deploy/transaction.owner
current=''
[[ ! -f "$owner" ]] || current="$(cat "$owner")"
if [[ "$action" == 'Status' && -n "${VPS_PARAM_EXPECTED_BACKUP:-}" ]]; then
  [[ "$VPS_PARAM_EXPECTED_BACKUP" =~ ^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/(protocol-lifecycle|ssh-maintenance)$ ]]
  current="$VPS_PARAM_EXPECTED_BACKUP"
fi
if [[ "$action" == 'VerifyUnowned' ]]; then
  exec 9>/var/lib/may-vps-deploy/transaction.lock
  flock -n 9 || exit 1
  [[ ! -e "$owner" ]]
  for unit in mxh-protocol-migration-rollback.timer mxh-protocol-migration-rollback.service mxh-ssh-maintenance-rollback.timer mxh-ssh-maintenance-rollback.service; do
    ! systemctl is-active --quiet "$unit" || exit 1
  done
  printf '%s\n' 'VPSDEPLOY_UNOWNED_TRANSACTION_CLEAR'
  exit 0
elif [[ "$action" == 'ReleaseUnarmed' ]]; then
  : "${VPS_PARAM_EXPECTED_BACKUP:?}"
  exec 9>/var/lib/may-vps-deploy/transaction.lock
  flock -n 9 || exit 1
  [[ -n "$current" && "$current" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
  [[ "$(cat "$owner")" == "$current" ]]
  [[ ! -f "$current/transaction-armed" ]]
  if systemctl is-active --quiet mxh-protocol-migration-rollback.timer; then exit 1; fi
  if systemctl is-active --quiet mxh-protocol-migration-rollback.service; then exit 1; fi
  if systemctl is-active --quiet mxh-ssh-maintenance-rollback.timer; then exit 1; fi
  if systemctl is-active --quiet mxh-ssh-maintenance-rollback.service; then exit 1; fi
  rm -f "$owner"
  current=''
elif [[ "$action" != 'Status' ]]; then exit 1; fi
phase=None
if [[ -n "$current" ]]; then
  phase=Preparing
  [[ ! -f "$current/transaction-armed" ]] || phase=Armed
  [[ ! -f "$current/rollback-executed" ]] || phase=RolledBack
  [[ ! -f "$current/transaction-committed" ]] || phase=Committed
  [[ ! -f "$current/tcp-chain-compensating" ]] || phase=Compensating
  [[ ! -f "$current/tcp-chain-rollback-complete" ]] || phase=ChainRolledBack
fi
printf 'VPSDEPLOY_TRANSACTION_BACKUP_B64=%s\n' "$(printf '%s' "$current" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_TRANSACTION_PHASE_B64=%s\n' "$(printf '%s' "$phase" | base64 | tr -d '\n')"
control_task=''
if [[ -n "$current" && -f "$current/control-task-id" ]]; then
  control_task="$(cat "$current/control-task-id")"
  [[ "$control_task" =~ ^[a-f0-9]{32}$ ]]
fi
printf 'VPSDEPLOY_CONTROL_TASK_ID_B64=%s\n' "$(printf '%s' "$control_task" | base64 | tr -d '\n')"
