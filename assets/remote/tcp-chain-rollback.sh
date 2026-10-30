#!/usr/bin/env bash
# Explicit compensation of this chain's snapshot, including a participant whose
# commit acknowledgement was lost. Never use another controller's transaction.
set -euo pipefail
: "${VPS_PARAM_EXPECTED_BACKUP:?}" "${VPS_PARAM_CONTROL_TASK_ID:?}" "${VPS_PARAM_TCP_CHAIN_ID:?}"
backup="$VPS_PARAM_EXPECTED_BACKUP"
[[ "$backup" =~ ^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$ ]]
[[ "$VPS_PARAM_CONTROL_TASK_ID" =~ ^[a-f0-9]{32}$ && "$VPS_PARAM_TCP_CHAIN_ID" =~ ^[a-f0-9]{32}$ ]]
[[ ! -L "$backup" && "$(readlink -f "$backup")" == "$backup" ]]
exec 9>/var/lib/may-vps-deploy/transaction.lock
flock -w 30 9 || exit 1
[[ "$(cat "$backup/control-task-id")" == "$VPS_PARAM_CONTROL_TASK_ID" ]]
[[ "$(cat "$backup/tcp-chain-id")" == "$VPS_PARAM_TCP_CHAIN_ID" ]]
components="$(cat "$backup/components")"
[[ "$components" == TcpForwarding || "$components" == TcpForwarding,Firewall || "$components" == UdpForwarding || "$components" == UdpForwarding,Firewall ]]
for file in tcp-chain-rollback tcp-chain-rollback.sha256; do [[ -f "$backup/$file" && ! -L "$backup/$file" ]]; done
(cd "$backup" && sha256sum -c tcp-chain-rollback.sha256 >/dev/null)
owner=/var/lib/may-vps-deploy/transaction.owner
[[ ! -e "$owner" || "$(cat "$owner")" == "$backup" ]]
# An active timer must belong to this exact snapshot. Do not disable a new one.
for unit in mxh-ssh-maintenance-rollback.timer mxh-ssh-maintenance-rollback.service; do
  ! systemctl is-active --quiet "$unit" || exit 1
done
if systemctl is-active --quiet mxh-protocol-migration-rollback.timer; then
  [[ "$(systemctl show -p ExecStart --value mxh-protocol-migration-rollback.service)" == *"$backup --transaction"* ]]
fi
! systemctl is-active --quiet mxh-protocol-migration-rollback.service || exit 1
if [[ ! -e "$backup/tcp-chain-rollback-complete" ]]; then
  printf '%s\n' "$backup" > "$owner"
  chmod 0600 "$owner"
  touch "$backup/tcp-chain-compensating"
  export VPS_TRANSACTION_LOCK_HELD=true
  bash "$backup/tcp-chain-rollback" "$backup"
  touch "$backup/tcp-chain-rollback-complete"
fi
[[ -f "$backup/rollback-executed" ]]
systemctl disable --now mxh-protocol-migration-rollback.timer >/dev/null 2>&1 || true
! systemctl is-active --quiet mxh-protocol-migration-rollback.timer || exit 1
[[ ! -e "$owner" || "$(cat "$owner")" == "$backup" ]]
rm -f "$owner"
printf '%s\n' VPSDEPLOY_TCP_CHAIN_ROLLED_BACK
