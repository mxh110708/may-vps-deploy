#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_SOURCE_ROLE:?}"
: "${VPS_PARAM_EXPECTED_BACKUP:?}"
case "$VPS_PARAM_SOURCE_ROLE" in RealityEntry|AnyTlsEntry|ShadowsocksLanding|MonitorOnly) ;; *) exit 1 ;; esac
[[ "$VPS_PARAM_EXPECTED_BACKUP" =~ ^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$ ]]
if [[ -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" && ! -f /var/lib/may-vps-deploy/transaction.owner ]]; then
  exec 9>/var/lib/may-vps-deploy/transaction.lock
  flock -n 9 || exit 1
  [[ ! -e /var/lib/may-vps-deploy/transaction.owner ]]
  if systemctl is-active --quiet mxh-protocol-migration-rollback.timer; then
    unit=/etc/systemd/system/mxh-protocol-migration-rollback.service
    [[ -f "$unit" && ! -L "$unit" ]]
    grep -Fxq "ExecStart=/usr/local/libexec/mxh-protocol-migration-rollback $VPS_PARAM_EXPECTED_BACKUP --transaction" "$unit"
    ! systemctl is-active --quiet mxh-protocol-migration-rollback.service
    systemctl disable --now mxh-protocol-migration-rollback.timer >/dev/null
    ! systemctl is-active --quiet mxh-protocol-migration-rollback.timer
  fi
  printf '%s\n' 'VPSDEPLOY_MIGRATION_ROLLBACK_OK'; exit 0
fi
[[ "$(cat /var/lib/may-vps-deploy/transaction.owner)" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
systemctl start mxh-protocol-migration-rollback.service
! systemctl is-failed --quiet mxh-protocol-migration-rollback.service
[[ -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" ]]
systemctl disable --now mxh-protocol-migration-rollback.timer >/dev/null 2>&1 || true
printf '%s\n' 'VPSDEPLOY_MIGRATION_ROLLBACK_OK'
