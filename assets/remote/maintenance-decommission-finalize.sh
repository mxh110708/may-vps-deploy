#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_CONFIRM:?}"
[[ "$VPS_PARAM_CONFIRM" == 'WIPE-REMOTE-BACKUPS' ]]
install -d -m 0700 /var/lib/may-vps-deploy
exec 9>/var/lib/may-vps-deploy/transaction.lock
flock -n 9 || exit 1
[[ ! -f /var/lib/may-vps-deploy/transaction.owner ]]
if systemctl is-active --quiet mxh-protocol-migration-rollback.timer; then exit 1; fi
if systemctl is-active --quiet mxh-protocol-migration-rollback.service; then exit 1; fi
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.timer; then exit 1; fi
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.service; then exit 1; fi
root=/root/vps-deploy-backups
if [[ -d "$root" ]]; then
  resolved="$(readlink -f "$root")"; [[ "$resolved" == /root/vps-deploy-backups ]]; rm -rf -- "$resolved"
fi
rm -f /etc/systemd/system/mxh-protocol-migration-rollback.timer /etc/systemd/system/mxh-protocol-migration-rollback.service /usr/local/libexec/mxh-protocol-migration-rollback
systemctl daemon-reload
printf '%s\n' 'VPSDEPLOY_DECOMMISSION_FINALIZED'
