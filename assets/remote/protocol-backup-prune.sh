#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_KEEP_LATEST:?}"
check_only="${VPS_PARAM_CHECK_ONLY:-false}"
[[ "$VPS_PARAM_KEEP_LATEST" =~ ^[0-9]+$ ]]
(( VPS_PARAM_KEEP_LATEST >= 0 && VPS_PARAM_KEEP_LATEST <= 100 ))
[[ "$check_only" == 'true' || "$check_only" == 'false' ]]

assert_no_transaction(){
  [[ ! -e /var/lib/mxh-vps-deploy/transaction.owner ]] || { echo 'An unfinished transaction protects backups; cleanup refused.' >&2; return 1; }
  for service in mxh-protocol-migration-rollback.timer mxh-protocol-migration-rollback.service mxh-ssh-maintenance-rollback.timer mxh-ssh-maintenance-rollback.service; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then echo 'An active rollback actor protects backups; cleanup refused.' >&2; return 1; fi
  done
}
assert_no_transaction
if [[ "$check_only" == 'true' ]]; then
  printf 'VPSDEPLOY_REMOTE_BACKUPS_REMOVED_B64=%s\n' "$(printf '0' | base64 | tr -d '\n')"
  printf '%s\n' 'VPSDEPLOY_PROTOCOL_BACKUP_PRUNE_OK'
  exit 0
fi

install -d -m 0700 /var/lib/mxh-vps-deploy
exec 9>/var/lib/mxh-vps-deploy/transaction.lock
flock -n 9 || exit 1
assert_no_transaction
root='/root/vps-deploy-backups'
if [[ ! -d "$root" ]]; then
  printf 'VPSDEPLOY_REMOTE_BACKUPS_REMOVED_B64=%s\n' "$(printf '0' | base64 | tr -d '\n')"
  printf '%s\n' 'VPSDEPLOY_PROTOCOL_BACKUP_PRUNE_OK'
  exit 0
fi

mapfile -t candidates < <(find "$root" -mindepth 2 -maxdepth 2 -type d \
  \( -name protocol-lifecycle -o -name protocol-migration \) -printf '%h/%f\n' | sort -r)
removed=0
for index in "${!candidates[@]}"; do
  (( index < VPS_PARAM_KEEP_LATEST )) && continue
  path="${candidates[$index]}"
  resolved="$(readlink -f "$path")"
  parent="$(basename "$(dirname "$resolved")")"
  leaf="$(basename "$resolved")"
  [[ "$resolved" == "$root"/* ]]
  [[ "$parent" =~ ^[0-9]{8}-[0-9]{6}$ ]]
  [[ "$leaf" == 'protocol-lifecycle' || "$leaf" == 'protocol-migration' ]]
  rm -rf -- "$resolved"
  rmdir -- "$(dirname "$resolved")" 2>/dev/null || true
  removed=$((removed + 1))
done

if (( VPS_PARAM_KEEP_LATEST == 0 )); then
  systemctl disable --now mxh-protocol-migration-rollback.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/mxh-protocol-migration-rollback.timer \
    /etc/systemd/system/mxh-protocol-migration-rollback.service \
    /usr/local/libexec/mxh-protocol-migration-rollback
  systemctl daemon-reload
fi

printf 'VPSDEPLOY_REMOTE_BACKUPS_REMOVED_B64=%s\n' "$(printf '%s' "$removed" | base64 | tr -d '\n')"
printf '%s\n' 'VPSDEPLOY_PROTOCOL_BACKUP_PRUNE_OK'
