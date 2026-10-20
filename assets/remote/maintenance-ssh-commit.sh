#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_BACKUP:?}"
exec 9>/var/lib/may-vps-deploy/transaction.lock
flock -n 9 || exit 1
[[ "$(cat /var/lib/may-vps-deploy/transaction.owner)" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
[[ ! -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" ]]
: "${VPS_PARAM_NEW_PRIMARY:?}"; : "${VPS_PARAM_NEW_RESCUE:?}"; : "${VPS_PARAM_NEW_PUBLIC_KEY:?}"
old_public="${VPS_PARAM_OLD_PUBLIC_KEY:-}"; admin="${VPS_PARAM_ADMIN_USER:-root}"
managed=/etc/ssh/sshd_config.d/00-00-local-access.conf
cat > "$managed" <<EOF
Port ${VPS_PARAM_NEW_PRIMARY}
Port ${VPS_PARAM_NEW_RESCUE}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
if [[ -n "$old_public" && "$old_public" != "$VPS_PARAM_NEW_PUBLIC_KEY" ]]; then
  old_type="$(awk '{print $1}' <<< "$old_public")"
  old_blob="$(awk '{print $2}' <<< "$old_public")"
  for user in root "$admin"; do
    id "$user" >/dev/null 2>&1 || continue
    home="$(getent passwd "$user" | cut -d: -f6)"; file="$home/.ssh/authorized_keys"
    if [[ -f "$file" ]]; then
      awk -v type="$old_type" -v blob="$old_blob" '!($1 == type && $2 == blob)' "$file" > "$file.tmp"
      chown --reference="$file" "$file.tmp"; chmod --reference="$file" "$file.tmp"; mv "$file.tmp" "$file"
    fi
  done
fi
sshd -t; systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
# Keep the rollback timer armed until the controller has saved local state and final firewall.
printf '%s\n' 'VPSDEPLOY_SSH_MAINTENANCE_COMMITTED'
