#!/usr/bin/env bash
set -euo pipefail

config='/etc/ssh/sshd_config.d/00-00-mxh-import-key-only.conf'
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/existing-import-ssh"
install -d -m 0700 "$backup_dir"
if [[ -f "$config" ]]; then cp -a "$config" "$backup_dir/"; fi
had_existing='false'
[[ -f "$backup_dir/$(basename "$config")" ]] && had_existing='true'
committed='false'
cleanup() {
  local status="$?"
  if [[ "$status" -ne 0 && "$committed" != 'true' ]]; then
    set +e
    if [[ "$had_existing" == 'true' ]]; then
      cp -a "$backup_dir/$(basename "$config")" "$config"
    else
      rm -f "$config"
    fi
    sshd -t && systemctl reload ssh.service
  fi
  exit "$status"
}
trap cleanup EXIT

cat > "$config" <<'EOF'
# Managed by May VPS Deploy existing-instance import.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
chmod 0644 "$config"
sshd -t
systemctl reload ssh.service
sleep 1
effective="$(sshd -T)"
grep -qx 'pubkeyauthentication yes' <<<"$effective"
grep -qx 'passwordauthentication no' <<<"$effective"
grep -qx 'kbdinteractiveauthentication no' <<<"$effective"
grep -Eq '^permitrootlogin (prohibit-password|without-password)$' <<<"$effective"
committed='true'
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
printf '%s\n' 'VPSDEPLOY_IMPORT_SSH_KEYONLY_OK'
