#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_OLD_PORTS:?}"
: "${VPS_PARAM_NEW_PRIMARY:?}"
: "${VPS_PARAM_NEW_RESCUE:?}"
: "${VPS_PARAM_NEW_PUBLIC_KEY:?}"
: "${VPS_PARAM_ADMIN_USER:?}"
for port in ${VPS_PARAM_OLD_PORTS//,/ } "$VPS_PARAM_NEW_PRIMARY" "$VPS_PARAM_NEW_RESCUE"; do
  [[ "$port" =~ ^[0-9]+$ ]] && ((port>=1 && port<=65535))
done
[[ "$VPS_PARAM_NEW_PUBLIC_KEY" == ssh-ed25519\ * ]]
[[ "$VPS_PARAM_ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]
command -v flock >/dev/null || { echo 'Missing flock (util-linux); install it before starting maintenance.' >&2; exit 1; }
install -d -m 0700 /var/lib/mxh-vps-deploy
exec 9>/var/lib/mxh-vps-deploy/transaction.lock
flock -n 9 || exit 1
[[ ! -f /var/lib/mxh-vps-deploy/transaction.owner ]]
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.timer; then exit 1; fi
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.service; then exit 1; fi
if systemctl is-active --quiet mxh-protocol-migration-rollback.timer; then exit 1; fi
if systemctl is-active --quiet mxh-protocol-migration-rollback.service; then exit 1; fi
firewall_required="${VPS_PARAM_FIREWALL_REQUIRED:-false}"
[[ "$firewall_required" == true || "$firewall_required" == false ]]
if [[ "$firewall_required" == true ]]; then mxh_firewall check; fi
stamp="$(date -u +%Y%m%d-%H%M%S)"; backup="/root/vps-deploy-backups/${stamp}/ssh-maintenance"
[[ ! -e "$backup" ]]
install -d -m 0700 "$backup"
printf '%s\n' "$backup" > /var/lib/mxh-vps-deploy/transaction.owner
chmod 0600 /var/lib/mxh-vps-deploy/transaction.owner
cp -a /etc/ssh "$backup/etc-ssh"
if [[ "$firewall_required" == true ]]; then
  mxh_firewall snapshot "$backup/firewall-state.json"
  declare -f mxh_firewall > "$backup/firewall-tools.sh"
  cp -a /etc/nftables.conf "$backup/nftables.conf"
fi
cp -a /root/.ssh/authorized_keys "$backup/root-authorized_keys"
if id "$VPS_PARAM_ADMIN_USER" >/dev/null 2>&1; then
  home="$(getent passwd "$VPS_PARAM_ADMIN_USER" | cut -d: -f6)"
  [[ ! -f "$home/.ssh/authorized_keys" ]] || cp -a "$home/.ssh/authorized_keys" "$backup/admin-authorized_keys"
fi
cat > "$backup/rollback" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec 9>/var/lib/mxh-vps-deploy/transaction.lock
flock -w 30 9 || exit 1
[[ ! -f '$backup/transaction-committed' ]] || exit 0
[[ "\$(cat /var/lib/mxh-vps-deploy/transaction.owner)" == '$backup' ]]
if [[ -f '$backup/nftables.conf' ]]; then
  [[ -f '$backup/firewall-state.json' && -f '$backup/firewall-tools.sh' ]] || { echo 'Legacy SSH firewall recovery needs ownership review.' >&2; exit 1; }
  # shellcheck disable=SC1091
  source '$backup/firewall-tools.sh'
  mxh_firewall restore '$backup/firewall-state.json' '$backup/nftables.conf' '$backup/firewall.restore'
fi
rm -rf /etc/ssh
cp -a '$backup/etc-ssh' /etc/ssh
cp -a '$backup/root-authorized_keys' /root/.ssh/authorized_keys
if [[ -f '$backup/admin-authorized_keys' ]]; then
  home="\$(getent passwd '$VPS_PARAM_ADMIN_USER' | cut -d: -f6)"
  cp -a '$backup/admin-authorized_keys' "\$home/.ssh/authorized_keys"
fi
sshd -t
systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
if [[ -f '$backup/firewall.restore' ]]; then install -m 0755 '$backup/firewall.restore' /etc/nftables.conf; nft -c -f /etc/nftables.conf; nft -f /etc/nftables.conf; fi
date -u +%FT%TZ > '$backup/rollback-executed'
rm -f /var/lib/mxh-vps-deploy/transaction.owner
EOF
chmod 0700 "$backup/rollback"
cat > /etc/systemd/system/mxh-ssh-maintenance-rollback.service <<EOF
[Service]
Type=oneshot
ExecStart=$backup/rollback
EOF
cat > /etc/systemd/system/mxh-ssh-maintenance-rollback.timer <<'EOF'
[Timer]
OnActiveSec=10min
AccuracySec=1s
Unit=mxh-ssh-maintenance-rollback.service
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
printf '%s\n' "$(( $(date +%s) + 600 ))" > "$backup/deadline-epoch"
systemctl enable --now mxh-ssh-maintenance-rollback.timer >/dev/null
date -u +%FT%TZ > "$backup/transaction-armed"

for user in root "$VPS_PARAM_ADMIN_USER"; do
  id "$user" >/dev/null 2>&1 || continue
  home="$(getent passwd "$user" | cut -d: -f6)"
  install -d -o "$user" -g "$(id -gn "$user")" -m 0700 "$home/.ssh"
  touch "$home/.ssh/authorized_keys"; chown "$user:$(id -gn "$user")" "$home/.ssh/authorized_keys"; chmod 0600 "$home/.ssh/authorized_keys"
  if ! grep -qxF "$VPS_PARAM_NEW_PUBLIC_KEY" "$home/.ssh/authorized_keys"; then
    [[ ! -s "$home/.ssh/authorized_keys" ]] || printf '\n' >> "$home/.ssh/authorized_keys"
    printf '%s\n' "$VPS_PARAM_NEW_PUBLIC_KEY" >> "$home/.ssh/authorized_keys"
  fi
done
managed=/etc/ssh/sshd_config.d/00-00-local-access.conf
install -d -m 0755 /etc/ssh/sshd_config.d
{
  for port in ${VPS_PARAM_OLD_PORTS//,/ } "$VPS_PARAM_NEW_PRIMARY" "$VPS_PARAM_NEW_RESCUE"; do printf '%s\n' "$port"; done |
    sort -nu | sed 's/^/Port /'
  printf '%s\n' 'PubkeyAuthentication yes' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin prohibit-password'
} > "$managed"
chmod 0644 "$managed"; sshd -t
systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup" | base64 | tr -d '\n')"
printf '%s\n' 'VPSDEPLOY_SSH_MAINTENANCE_STAGED'
