#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_TRANSACTION_ID:?}"
: "${VPS_PARAM_ADMIN_USER:?}"
phase='validate-input'
report_failure() {
  local exit_status="$1"
  printf 'VPSDEPLOY_BASELINE_FAILURE_PHASE=%s\n' "$phase" >&2
  exit "$exit_status"
}
trap 'report_failure "$?"' ERR
[[ "$VPS_PARAM_TRANSACTION_ID" =~ ^[a-f0-9]{32}$ ]]
[[ "$VPS_PARAM_ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
network_managed="${VPS_PARAM_NETWORK_MANAGED:-true}"
[[ "$network_managed" == true || "$network_managed" == false ]]

phase='prepare-baseline-directory'
root='/root/vps-deploy-transaction-baselines'
baseline="$root/$VPS_PARAM_TRANSACTION_ID"
install -d -m 0700 "$root"
if [[ -f "$baseline/baseline.complete" ]]; then
  printf 'VPSDEPLOY_BASELINE_DIR_B64=%s\n' "$(printf '%s' "$baseline" | base64 | tr -d '\n')"
  printf '%s\n' 'VPSDEPLOY_DEPLOYMENT_BASELINE_OK'
  exit 0
fi
if [[ -e "$baseline" || -L "$baseline" ]]; then
  resolved_existing="$(readlink -f "$baseline")"
  [[ "$resolved_existing" == "$baseline" ]]
  rm -rf -- "$baseline"
fi
install -d -m 0700 "$baseline"

paths=(
  root/.ssh/authorized_keys
  etc/ssh/sshd_config
  etc/ssh/sshd_config.d
  etc/nftables.conf
  usr/local/bin/xray
  usr/local/etc/xray
  usr/local/share/xray
  etc/systemd/system/xray.service
  etc/systemd/system/xray@.service
  etc/systemd/system/xray.service.d
  usr/local/bin/sing-box
  etc/sing-box
  var/lib/sing-box
  etc/systemd/system/sing-box.service
  etc/systemd/system/sing-box.service.d
  usr/local/bin/sing-box-anytls
  etc/sing-box-anytls
  var/lib/sing-box-anytls
  etc/systemd/system/sing-box-anytls.service
  etc/mxh-tls/anytls
  etc/mxh-tls/reality-target
  etc/letsencrypt/cloudflare.ini
  etc/letsencrypt/cloudflare.ini.mxh-source
  etc/letsencrypt/mxh-anytls-cloudflare.ini
  etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source
  etc/letsencrypt/archive/mxh-anytls
  etc/letsencrypt/live/mxh-anytls
  etc/letsencrypt/renewal/mxh-anytls.conf
  etc/letsencrypt/archive/mxh-reality-target
  etc/letsencrypt/live/mxh-reality-target
  etc/letsencrypt/renewal/mxh-reality-target.conf
  usr/local/libexec/mxh-certbot-dns
  usr/local/libexec/mxh-certbot-deploy
  etc/systemd/system/mxh-certbot-renew.service
  etc/systemd/system/mxh-certbot-renew.timer
  etc/nginx/sites-available/mxh-reality-target
  etc/nginx/sites-enabled/mxh-reality-target
  etc/nginx/sites-enabled/default
  var/www/mxh-reality-target
  var/log/xray
  usr/local/bin/komari-agent
  etc/komari-agent
  var/lib/komari-agent
  etc/systemd/system/komari-agent.service
)
if [[ "$network_managed" == true ]]; then paths+=(etc/sysctl.d/99-mxh-vps-deploy.conf); fi

phase='capture-admin-account'
if id "$VPS_PARAM_ADMIN_USER" >/dev/null 2>&1; then
  printf '%s\n' 'true' > "$baseline/admin.present"
  getent passwd "$VPS_PARAM_ADMIN_USER" > "$baseline/admin.passwd"
  getent shadow "$VPS_PARAM_ADMIN_USER" > "$baseline/admin.shadow"
  id -nG "$VPS_PARAM_ADMIN_USER" > "$baseline/admin.groups"
  admin_home="$(getent passwd "$VPS_PARAM_ADMIN_USER" | cut -d: -f6)"
  [[ "$admin_home" == /* && "$admin_home" != '/' ]] || exit 1
  admin_key="${admin_home#/}/.ssh/authorized_keys"
  paths+=("$admin_key")
else
  printf '%s\n' 'false' > "$baseline/admin.present"
fi

phase='capture-service-accounts'
for account in sing-box sing-box-anytls komari-agent; do
  if id "$account" >/dev/null 2>&1; then printf '%s\n' true; else printf '%s\n' false; fi > "$baseline/user-${account}.present"
done

: > "$baseline/paths.list"
: > "$baseline/absent.list"
phase='inventory-managed-paths'
existing=()
for path in "${paths[@]}"; do
  [[ "$path" != /* && "$path" != *'..'* ]]
  if [[ -e "/$path" || -L "/$path" ]]; then
    printf '%s\n' "$path" >> "$baseline/paths.list"
    existing+=("$path")
  else
    printf '%s\n' "$path" >> "$baseline/absent.list"
  fi
done
phase='archive-managed-paths'
if (( ${#existing[@]} )); then
  tar --numeric-owner -czpf "$baseline/files.tar.gz" -C / "${existing[@]}"
else
  tar --numeric-owner -czpf "$baseline/files.tar.gz" --files-from /dev/null
fi

services=(
  ssh.service ssh.socket nftables.service systemd-timesyncd.service
  xray.service sing-box.service sing-box-anytls.service nginx.service
  certbot.timer mxh-certbot-renew.timer komari-agent.service
)
phase='capture-services'
: > "$baseline/services.tsv"
for service in "${services[@]}"; do
  unit_file="$(systemctl list-unit-files "$service" --no-legend 2>/dev/null || true)"
  if grep -q . <<< "$unit_file"; then exists=true; else exists=false; fi
  if systemctl is-enabled --quiet "$service" 2>/dev/null; then enabled=true; else enabled=false; fi
  if systemctl is-active --quiet "$service" 2>/dev/null; then active=true; else active=false; fi
  printf '%s\t%s\t%s\t%s\n' "$service" "$exists" "$enabled" "$active" >> "$baseline/services.tsv"
done

phase='capture-firewall'
if command -v nft >/dev/null 2>&1; then
  nft list ruleset > "$baseline/nftables.ruleset"
else
  : > "$baseline/nftables.ruleset"
fi
sysctl_keys=(
  net.core.default_qdisc net.ipv4.tcp_congestion_control net.ipv4.tcp_fastopen
  net.ipv4.tcp_mtu_probing net.core.rmem_max net.core.wmem_max
  net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.somaxconn net.ipv4.tcp_max_syn_backlog
)
phase='capture-sysctl'
: > "$baseline/sysctl.tsv"
for key in "${sysctl_keys[@]}"; do
  [[ "$network_managed" == true ]] || break
  value="$(sysctl -n "$key" 2>/dev/null || true)"
  [[ -z "$value" ]] || printf '%s\t%s\n' "$key" "$value" >> "$baseline/sysctl.tsv"
done
phase='capture-packages'
dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u > "$baseline/packages.before"
phase='capture-backup-directories'
if [[ -d /root/vps-deploy-backups ]]; then
  find /root/vps-deploy-backups -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -u > "$baseline/backup-directories.before"
else
  : > "$baseline/backup-directories.before"
fi
phase='finalize-baseline'
printf '%s\n' "$VPS_PARAM_ADMIN_USER" > "$baseline/admin.name"
printf '%s\n' "$network_managed" > "$baseline/network.managed"
date -u +%FT%TZ > "$baseline/baseline.complete"
chmod -R go-rwx "$baseline"

printf 'VPSDEPLOY_BASELINE_DIR_B64=%s\n' "$(printf '%s' "$baseline" | base64 | tr -d '\n')"
printf '%s\n' 'VPSDEPLOY_DEPLOYMENT_BASELINE_OK'
