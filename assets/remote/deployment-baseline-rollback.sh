#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_BASELINE_DIR:?}"
: "${VPS_PARAM_ADMIN_USER:?}"
root='/root/vps-deploy-transaction-baselines'
baseline="$(readlink -f "$VPS_PARAM_BASELINE_DIR")"
[[ "$(dirname "$baseline")" == "$root" ]]
[[ "$(basename "$baseline")" =~ ^[a-f0-9]{32}$ ]]
[[ -f "$baseline/baseline.complete" && -f "$baseline/files.tar.gz" ]]
[[ "$(cat "$baseline/admin.name")" == "$VPS_PARAM_ADMIN_USER" ]]
network_managed="${VPS_PARAM_RESTORE_NETWORK:-$(cat "$baseline/network.managed" 2>/dev/null || printf true)}"
[[ "$network_managed" == true || "$network_managed" == false ]]

# Check ownership before changing SSH, services or files. The initial audit
# required an empty ruleset; only this deployment's inet/filter may be removed.
firewall_owned=false
nft_was_enabled="$(awk -F '\t' '$1 == "nftables.service" { print $3; exit }' "$baseline/services.tsv")"
nft_was_active="$(awk -F '\t' '$1 == "nftables.service" { print $4; exit }' "$baseline/services.tsv")"
override=/run/systemd/system/nftables.service.d/90-mxh-deployment-restore.conf
if [[ -f "$baseline/firewall-state.json" ]]; then
  [[ -f "$baseline/firewall-tools.sh" && ! -L "$baseline/firewall-tools.sh" ]]
  # shellcheck disable=SC1091
  source "$baseline/firewall-tools.sh"
  mxh_firewall deployment-check "$baseline"
  [[ "$nft_was_active" == true || ( ! -e "$override" && ! -L "$override" && "$(readlink -m "$override")" == "$override" ) ]]
  firewall_owned=true
  mxh_firewall deployment-clear "$baseline"
elif command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
  echo 'Firewall ownership is unavailable; deployment rollback needs explicit review.' >&2; exit 1
fi

for service in xray.service sing-box.service sing-box-anytls.service nginx.service komari-agent.service mxh-certbot-renew.timer vps-deploy-ssh-rollback.timer vps-deploy-ssh-rollback.service; do
  systemctl disable --now "$service" >/dev/null 2>&1 || true
done
rm -f /usr/local/sbin/vps-deploy-ssh-rollback /run/vps-deploy-ssh-cutover-ok

# Historical baselines listed both TLS roots. Remove/restore only the owned
# lineages even for those snapshots; never clear another site's certificate.
tls_paths=(etc/mxh-tls/anytls etc/mxh-tls/reality-target
  etc/letsencrypt/cloudflare.ini etc/letsencrypt/cloudflare.ini.mxh-source
  etc/letsencrypt/mxh-anytls-cloudflare.ini etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source
  etc/letsencrypt/archive/mxh-anytls etc/letsencrypt/live/mxh-anytls etc/letsencrypt/renewal/mxh-anytls.conf
  etc/letsencrypt/archive/mxh-reality-target etc/letsencrypt/live/mxh-reality-target etc/letsencrypt/renewal/mxh-reality-target.conf)
if grep -Eq '^etc/(letsencrypt|mxh-tls)$' "$baseline/paths.list" "$baseline/absent.list"; then
  for path in "${tls_paths[@]}"; do rm -rf -- "/${path:?}"; done
fi
while IFS= read -r path; do
  [[ -n "$path" && "$path" != /* && "$path" != *'..'* ]]
  [[ "$path" != etc/letsencrypt && "$path" != etc/mxh-tls ]] || continue
  [[ "$path" != etc/nftables.conf || "$firewall_owned" == true ]] || continue
  [[ "$path" != etc/sysctl.d/99-mxh-vps-deploy.conf || "$network_managed" == true ]] || continue
  rm -rf -- "/${path:?}"
done < "$baseline/paths.list"
while IFS= read -r path; do
  [[ -n "$path" && "$path" != /* && "$path" != *'..'* ]]
  [[ "$path" != etc/letsencrypt && "$path" != etc/mxh-tls ]] || continue
  [[ "$path" != etc/nftables.conf || "$firewall_owned" == true ]] || continue
  [[ "$path" != etc/sysctl.d/99-mxh-vps-deploy.conf || "$network_managed" == true ]] || continue
  rm -rf -- "/${path:?}"
done < "$baseline/absent.list"
members="$(mktemp)"
tar -tzpf "$baseline/files.tar.gz" | while IFS= read -r member; do
  case "$member" in
    etc/nftables.conf) [[ "$firewall_owned" == true ]] || continue;;
    etc/sysctl.d/99-mxh-vps-deploy.conf) [[ "$network_managed" == true ]] || continue;;
    etc/letsencrypt/cloudflare.ini|etc/letsencrypt/cloudflare.ini.mxh-source|etc/letsencrypt/mxh-anytls-cloudflare.ini|etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source|etc/letsencrypt/archive/mxh-anytls/*|etc/letsencrypt/live/mxh-anytls/*|etc/letsencrypt/renewal/mxh-anytls.conf|etc/letsencrypt/archive/mxh-reality-target/*|etc/letsencrypt/live/mxh-reality-target/*|etc/letsencrypt/renewal/mxh-reality-target.conf|etc/mxh-tls/anytls/*|etc/mxh-tls/reality-target/*) ;;
    etc/letsencrypt|etc/letsencrypt/*|etc/mxh-tls|etc/mxh-tls/*) continue;;
  esac
  printf '%s\n' "$member"
done > "$members"
tar --numeric-owner --no-recursion -xzpf "$baseline/files.tar.gz" -C / -T "$members"
rm -f "$members"

if [[ "$(cat "$baseline/admin.present")" == 'false' ]]; then
  if id "$VPS_PARAM_ADMIN_USER" >/dev/null 2>&1; then userdel -r "$VPS_PARAM_ADMIN_USER" >/dev/null 2>&1 || userdel "$VPS_PARAM_ADMIN_USER"; fi
else
  shadow_hash="$(cut -d: -f2 "$baseline/admin.shadow")"
  usermod -p "$shadow_hash" "$VPS_PARAM_ADMIN_USER"
  groups="$(tr ' ' ',' < "$baseline/admin.groups")"
  usermod -G "$groups" "$VPS_PARAM_ADMIN_USER"
fi
for account in sing-box sing-box-anytls komari-agent; do
  if [[ "$(cat "$baseline/user-${account}.present")" == 'false' ]] && id "$account" >/dev/null 2>&1; then
    userdel "$account" >/dev/null 2>&1 || true
    getent group "$account" >/dev/null 2>&1 && groupdel "$account" >/dev/null 2>&1 || true
  fi
done

systemctl daemon-reload
while IFS=$'\t' read -r key value; do
  [[ "$network_managed" == true ]] || break
  [[ -n "$key" ]] || continue
  sysctl -w "$key=$value" >/dev/null 2>&1 || true
done < "$baseline/sysctl.tsv"

while IFS=$'\t' read -r service existed enabled active; do
  [[ "$existed" == 'true' ]] || continue
  [[ "$service" != 'ssh.service' && "$service" != 'ssh.socket' ]] || continue
  [[ "$service" != nftables.service ]] || continue
  if [[ "$enabled" == 'true' ]]; then systemctl enable "$service" >/dev/null 2>&1 || true; else systemctl disable "$service" >/dev/null 2>&1 || true; fi
  if [[ "$active" == 'true' ]]; then systemctl start "$service" >/dev/null 2>&1 || true; else systemctl stop "$service" >/dev/null 2>&1 || true; fi
done < "$baseline/services.tsv"
# Stopping Debian's nftables unit normally flushes all tables. Clear only its
# active state with a temporary runtime override, preserving unrelated tables.
if [[ "$firewall_owned" == true && "$nft_was_active" != true ]]; then
  install -d -m 0755 "$(dirname "$override")"
  printf '[Service]\nExecStop=\n' > "$override"
  cleanup_nft_override(){ rm -f "$override"; systemctl daemon-reload; }
  trap cleanup_nft_override EXIT
  systemctl daemon-reload
  systemctl stop nftables.service
  cleanup_nft_override; trap - EXIT
fi
if [[ "$firewall_owned" == true ]]; then
  if [[ "$nft_was_enabled" == true ]]; then systemctl enable nftables.service >/dev/null; else systemctl disable nftables.service >/dev/null; fi
fi
sshd -t
for service in ssh.service ssh.socket; do
  row="$(awk -F '\t' -v name="$service" '$1 == name { print; exit }' "$baseline/services.tsv")"
  [[ -n "$row" ]] || continue
  IFS=$'\t' read -r _ existed enabled active <<<"$row"
  [[ "$existed" == 'true' ]] || continue
  if [[ "$enabled" == 'true' ]]; then systemctl enable "$service" >/dev/null 2>&1 || true; else systemctl disable "$service" >/dev/null 2>&1 || true; fi
  [[ "$active" == 'true' ]] && systemctl start "$service" >/dev/null 2>&1 || true
done
systemctl reload ssh.service >/dev/null 2>&1 || systemctl reload sshd.service >/dev/null 2>&1 || true
for service in ssh.service ssh.socket; do
  row="$(awk -F '\t' -v name="$service" '$1 == name { print; exit }' "$baseline/services.tsv")"
  [[ -n "$row" ]] || continue
  IFS=$'\t' read -r _ existed enabled active <<<"$row"
  [[ "$existed" == 'true' && "$active" == 'false' ]] && systemctl stop "$service" >/dev/null 2>&1 || true
done
dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u > "$baseline/packages.after"
comm -13 "$baseline/packages.before" "$baseline/packages.after" > "$baseline/packages.preserved"
package_residue_count="$(wc -l < "$baseline/packages.preserved" | tr -d ' ')"
date -u +%FT%TZ > "$baseline/rollback.complete"
printf 'VPSDEPLOY_PACKAGE_RESIDUE_COUNT_B64=%s\n' "$(printf '%s' "$package_residue_count" | base64 | tr -d '\n')"
printf '%s\n' 'VPSDEPLOY_DEPLOYMENT_ROLLBACK_OK'
