#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_SOURCE_ROLE:?}"
: "${VPS_PARAM_TARGET_ROLE:?}"
: "${VPS_PARAM_TIMEOUT_MINUTES:?}"

case "$VPS_PARAM_SOURCE_ROLE" in RealityEntry|AnyTlsEntry|ShadowsocksLanding|MonitorOnly) ;; *) exit 1 ;; esac
case "$VPS_PARAM_TARGET_ROLE" in RealityEntry|AnyTlsEntry|ShadowsocksLanding|MonitorOnly) ;; *) exit 1 ;; esac
[[ "$VPS_PARAM_TIMEOUT_MINUTES" =~ ^[0-9]+$ ]]
(( VPS_PARAM_TIMEOUT_MINUTES >= 5 && VPS_PARAM_TIMEOUT_MINUTES <= 60 ))

command -v flock >/dev/null || { echo 'Missing flock (util-linux); install it before starting maintenance.' >&2; exit 1; }
install -d -m 0700 /var/lib/mxh-vps-deploy
exec 9>/var/lib/mxh-vps-deploy/transaction.lock
flock -n 9 || { echo 'Another transaction command is running.' >&2; exit 1; }
owner=/var/lib/mxh-vps-deploy/transaction.owner
[[ ! -e "$owner" ]] || { echo 'An unfinished transaction exists; inspect and recover it before starting another.' >&2; exit 1; }
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.timer; then exit 1; fi
if systemctl is-active --quiet mxh-ssh-maintenance-rollback.service; then exit 1; fi
if systemctl is-active --quiet mxh-protocol-migration-rollback.timer || systemctl is-active --quiet mxh-protocol-migration-rollback.service; then
  echo 'An existing rollback unit is active; refusing to replace it.' >&2; exit 1
fi
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/protocol-lifecycle"
[[ ! -e "$backup_dir" ]] || { echo 'Snapshot timestamp collision; retry later.' >&2; exit 1; }
install -d -m 0700 "$backup_dir"
if [[ -n "${VPS_PARAM_CONTROL_TASK_ID:-}" ]]; then
  [[ "$VPS_PARAM_CONTROL_TASK_ID" =~ ^[a-f0-9]{32}$ ]]
  printf '%s\n' "$VPS_PARAM_CONTROL_TASK_ID" > "$backup_dir/control-task-id"
fi
components="${VPS_PARAM_COMPONENTS:-Protocols,Network,Firewall}"
IFS=',' read -r -a component_list <<<"$components"
((${#component_list[@]} > 0))
for component in "${component_list[@]}"; do
  case "$component" in Protocols|RealityEntry|AnyTlsEntry|ShadowsocksLanding|TrustedTls|Network|Firewall|KomariAgent|KomariController|Cloudflared) ;; *) echo 'Unsupported transaction component.' >&2; exit 1 ;; esac
done
scope_has(){ [[ ",$components," == *",$1,"* ]]; }
printf '%s\n' "$components" > "$backup_dir/components"
printf '%s\n' "$backup_dir" > "$owner"
chmod 0600 "$owner"
if scope_has Firewall && [[ -f /etc/nftables.conf ]]; then
  mxh_firewall snapshot "$backup_dir/firewall-state.json"
  declare -f mxh_firewall > "$backup_dir/firewall-tools.sh"
  cp -a /etc/nftables.conf "$backup_dir/nftables.conf"
fi
if scope_has Network && [[ -f /etc/sysctl.d/99-mxh-vps-deploy.conf ]]; then
  cp -a /etc/sysctl.d/99-mxh-vps-deploy.conf "$backup_dir/99-mxh-vps-deploy.conf"
elif scope_has Network; then
  touch "$backup_dir/sysctl-config-was-absent"
fi
if scope_has Network && [[ "${VPS_PARAM_NETWORK_SNAPSHOT:-false}" == true ]]; then
  mxh_network snapshot "$backup_dir"
  declare -f mxh_network > "$backup_dir/network-tools.sh"
  chmod 0600 "$backup_dir/network-tools.sh"
fi
printf '%s\n' "$VPS_PARAM_SOURCE_ROLE" > "$backup_dir/source-role"
printf '%s\n' "$VPS_PARAM_TARGET_ROLE" > "$backup_dir/target-role"

service_snapshot() {
  local role="$1" service="$2" binary="$3" config="$4"
  local installed='false' enabled='false' active='false'
  if [[ -x "$binary" && -s "$config" ]] && systemctl cat "$service" >/dev/null 2>&1; then installed='true'; fi
  systemctl is-enabled --quiet "$service" 2>/dev/null && enabled='true'
  systemctl is-active --quiet "$service" 2>/dev/null && active='true'
  printf '%s\n' "$installed" > "$backup_dir/${role}.installed"
  printf '%s\n' "$enabled" > "$backup_dir/${role}.enabled"
  printf '%s\n' "$active" > "$backup_dir/${role}.active"
}
service_snapshot RealityEntry xray.service /usr/local/bin/xray /usr/local/etc/xray/config.json
service_snapshot AnyTlsEntry sing-box-anytls.service /usr/local/bin/sing-box-anytls /etc/sing-box-anytls/config.json
service_snapshot ShadowsocksLanding sing-box.service /usr/local/bin/sing-box /etc/sing-box/config.json
nginx_enabled='false'
nginx_active='false'
systemctl is-enabled --quiet nginx.service 2>/dev/null && nginx_enabled='true'
systemctl is-active --quiet nginx.service 2>/dev/null && nginx_active='true'
printf '%s\n' "$nginx_enabled" > "$backup_dir/NginxRealityTarget.enabled"
printf '%s\n' "$nginx_active" > "$backup_dir/NginxRealityTarget.active"
aux_snapshot() {
  local name="$1" service="$2" unit='false' enabled='false' active='false'
  systemctl cat "$service" >/dev/null 2>&1 && unit='true'
  systemctl is-enabled --quiet "$service" 2>/dev/null && enabled='true'
  systemctl is-active --quiet "$service" 2>/dev/null && active='true'
  printf '%s\n' "$unit" > "$backup_dir/${name}.unit"
  printf '%s\n' "$enabled" > "$backup_dir/${name}.enabled"
  printf '%s\n' "$active" > "$backup_dir/${name}.active"
}
aux_snapshot KomariAgent komari-agent.service
aux_snapshot KomariController komari.service
aux_snapshot Cloudflared cloudflared.service
if scope_has TrustedTls; then
  aux_snapshot TrustedTlsRenew mxh-certbot-renew.timer
  aux_snapshot DistributionCertbotRenew certbot.timer
fi

quiesce_controller="${VPS_PARAM_QUIESCE_KOMARI_CONTROLLER:-false}"
[[ "$quiesce_controller" == true || "$quiesce_controller" == false ]]
if scope_has KomariController; then quiesce_controller=true; fi
[[ "$quiesce_controller" == false ]] || scope_has KomariController
controller_was_active="$(cat "$backup_dir/KomariController.active")"
restart_after_snapshot(){ [[ "$quiesce_controller" == false || "$controller_was_active" == false ]] || systemctl start komari.service; }
if [[ "$quiesce_controller" == true ]]; then
  for directory in /var/lib/komari /opt/komari; do [[ ! -L "$directory" ]] || { echo 'Unsupported symlinked Komari data directory.' >&2; exit 1; }; done
  trap restart_after_snapshot EXIT
  if [[ "$controller_was_active" == true ]]; then systemctl stop komari.service; fi
  ! systemctl is-active --quiet komari.service || { echo 'Controller is still running; consistent snapshot refused.' >&2; exit 1; }
fi

candidate_paths=()
if scope_has Protocols; then candidate_paths+=(
  usr/local/bin/xray usr/local/etc/xray usr/local/share/xray
  etc/systemd/system/xray.service etc/systemd/system/xray@.service etc/systemd/system/xray.service.d
  etc/nginx/sites-available/mxh-reality-target etc/nginx/sites-enabled/mxh-reality-target var/www/mxh-reality-target
  etc/mxh-tls/anytls etc/mxh-tls/reality-target
  etc/letsencrypt/cloudflare.ini etc/letsencrypt/cloudflare.ini.mxh-source
  etc/letsencrypt/mxh-anytls-cloudflare.ini etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source
  etc/letsencrypt/archive/mxh-anytls etc/letsencrypt/live/mxh-anytls etc/letsencrypt/renewal/mxh-anytls.conf
  etc/letsencrypt/archive/mxh-reality-target etc/letsencrypt/live/mxh-reality-target etc/letsencrypt/renewal/mxh-reality-target.conf
  etc/systemd/system/mxh-certbot-renew.timer etc/systemd/system/mxh-certbot-renew.service
  usr/local/libexec/mxh-certbot-dns usr/local/libexec/mxh-certbot-deploy
  usr/local/bin/sing-box-anytls etc/systemd/system/sing-box-anytls.service etc/sing-box-anytls var/lib/sing-box-anytls
  usr/local/bin/sing-box etc/systemd/system/sing-box.service etc/systemd/system/sing-box.service.d etc/sing-box var/lib/sing-box
); fi
if scope_has RealityEntry; then candidate_paths+=(usr/local/bin/xray usr/local/etc/xray usr/local/share/xray etc/systemd/system/xray.service etc/systemd/system/xray@.service etc/systemd/system/xray.service.d); fi
if scope_has AnyTlsEntry; then candidate_paths+=(usr/local/bin/sing-box-anytls etc/systemd/system/sing-box-anytls.service etc/sing-box-anytls var/lib/sing-box-anytls); fi
if scope_has ShadowsocksLanding; then candidate_paths+=(usr/local/bin/sing-box etc/systemd/system/sing-box.service etc/systemd/system/sing-box.service.d etc/sing-box var/lib/sing-box); fi
if scope_has TrustedTls; then candidate_paths+=(etc/systemd/system/mxh-certbot-renew.timer etc/systemd/system/mxh-certbot-renew.service usr/local/libexec/mxh-certbot-dns usr/local/libexec/mxh-certbot-deploy etc/letsencrypt/cloudflare.ini.mxh-source etc/letsencrypt/mxh-anytls-cloudflare.ini etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source etc/letsencrypt/archive/mxh-anytls etc/letsencrypt/live/mxh-anytls etc/letsencrypt/renewal/mxh-anytls.conf etc/mxh-tls/anytls); fi
if scope_has KomariAgent; then candidate_paths+=(usr/local/bin/komari-agent etc/komari-agent etc/systemd/system/komari-agent.service var/lib/komari-agent); fi
if scope_has KomariController; then candidate_paths+=(usr/local/bin/komari usr/bin/komari opt/komari var/lib/komari etc/systemd/system/komari.service); fi
if scope_has Cloudflared; then candidate_paths+=(usr/local/bin/cloudflared usr/bin/cloudflared etc/systemd/system/cloudflared.service etc/cloudflared); fi
existing_paths=()
for relative in "${candidate_paths[@]}"; do
  if [[ -e "/$relative" || -L "/$relative" ]]; then existing_paths+=("$relative"); fi
done
printf '%s\n' "${existing_paths[@]}" > "$backup_dir/existing-paths"
if (( ${#existing_paths[@]} > 0 )); then
  tar --numeric-owner -czpf "$backup_dir/protocol-files.tar.gz" -C / "${existing_paths[@]}"
else
  # A monitor-only host can have no files in the selected maintenance scope.
  # Still produce a valid archive for download and the common restore path.
  tar --numeric-owner -czpf "$backup_dir/protocol-files.tar.gz" -C / --files-from /dev/null
fi
if [[ "$quiesce_controller" == true ]]; then
  touch "$backup_dir/KomariController.quiesced"
  restart_after_snapshot; trap - EXIT
fi
chmod -R go-rwx "$backup_dir"

install -d -m 0755 /usr/local/libexec
cat > /usr/local/libexec/mxh-protocol-migration-rollback <<'ROLLBACK'
#!/usr/bin/env bash
set -euo pipefail
backup_dir="$1"
components="$(cat "$backup_dir/components" 2>/dev/null || printf '%s' 'Protocols,Network,Firewall,KomariAgent,KomariController,Cloudflared')"
protocol_only=false
if [[ "${2:-}" == '--protocol-only' ]]; then
  components='Protocols,Network,Firewall'; protocol_only=true
fi
if [[ "${2:-}" == '--protocol-files-only' ]]; then
  [[ ",$components," == *',Protocols,'* ]] || exit 1
  components='Protocols'; protocol_only=true
fi
scope_has(){ [[ ",$components," == *",$1,"* ]]; }
if [[ "${VPS_TRANSACTION_LOCK_HELD:-false}" != true ]]; then
  exec 9>/var/lib/mxh-vps-deploy/transaction.lock
  flock -w 30 9 || exit 1
fi
if [[ "${2:-}" == '--transaction' ]]; then
  [[ ! -f "$backup_dir/transaction-committed" ]] || exit 0
  [[ "$(cat /var/lib/mxh-vps-deploy/transaction.owner)" == "$backup_dir" ]]
fi
if scope_has Firewall && [[ -f "$backup_dir/nftables.conf" ]]; then
  [[ -f "$backup_dir/firewall-state.json" ]] || { echo 'Legacy firewall snapshot needs explicit ownership review.' >&2; exit 1; }
  # shellcheck disable=SC1091
  source "$backup_dir/firewall-tools.sh"
  mxh_firewall restore "$backup_dir/firewall-state.json" "$backup_dir/nftables.conf" "$backup_dir/firewall.restore"
  nft -c -f "$backup_dir/firewall.restore"
fi
if scope_has Network && [[ -f "$backup_dir/network-state.json" ]]; then
  python3 - "$backup_dir/network-state.json" <<'NETWORK_VERSION'
import json, sys
if json.load(open(sys.argv[1])).get('Version') != 2:
    raise SystemExit('Legacy network snapshot needs explicit ownership review.')
NETWORK_VERSION
fi

cleanup_role() {
  case "$1" in
    RealityEntry)
      rm -f /usr/local/bin/xray /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
      rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/systemd/system/xray.service.d
      if scope_has Protocols; then
        rm -f /etc/nginx/sites-enabled/mxh-reality-target /etc/nginx/sites-available/mxh-reality-target
        rm -rf /var/www/mxh-reality-target
      fi
      ;;
    AnyTlsEntry)
      rm -f /usr/local/bin/sing-box-anytls /etc/systemd/system/sing-box-anytls.service
      rm -rf /etc/sing-box-anytls /var/lib/sing-box-anytls
      ;;
    ShadowsocksLanding)
      rm -f /usr/local/bin/sing-box /etc/systemd/system/sing-box.service
      rm -rf /etc/systemd/system/sing-box.service.d /etc/sing-box /var/lib/sing-box
      ;;
  esac
}

for role in RealityEntry AnyTlsEntry ShadowsocksLanding; do
  if ! scope_has Protocols && ! scope_has "$role"; then continue; fi
  case "$role" in RealityEntry) service=xray.service ;; AnyTlsEntry) service=sing-box-anytls.service ;; ShadowsocksLanding) service=sing-box.service ;; esac
  systemctl disable --now "$service" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$service"; then echo 'Protocol service did not stop; rollback refused.' >&2; exit 1; fi
  if [[ "$(cat "$backup_dir/${role}.installed")" == 'false' ]]; then cleanup_role "$role"; fi
done
if scope_has TrustedTls; then
  systemctl stop mxh-certbot-renew.timer mxh-certbot-renew.service >/dev/null 2>&1 || true
  for relative in etc/systemd/system/mxh-certbot-renew.timer etc/systemd/system/mxh-certbot-renew.service usr/local/libexec/mxh-certbot-dns usr/local/libexec/mxh-certbot-deploy etc/letsencrypt/cloudflare.ini.mxh-source etc/letsencrypt/mxh-anytls-cloudflare.ini etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source etc/letsencrypt/archive/mxh-anytls etc/letsencrypt/live/mxh-anytls etc/letsencrypt/renewal/mxh-anytls.conf etc/mxh-tls/anytls; do
    if ! grep -Fxq "$relative" "$backup_dir/existing-paths"; then rm -rf -- "/${relative:?}"; fi
  done
fi
if scope_has KomariAgent; then
  systemctl stop komari-agent.service >/dev/null 2>&1 || true
  ! systemctl is-active --quiet komari-agent.service || exit 1
fi
if scope_has Cloudflared; then
  systemctl stop cloudflared.service >/dev/null 2>&1 || true
  ! systemctl is-active --quiet cloudflared.service || exit 1
fi
if [[ -f "$backup_dir/protocol-files.tar.gz" ]]; then
  if scope_has KomariController; then
    systemctl stop komari.service >/dev/null 2>&1 || true
    ! systemctl is-active --quiet komari.service || { echo 'Controller is still running; database restore refused.' >&2; exit 1; }
    failed_dir="$(mktemp -d "$backup_dir/failed-komari-data-XXXXXXXX")"
    for directory in /var/lib/komari /opt/komari; do
      [[ -d "$directory" ]] || continue
      [[ ! -L "$directory" && "$(readlink -f "$directory")" == "$directory" ]] || exit 1
      leaf="${directory#/}"; mv "$directory" "$failed_dir/${leaf//\//-}"
    done
  fi
  # Old snapshots captured all of /etc/letsencrypt. Filter their TLS members
  # too, so another site's current lineage and ACME account cannot be reverted.
  tls_member_allowed(){
    case "$1" in
      etc/letsencrypt/cloudflare.ini|etc/letsencrypt/cloudflare.ini.mxh-source|etc/letsencrypt/mxh-anytls-cloudflare.ini|etc/letsencrypt/mxh-anytls-cloudflare.ini.mxh-source|etc/letsencrypt/archive/mxh-anytls/*|etc/letsencrypt/live/mxh-anytls/*|etc/letsencrypt/renewal/mxh-anytls.conf|etc/letsencrypt/archive/mxh-reality-target/*|etc/letsencrypt/live/mxh-reality-target/*|etc/letsencrypt/renewal/mxh-reality-target.conf|etc/mxh-tls/anytls/*|etc/mxh-tls/reality-target/*) return 0;;
      etc/letsencrypt|etc/letsencrypt/*|etc/mxh-tls|etc/mxh-tls/*) return 1;;
      *) return 0;;
    esac
  }
  if [[ "$protocol_only" == true ]]; then
    # Historical snapshots also contain monitoring data, which is outside a protocol restore.
    members="$(mktemp)"
    tar -tzpf "$backup_dir/protocol-files.tar.gz" | while IFS= read -r member; do
      tls_member_allowed "$member" || continue
      case "$member" in
        usr/local/bin/xray|usr/local/bin/sing-box|usr/local/bin/sing-box-anytls|usr/local/etc/xray/*|usr/local/share/xray/*|etc/sing-box/*|etc/sing-box-anytls/*|var/lib/sing-box/*|var/lib/sing-box-anytls/*|etc/mxh-tls/*|etc/letsencrypt/*|var/www/mxh-reality-target/*|etc/nginx/sites-available/mxh-reality-target|etc/nginx/sites-enabled/mxh-reality-target|etc/systemd/system/xray.service|etc/systemd/system/xray@.service|etc/systemd/system/xray.service.d/*|etc/systemd/system/sing-box.service|etc/systemd/system/sing-box.service.d/*|etc/systemd/system/sing-box-anytls.service|etc/systemd/system/mxh-certbot-renew.timer|etc/systemd/system/mxh-certbot-renew.service|usr/local/libexec/mxh-certbot-dns|usr/local/libexec/mxh-certbot-deploy)
          [[ "$member" != /* && "/$member/" != *'/../'* ]] || exit 1
          printf '%s\n' "$member" ;;
      esac
    done > "$members"
    tar --numeric-owner --no-recursion -xzpf "$backup_dir/protocol-files.tar.gz" -C / -T "$members"
    rm -f "$members"
  else
    members="$(mktemp)"
    tar -tzpf "$backup_dir/protocol-files.tar.gz" | while IFS= read -r member; do tls_member_allowed "$member" && printf '%s\n' "$member" || true; done > "$members"
    tar --numeric-owner --no-recursion -xzpf "$backup_dir/protocol-files.tar.gz" -C / -T "$members"
    rm -f "$members"
  fi
fi
if scope_has Firewall && [[ -f "$backup_dir/nftables.conf" ]]; then
  [[ -f "$backup_dir/firewall-state.json" ]] || { echo 'Legacy firewall snapshot needs manual ownership review.' >&2; exit 1; }
  mxh_firewall restore "$backup_dir/firewall-state.json" "$backup_dir/nftables.conf" "$backup_dir/firewall.restore"
  install -m 0755 "$backup_dir/firewall.restore" /etc/nftables.conf
  nft -c -f /etc/nftables.conf
  nft -f /etc/nftables.conf
fi
if scope_has Network; then
  if [[ -f "$backup_dir/network-state.json" ]]; then
    [[ ! -L "$backup_dir/network-state.json" && -f "$backup_dir/network-tools.sh" && ! -L "$backup_dir/network-tools.sh" ]]
    # shellcheck disable=SC1091
    source "$backup_dir/network-tools.sh"
    mxh_network restore "$backup_dir"
  else
    if [[ -f "$backup_dir/99-mxh-vps-deploy.conf" ]]; then
      cp -a "$backup_dir/99-mxh-vps-deploy.conf" /etc/sysctl.d/99-mxh-vps-deploy.conf
    elif [[ -f "$backup_dir/sysctl-config-was-absent" ]]; then
      rm -f /etc/sysctl.d/99-mxh-vps-deploy.conf
    fi
    sysctl --system >/dev/null
  fi
fi
systemctl daemon-reload

restore_service() {
  local role="$1" service="$2" enabled active
  enabled="$(cat "$backup_dir/${role}.enabled")"
  active="$(cat "$backup_dir/${role}.active")"
  if [[ "$enabled" == 'true' ]]; then systemctl enable "$service" >/dev/null; else systemctl disable "$service" >/dev/null 2>&1 || true; fi
  if [[ "$active" == 'true' ]]; then systemctl start "$service"; else systemctl stop "$service" >/dev/null 2>&1 || true; fi
  if [[ "$enabled" == 'true' ]]; then systemctl is-enabled --quiet "$service"; else ! systemctl is-enabled --quiet "$service" 2>/dev/null; fi
  if [[ "$active" == 'true' ]]; then systemctl is-active --quiet "$service"; else ! systemctl is-active --quiet "$service" 2>/dev/null; fi
}
if scope_has Protocols; then
  restore_service RealityEntry xray.service
  restore_service AnyTlsEntry sing-box-anytls.service
  restore_service ShadowsocksLanding sing-box.service
fi
if ! scope_has Protocols; then
  if scope_has RealityEntry; then restore_service RealityEntry xray.service; fi
  if scope_has AnyTlsEntry; then restore_service AnyTlsEntry sing-box-anytls.service; fi
  if scope_has ShadowsocksLanding; then restore_service ShadowsocksLanding sing-box.service; fi
fi
if scope_has TrustedTls; then
  restore_service TrustedTlsRenew mxh-certbot-renew.timer
  restore_service DistributionCertbotRenew certbot.timer
fi
if scope_has Protocols && command -v nginx >/dev/null 2>&1; then
  nginx_enabled="$(cat "$backup_dir/NginxRealityTarget.enabled")"
  nginx_active="$(cat "$backup_dir/NginxRealityTarget.active")"
  if [[ "$nginx_enabled" == 'true' ]]; then systemctl enable nginx.service >/dev/null; else systemctl disable nginx.service >/dev/null 2>&1 || true; fi
  if [[ "$nginx_active" == 'true' ]]; then
    nginx -t
    systemctl reload-or-restart nginx.service
  else
    systemctl stop nginx.service >/dev/null 2>&1 || true
  fi
fi
restore_aux() {
  local name="$1" service="$2" unit enabled active
  unit="$(cat "$backup_dir/${name}.unit")"; enabled="$(cat "$backup_dir/${name}.enabled")"; active="$(cat "$backup_dir/${name}.active")"
  if [[ "$unit" == 'false' ]]; then
    systemctl disable --now "$service" >/dev/null 2>&1 || true
    local paths=() relative
    case "$name" in
      KomariAgent) paths=(usr/local/bin/komari-agent etc/systemd/system/komari-agent.service etc/komari-agent var/lib/komari-agent) ;;
      KomariController) paths=(usr/local/bin/komari usr/bin/komari etc/systemd/system/komari.service opt/komari var/lib/komari) ;;
      Cloudflared) paths=(usr/local/bin/cloudflared usr/bin/cloudflared etc/systemd/system/cloudflared.service etc/cloudflared) ;;
    esac
    for relative in "${paths[@]}"; do
      if [[ -f "$backup_dir/existing-paths" ]] && grep -Fxq "$relative" "$backup_dir/existing-paths"; then continue; fi
      rm -rf -- "/${relative:?}"
    done
    systemctl daemon-reload
    return
  fi
  if [[ "$enabled" == 'true' ]]; then systemctl enable "$service" >/dev/null; else systemctl disable "$service" >/dev/null 2>&1 || true; fi
  if [[ "$active" == 'true' ]]; then systemctl start "$service"; else systemctl stop "$service" >/dev/null 2>&1 || true; fi
}
if scope_has KomariAgent; then restore_aux KomariAgent komari-agent.service; fi
if scope_has KomariController; then restore_aux KomariController komari.service; fi
if scope_has Cloudflared; then restore_aux Cloudflared cloudflared.service; fi
date -u +%FT%TZ > "$backup_dir/rollback-executed"
if [[ "${2:-}" == '--transaction' ]]; then
  rm -f /var/lib/mxh-vps-deploy/transaction.owner
  systemctl disable --now mxh-protocol-migration-rollback.timer >/dev/null 2>&1 || true
  ! systemctl is-active --quiet mxh-protocol-migration-rollback.timer || exit 1
fi
ROLLBACK
chmod 0750 /usr/local/libexec/mxh-protocol-migration-rollback

cat > /etc/systemd/system/mxh-protocol-migration-rollback.service <<EOF
[Unit]
Description=Rollback an unconfirmed MXH protocol lifecycle change
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/mxh-protocol-migration-rollback $backup_dir --transaction
Restart=on-failure
RestartSec=5s
EOF
cat > /etc/systemd/system/mxh-protocol-migration-rollback.timer <<EOF
[Unit]
Description=Rollback timer for an unconfirmed MXH protocol lifecycle change

[Timer]
OnActiveSec=${VPS_PARAM_TIMEOUT_MINUTES}min
AccuracySec=1s
Unit=mxh-protocol-migration-rollback.service

[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/mxh-protocol-migration-rollback.service \
  /etc/systemd/system/mxh-protocol-migration-rollback.timer
printf '%s\n' "$(( $(date +%s) + VPS_PARAM_TIMEOUT_MINUTES * 60 ))" > "$backup_dir/deadline-epoch"
systemctl daemon-reload
systemctl enable --now mxh-protocol-migration-rollback.timer >/dev/null
systemctl is-active --quiet mxh-protocol-migration-rollback.timer
date -u +%FT%TZ > "$backup_dir/transaction-armed"
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
printf '%s\n' 'VPSDEPLOY_MIGRATION_ROLLBACK_ARMED'
