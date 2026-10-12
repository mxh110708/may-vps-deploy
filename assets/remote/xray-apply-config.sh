#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_CONFIG_JSON:?}"
: "${VPS_PARAM_PRIMARY_PORT:?}"
: "${VPS_PARAM_TARGET:?}"
backup_port="${VPS_PARAM_BACKUP_PORT:-}"

config='/usr/local/etc/xray/config.json'
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/xray"
install -d -m 0700 "$backup_dir"
if [[ -f "$config" ]]; then cp -a "$config" "$backup_dir/config.json"; fi

temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT
printf '%s' "$VPS_PARAM_CONFIG_JSON" > "$temporary"
python3 -m json.tool "$temporary" >/dev/null
service_user="$(systemctl show xray.service -p User --value)"
service_user="${service_user:-root}"
service_group="$(id -gn "$service_user")"
install -o root -g "$service_group" -m 0640 "$temporary" "$config"

/usr/local/bin/xray run -test -config "$config"
install -d -o "$service_user" -g "$service_group" -m 0750 /var/log/xray
touch /var/log/xray/error.log
chown "$service_user:$service_group" /var/log/xray/error.log
chmod 0640 /var/log/xray/error.log

systemctl restart xray.service
systemctl is-active --quiet xray.service
sleep 1
ports=("$VPS_PARAM_PRIMARY_PORT")
if [[ -n "$backup_port" && "$backup_port" != 0 ]]; then ports+=("$backup_port"); fi
for port in "${ports[@]}"; do
  grep -q xray <<< "$(ss -H -lntp "sport = :$port")" || { echo "Xray is not listening on $port" >&2; exit 1; }
done

if command -v timeout >/dev/null 2>&1; then
  timeout 30 /usr/local/bin/xray tls ping "$VPS_PARAM_TARGET" >/dev/null 2>&1 || true
fi
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
