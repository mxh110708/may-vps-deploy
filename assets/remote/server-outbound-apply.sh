#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_CONFIG_SHA256:?}"
: "${VPS_PARAM_CONFIG_JSON:?}"
[[ "$VPS_PARAM_EXPECTED_CONFIG_SHA256" =~ ^[0-9a-f]{64}$ ]]
: "${VPS_PARAM_ROLE:?}"
case "$VPS_PARAM_ROLE" in
  RealityEntry) config=/usr/local/etc/xray/config.json; binary=/usr/local/bin/xray; service=xray.service; directory=/usr/local/etc/xray; parent=/usr/local/etc ;;
  AnyTlsEntry) config=/etc/sing-box-anytls/config.json; binary=/usr/local/bin/sing-box-anytls; service=sing-box-anytls.service; directory=/etc/sing-box-anytls; parent=/etc ;;
  *) exit 1 ;;
esac
for path in "$parent" "$directory" "$config" "$binary"; do
  [[ ! -L "$path" ]] || { printf '%s\n' 'Server outbound path is linked.' >&2; exit 1; }
done
[[ -f "$config" && -s "$config" && -x "$binary" ]]
systemctl is-active --quiet "$service"
systemctl is-enabled --quiet "$service"
exec_start="$(systemctl show "$service" -p ExecStart --value)"
if [[ "$VPS_PARAM_ROLE" == RealityEntry ]]; then
  [[ "$exec_start" == *"$binary run -config $config"* ]]
else
  [[ "$exec_start" == *"$binary run -c $config"* ]]
fi
printf '%s  %s\n' "$VPS_PARAM_EXPECTED_CONFIG_SHA256" "$config" | sha256sum --check --status
tmp="$(mktemp "$directory/.may-outbound-XXXXXXXX.json")"
trap 'rm -f -- "$tmp"' EXIT
chmod 0600 "$tmp"
printf '%s' "$VPS_PARAM_CONFIG_JSON" > "$tmp"
if [[ "$VPS_PARAM_ROLE" == RealityEntry ]]; then
  "$binary" run -test -config "$tmp" >/dev/null 2>&1
  user="$(systemctl show "$service" -p User --value)"; user="${user:-root}"; group="$(id -gn "$user")"
else
  "$binary" check -c "$tmp" >/dev/null 2>&1
  group=sing-box-anytls
fi
chown "root:$group" "$tmp"
chmod 0640 "$tmp"
# Configuration validation can take time; check drift again immediately before replacement.
[[ ! -L "$config" && -f "$config" ]]
printf '%s  %s\n' "$VPS_PARAM_EXPECTED_CONFIG_SHA256" "$config" | sha256sum --check --status
mv -T -- "$tmp" "$config"
systemctl restart "$service"
systemctl is-active --quiet "$service"
printf '%s\n' 'VPSDEPLOY_SERVER_OUTBOUND_APPLIED'
