#!/usr/bin/env bash
set -euo pipefail
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
python3 - "$config" <<'PY'
import base64, hashlib, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 1048576: raise SystemExit('Server config exceeds supported limit.')
raw = path.read_bytes()
config = json.loads(raw)
if not isinstance(config, dict): raise SystemExit('Invalid server config.')
for name, value in [('SERVER_CONFIG', json.dumps(config, separators=(',', ':'))), ('SERVER_CONFIG_SHA256', hashlib.sha256(raw).hexdigest())]:
    print('VPSDEPLOY_' + name + '_B64=' + base64.b64encode(value.encode()).decode())
PY
printf '%s\n' 'VPSDEPLOY_SERVER_OUTBOUND_READ'
