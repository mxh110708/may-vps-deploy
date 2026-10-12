#!/usr/bin/env bash
set -Eeuo pipefail
phase='parameters'
report_failure() {
  local status="$?"
  trap - ERR
  printf 'VPSDEPLOY_MONITORING_FAILURE_PHASE_B64=%s\n' "$(printf '%s' "$phase" | base64 | tr -d '\n')"
  exit "$status"
}
trap report_failure ERR
: "${VPS_PARAM_COMPONENT:?}"
: "${VPS_PARAM_VERSION:?}"
: "${VPS_PARAM_ASSET_NAME:?}"
: "${VPS_PARAM_SHA256:?}"
: "${VPS_PARAM_PORT:?}"
: "${VPS_PARAM_SECRET:?}"
[[ "$VPS_PARAM_PORT" =~ ^[0-9]+$ ]] && (( VPS_PARAM_PORT >= 1 && VPS_PARAM_PORT <= 65535 ))
[[ "$VPS_PARAM_SHA256" =~ ^[0-9a-f]{64}$ ]]
case "$VPS_PARAM_COMPONENT" in
  KomariController)
    [[ "$VPS_PARAM_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$VPS_PARAM_ASSET_NAME" == komari-linux-amd64 ]]
    repository=komari-monitor/komari; binary=/usr/local/bin/komari; service=komari.service
    ;;
  Tunnel)
    [[ "$VPS_PARAM_VERSION" =~ ^[0-9]{4}\.[0-9]+\.[0-9]+$ && "$VPS_PARAM_ASSET_NAME" == cloudflared-linux-amd64 ]]
    [[ "$VPS_PARAM_SECRET" != *[[:space:]]* ]]
    repository=cloudflare/cloudflared; binary=/usr/local/bin/cloudflared; service=cloudflared.service
    ;;
  *) exit 1 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
phase='download'
base="https://github.com/${repository}/releases/download"
url="${VPS_PARAM_DOWNLOAD_URL:-${base}/${VPS_PARAM_VERSION}/${VPS_PARAM_ASSET_NAME}}"
[[ "$url" == "${base}/v${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}" || "$url" == "${base}/${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}" ]]
curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 300 \
  "$url" -o "$work/binary"
printf '%s  %s\n' "$VPS_PARAM_SHA256" "$work/binary" | sha256sum -c - >/dev/null
phase='binary-check'
chmod 0755 "$work/binary"
if [[ "$VPS_PARAM_COMPONENT" == KomariController ]]; then
  # Komari 1.5 prints its version banner before parsing flags and has no
  # --version flag. --help exits successfully without starting a server.
  version_output="$("$work/binary" --help 2>&1)"
  grep -Fq "Komari Monitor ${VPS_PARAM_VERSION}" <<<"$version_output"
else
  version_output="$("$work/binary" --version 2>&1)"
  grep -Fq "$VPS_PARAM_VERSION" <<<"$version_output"
fi
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
[[ ! -e "$binary" && ! -L "$binary" ]]
install -o root -g root -m 0755 "$work/binary" "$binary"
if [[ "$VPS_PARAM_COMPONENT" == KomariController ]]; then
  getent group komari >/dev/null || groupadd --system komari
  id -u komari >/dev/null 2>&1 || useradd --system --gid komari --home-dir /var/lib/komari --shell /usr/sbin/nologin komari
  install -d -o komari -g komari -m 0700 /var/lib/komari
  cat > /etc/systemd/system/komari.service <<EOF
[Unit]
Description=Komari monitoring controller
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
User=komari
Group=komari
WorkingDirectory=/var/lib/komari
ExecStart=/usr/local/bin/komari server -l 127.0.0.1:${VPS_PARAM_PORT}
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/komari
[Install]
WantedBy=multi-user.target
EOF
else
  getent group cloudflared >/dev/null || groupadd --system cloudflared
  id -u cloudflared >/dev/null 2>&1 || useradd --system --gid cloudflared --home-dir /nonexistent --shell /usr/sbin/nologin cloudflared
  install -d -o root -g cloudflared -m 0750 /etc/cloudflared
  printf '%s' "$VPS_PARAM_SECRET" > "$work/token"
  install -o root -g cloudflared -m 0640 "$work/token" /etc/cloudflared/mxh-token
  cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel connector
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
User=cloudflared
Group=cloudflared
ExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:${VPS_PARAM_PORT} run --token-file /etc/cloudflared/mxh-token
TimeoutStartSec=90s
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
[Install]
WantedBy=multi-user.target
EOF
fi
chmod 0644 "/etc/systemd/system/$service"
phase='service-start'
systemctl daemon-reload
systemctl enable --now "$service" >/dev/null
systemctl is-active --quiet "$service"
phase='service-process'
pid="$(systemctl show "$service" -p MainPID --value)"
[[ "$pid" =~ ^[1-9][0-9]*$ && "/proc/$pid/exe" -ef "$binary" ]]
phase='readiness'
python3 <<'PY'
import base64, http.cookiejar, json, os, time, urllib.error, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base = 'http://127.0.0.1:' + os.environ['VPS_PARAM_PORT']
def request(path, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers={'Content-Type': 'application/json'})
    with opener.open(req, timeout=10) as response: return response.read()
def fail(phase):
    print('VPSDEPLOY_MONITORING_FAILURE_PHASE_B64=' + base64.b64encode(phase.encode()).decode())
    raise SystemExit(1)
if os.environ['VPS_PARAM_COMPONENT'] == 'KomariController':
    for attempt in range(30):
        try:
            status = json.loads(request('/api/install/status'))
            if status.get('data', {}).get('required') is True: break
        except (OSError, ValueError): pass
        time.sleep(1)
    else: fail('controller-guide')
    body = {'username': 'admin', 'password': os.environ['VPS_PARAM_SECRET'], 'sitename': 'MXH Monitor', 'description': '', 'metric_dsn': './data/metrics.db'}
    try: request('/api/install/complete', body)
    except (OSError, ValueError): fail('controller-initialization')
    for attempt in range(30):
        try:
            result = json.loads(request('/api/login', {'username': 'admin', 'password': os.environ['VPS_PARAM_SECRET']}))
            if result.get('status') == 'success':
                request('/api/logout'); break
        except (OSError, ValueError): pass
        time.sleep(1)
    else: fail('controller-login')
else:
    for attempt in range(30):
        try: request('/ready'); break
        except OSError: time.sleep(1)
    else: fail('tunnel-readiness')
PY
printf '%s\n' 'VPSDEPLOY_MONITORING_INSTALLED'
