#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_ENDPOINT:?}"
: "${VPS_PARAM_TOKEN:?}"
: "${VPS_PARAM_NODE_NAME:?}"
: "${VPS_PARAM_VERSION:?}"
: "${VPS_PARAM_ASSET_NAME:?}"
: "${VPS_PARAM_SHA256:?}"

case "$(uname -m)" in
  x86_64|amd64) expected_arch='amd64' ;;
  aarch64|arm64) expected_arch='arm64' ;;
  *) echo 'Unsupported Komari architecture.' >&2; exit 1 ;;
esac
[[ "$VPS_PARAM_ASSET_NAME" == *"-${expected_arch}" ]] || exit 1

config_dir='/etc/komari-agent'
state_dir='/var/lib/komari-agent'
config_file="${config_dir}/config.json"
url="https://github.com/komari-monitor/komari-agent/releases/download/${VPS_PARAM_VERSION}/${VPS_PARAM_ASSET_NAME}"
url="${VPS_PARAM_DOWNLOAD_URL:-$url}"
base='https://github.com/komari-monitor/komari-agent/releases/download'
[[ "$url" == "${base}/v${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}" || "$url" == "${base}/${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}" ]]
binary="$(mktemp)"
config="$(mktemp)"
trap 'rm -f "$binary" "$config"' EXIT

if ! getent group komari-agent >/dev/null 2>&1; then groupadd --system komari-agent; fi
if ! id komari-agent >/dev/null 2>&1; then
  useradd --system --gid komari-agent --home-dir "$state_dir" --shell /usr/sbin/nologin komari-agent
fi
install -d -o komari-agent -g komari-agent -m 0750 "$state_dir"
install -d -o root -g komari-agent -m 0750 "$config_dir"

curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$binary" "$url"
printf '%s  %s\n' "$VPS_PARAM_SHA256" "$binary" | sha256sum --check --status
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
install -o root -g root -m 0755 "$binary" /usr/local/bin/komari-agent

python3 - "$config" <<'PY'
import json
import os
import sys

output = sys.argv[1]
config = {
    "endpoint": os.environ["VPS_PARAM_ENDPOINT"].rstrip("/"),
    "token": os.environ["VPS_PARAM_TOKEN"].strip(),
    "interval": 5,
    "disable_auto_update": True,
    "disable_web_ssh": True,
    "ignore_unsafe_cert": False,
    "max_retries": 5,
    "reconnect_interval": 10,
    "info_report_interval": 15,
    "disable_compression": False,
    "prefer_ip_version": "4",
}
if not config["token"] or any(character.isspace() for character in config["token"]):
    raise SystemExit("Invalid Komari token")
with open(output, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PY
install -o komari-agent -g komari-agent -m 0600 "$config" "$config_file"

cat > /etc/systemd/system/komari-agent.service <<'EOF'
[Unit]
Description=Komari Monitoring Agent
Documentation=https://github.com/komari-monitor/komari-agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=komari-agent
Group=komari-agent
WorkingDirectory=/var/lib/komari-agent
ExecStart=/usr/local/bin/komari-agent --config /etc/komari-agent/config.json
Restart=always
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/komari-agent
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable komari-agent.service
systemctl restart komari-agent.service
systemctl is-active --quiet komari-agent.service
if grep -q komari-agent <<< "$(ss -H -lntup 2>/dev/null)"; then
  echo 'Komari Agent unexpectedly opened a listening port.' >&2
  exit 1
fi
printf 'VPSDEPLOY_KOMARI_OK\n'
