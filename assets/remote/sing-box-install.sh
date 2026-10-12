#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_VERSION:?}"
: "${VPS_PARAM_ASSET_NAME:?}"
: "${VPS_PARAM_SHA256:?}"
need_bind_interface="${VPS_PARAM_NEED_BIND_INTERFACE:-false}"

stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/sing-box-install"
install -d -m 0700 "$backup_dir"
for existing in /usr/local/bin/sing-box /etc/systemd/system/sing-box.service \
  /etc/systemd/system/sing-box.service.d/20-bind-interface-capability.conf; do
  if [[ -f "$existing" ]]; then
    cp -a "$existing" "$backup_dir/$(basename "$existing")"
  fi
done

archive="$(mktemp)"
stage="$(mktemp -d)"
trap 'rm -f "$archive"; rm -rf "$stage"' EXIT
url="https://github.com/SagerNet/sing-box/releases/download/v${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}"
url="${VPS_PARAM_DOWNLOAD_URL:-$url}"
base='https://github.com/SagerNet/sing-box/releases/download'
[[ "$url" == "${base}/v${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}" || "$url" == "${base}/${VPS_PARAM_VERSION#v}/${VPS_PARAM_ASSET_NAME}" ]]
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$archive" "$url"
printf '%s  %s\n' "$VPS_PARAM_SHA256" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$stage"
binary="$(find "$stage" -type f -name sing-box -print -quit)"
[[ -n "$binary" ]] || { echo 'sing-box binary is missing from release archive.' >&2; exit 1; }
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
install -o root -g root -m 0755 "$binary" /usr/local/bin/sing-box

if ! getent group sing-box >/dev/null 2>&1; then groupadd --system sing-box; fi
if ! id sing-box >/dev/null 2>&1; then
  useradd --system --gid sing-box --home-dir /var/lib/sing-box --shell /usr/sbin/nologin sing-box
fi
install -d -o root -g sing-box -m 0750 /etc/sing-box
install -d -o sing-box -g sing-box -m 0750 /var/lib/sing-box

cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box Shadowsocks Landing Service
Documentation=https://sing-box.sagernet.org/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=sing-box
Group=sing-box
WorkingDirectory=/var/lib/sing-box
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sing-box
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

dropin_dir='/etc/systemd/system/sing-box.service.d'
dropin_file="${dropin_dir}/20-bind-interface-capability.conf"
if [[ "$need_bind_interface" == 'true' ]]; then
  install -d -m 0755 "$dropin_dir"
  cat > "$dropin_file" <<'EOF'
[Service]
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
EOF
  chmod 0644 "$dropin_file"
else
  rm -f "$dropin_file"
fi

systemctl daemon-reload
actual="$(/usr/local/bin/sing-box version | awk 'NR==1 {print $3}')"
[[ "${actual#v}" == "${VPS_PARAM_VERSION#v}" ]] || { echo 'Unexpected sing-box version.' >&2; exit 1; }
printf 'VPSDEPLOY_SING_BOX_VERSION_B64=%s\n' "$(printf '%s' "$actual" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
