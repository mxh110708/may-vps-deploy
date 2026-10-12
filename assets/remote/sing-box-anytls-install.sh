#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_VERSION:?}"
: "${VPS_PARAM_ASSET_NAME:?}"
: "${VPS_PARAM_SHA256:?}"

stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/sing-box-anytls-install"
install -d -m 0700 "$backup_dir"
for existing in /usr/local/bin/sing-box-anytls /etc/systemd/system/sing-box-anytls.service; do
  if [[ -f "$existing" ]]; then cp -a "$existing" "$backup_dir/$(basename "$existing")"; fi
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
install -o root -g root -m 0755 "$binary" /usr/local/bin/sing-box-anytls

getent group sing-box-anytls >/dev/null 2>&1 || groupadd --system sing-box-anytls
id sing-box-anytls >/dev/null 2>&1 || useradd --system --gid sing-box-anytls \
  --home-dir /var/lib/sing-box-anytls --shell /usr/sbin/nologin sing-box-anytls
install -d -o root -g sing-box-anytls -m 0750 /etc/sing-box-anytls
install -d -o sing-box-anytls -g sing-box-anytls -m 0750 /var/lib/sing-box-anytls

cat > /etc/systemd/system/sing-box-anytls.service <<'EOF'
[Unit]
Description=sing-box AnyTLS trusted TLS and ECH entry
Documentation=https://sing-box.sagernet.org/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=sing-box-anytls
Group=sing-box-anytls
WorkingDirectory=/var/lib/sing-box-anytls
ExecStart=/usr/local/bin/sing-box-anytls run -c /etc/sing-box-anytls/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sing-box-anytls
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
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/sing-box-anytls.service
systemctl daemon-reload
actual="$(/usr/local/bin/sing-box-anytls version | awk 'NR==1 {print $3}')"
[[ "${actual#v}" == "${VPS_PARAM_VERSION#v}" ]] || { echo 'Unexpected sing-box version.' >&2; exit 1; }
printf 'VPSDEPLOY_SING_BOX_VERSION_B64=%s\n' "$(printf '%s' "$actual" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
