#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_BACKUP_PATH:?}"
: "${VPS_PARAM_SCOPE:?}"
[[ "$VPS_PARAM_SCOPE" == 'ConfigOnly' || "$VPS_PARAM_SCOPE" == 'Full' ]]
resolved="$(readlink -f "$VPS_PARAM_BACKUP_PATH")"
[[ "$resolved" =~ ^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$ ]]
[[ -d "$resolved" ]]
[[ -x /usr/local/libexec/mxh-protocol-migration-rollback ]]

if [[ "$VPS_PARAM_SCOPE" == 'Full' ]]; then
  if [[ "${VPS_PARAM_DESKTOP_PROTOCOL_ONLY:-false}" == true ]]; then
    grep -Fq -- "'--protocol-files-only'" /usr/local/libexec/mxh-protocol-migration-rollback || { echo 'Installed helper does not support strict protocol scope.' >&2; exit 1; }
    /usr/local/libexec/mxh-protocol-migration-rollback "$resolved" --protocol-files-only
  else
    /usr/local/libexec/mxh-protocol-migration-rollback "$resolved" --protocol-only
  fi
else
  [[ -f "$resolved/protocol-files.tar.gz" ]]
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  tar --numeric-owner -xzpf "$resolved/protocol-files.tar.gz" -C "$stage"
  copy_path() {
    local relative="$1"
    if [[ -e "$stage/$relative" || -L "$stage/$relative" ]]; then
      local target="/${relative:?}"
      rm -rf -- "$target"
      install -d -m 0755 "$(dirname "$target")"
      cp -a "$stage/$relative" "$target"
    fi
  }
  for relative in usr/local/etc/xray etc/sing-box-anytls etc/sing-box etc/mxh-tls/anytls etc/mxh-tls/reality-target \
    etc/nginx/sites-available/mxh-reality-target etc/nginx/sites-enabled/mxh-reality-target var/www/mxh-reality-target; do
    copy_path "$relative"
  done
  systemctl daemon-reload
  if systemctl is-active --quiet nginx.service; then
    nginx -t
    systemctl reload nginx.service
  fi
  if systemctl is-active --quiet xray.service; then /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json; systemctl restart xray.service; fi
  if systemctl is-active --quiet sing-box-anytls.service; then /usr/local/bin/sing-box-anytls check -c /etc/sing-box-anytls/config.json; systemctl restart sing-box-anytls.service; fi
  if systemctl is-active --quiet sing-box.service; then /usr/local/bin/sing-box check -c /etc/sing-box/config.json; systemctl restart sing-box.service; fi
fi
printf '%s\n' 'VPSDEPLOY_MANUAL_RESTORE_APPLIED'
