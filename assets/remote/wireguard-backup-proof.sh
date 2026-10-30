#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_BACKUP_DIR:?}"
[[ "$VPS_PARAM_BACKUP_DIR" =~ ^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$ ]]
[[ ! -L "$VPS_PARAM_BACKUP_DIR" && "$(readlink -f "$VPS_PARAM_BACKUP_DIR")" == "$VPS_PARAM_BACKUP_DIR" ]]
[[ -f "$VPS_PARAM_BACKUP_DIR/protocol-files.tar.gz" && ! -L "$VPS_PARAM_BACKUP_DIR/protocol-files.tar.gz" ]]
value="$(sha256sum "$VPS_PARAM_BACKUP_DIR/protocol-files.tar.gz" | cut -d ' ' -f 1)"
printf 'VPSDEPLOY_WIREGUARD_BACKUP_SHA256_B64=%s\n' "$(printf '%s' "$value" | base64 | tr -d '\n')"
printf '%s\n' VPSDEPLOY_WIREGUARD_BACKUP_PROOF
