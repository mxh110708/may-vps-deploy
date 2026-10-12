#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_VERSION:?}"
: "${VPS_PARAM_INSTALLER_URL:?}"
: "${VPS_PARAM_INSTALLER_SHA256:?}"

temporary="$(mktemp)"
package="$(mktemp)"
trap 'rm -f "$temporary" "$package"' EXIT
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$temporary" "$VPS_PARAM_INSTALLER_URL"
printf '%s  %s\n' "$VPS_PARAM_INSTALLER_SHA256" "$temporary" | sha256sum --check --status
if [[ -n "${VPS_PARAM_SHA256:-}" ]]; then
  [[ "$VPS_PARAM_SHA256" =~ ^[a-f0-9]{64}$ && "${VPS_PARAM_ASSET_NAME:-}" == Xray-linux-64.zip ]]
  version="${VPS_PARAM_VERSION#v}"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
  base='https://github.com/XTLS/Xray-core/releases/download'
  url="${VPS_PARAM_DOWNLOAD_URL:-${base}/v${version}/Xray-linux-64.zip}"
  [[ "$url" == "${base}/v${version}/Xray-linux-64.zip" || "$url" == "${base}/${version}/Xray-linux-64.zip" ]]
  curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 3 --output "$package" "$url"
  printf '%s  %s\n' "$VPS_PARAM_SHA256" "$package" | sha256sum --check --status
  if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
  # --local and --version are mutually exclusive in the pinned installer.
  # Its local-file acknowledgement follows our independent digest check.
  printf '\n' | bash "$temporary" install --local "$package"
else
  if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
  bash "$temporary" install --version "v${VPS_PARAM_VERSION#v}"
fi

actual="$(/usr/local/bin/xray version | awk 'NR==1 {print $2}')"
[[ "${actual#v}" == "${VPS_PARAM_VERSION#v}" ]] || {
  echo "Unexpected Xray version" >&2
  exit 1
}
systemctl enable xray.service
printf 'VPSDEPLOY_XRAY_VERSION_B64=%s\n' "$(printf '%s' "$actual" | base64 | tr -d '\n')"
