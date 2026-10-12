#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_ROLE:?}"
: "${VPS_PARAM_SSH_PRIMARY:?}"
: "${VPS_PARAM_SSH_RESCUE:?}"
: "${VPS_PARAM_KOMARI_ENABLED:?}"
: "${VPS_PARAM_REALITY_ENABLED:?}"
: "${VPS_PARAM_ANYTLS_ENABLED:?}"
: "${VPS_PARAM_SHADOWSOCKS_ENABLED:?}"
firewall_mode="${VPS_PARAM_FIREWALL_MODE:-ManagedNftables}"
preserve_ssh_auth="${VPS_PARAM_PRESERVE_SSH_AUTH:-false}"
[[ "$preserve_ssh_auth" == true || "$preserve_ssh_auth" == false ]]

for value in "$VPS_PARAM_REALITY_ENABLED" "$VPS_PARAM_ANYTLS_ENABLED" "$VPS_PARAM_SHADOWSOCKS_ENABLED"; do
  [[ "$value" == 'true' || "$value" == 'false' ]] || exit 1
done
if [[ "$VPS_PARAM_REALITY_ENABLED" == true && "$VPS_PARAM_ANYTLS_ENABLED" == true ]]; then
  [[ "$VPS_PARAM_XRAY_PRIMARY" != "$VPS_PARAM_ANYTLS_PORT" && "${VPS_PARAM_XRAY_BACKUP:-}" != "$VPS_PARAM_ANYTLS_PORT" ]] || exit 1
fi

sshd -t
effective="$(sshd -T)"
grep -qx "port ${VPS_PARAM_SSH_PRIMARY}" <<<"$effective"
grep -qx "port ${VPS_PARAM_SSH_RESCUE}" <<<"$effective"
if [[ "$preserve_ssh_auth" == false ]]; then
  grep -qx 'passwordauthentication no' <<<"$effective"
  grep -qx 'kbdinteractiveauthentication no' <<<"$effective"
fi
grep -qx 'pubkeyauthentication yes' <<<"$effective"
case "$firewall_mode" in
  ManagedNftables)
    systemctl is-active --quiet nftables.service
    nft -c -f /etc/nftables.conf
    ;;
  PreserveExisting)
    if [[ -f /etc/nftables.conf ]]; then nft -c -f /etc/nftables.conf; fi
    ;;
  *) exit 1 ;;
esac

if [[ "$VPS_PARAM_REALITY_ENABLED" == 'true' ]]; then
  : "${VPS_PARAM_XRAY_PRIMARY:?}"
  /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
  systemctl is-enabled --quiet xray.service
  systemctl is-active --quiet xray.service
  grep -q xray <<< "$(ss -H -lntp "sport = :${VPS_PARAM_XRAY_PRIMARY}")"
  if [[ -n "${VPS_PARAM_XRAY_BACKUP:-}" && "$VPS_PARAM_XRAY_BACKUP" != 0 ]]; then
    grep -q xray <<< "$(ss -H -lntp "sport = :${VPS_PARAM_XRAY_BACKUP}")"
  fi
  if [[ "${VPS_PARAM_REALITY_TARGET_MODE:-ExternalAudited}" == 'LocalOwnedTls' ]]; then
    : "${VPS_PARAM_LOCAL_HTTPS_PORT:?}"
    : "${VPS_PARAM_REALITY_SERVER_NAME:?}"
    systemctl is-active --quiet nginx.service
    ss -H -lntp "sport = :${VPS_PARAM_LOCAL_HTTPS_PORT}" | grep -F nginx >/dev/null
    ! ss -H -lntp 'sport = :80' | grep -F nginx >/dev/null
    ! ss -H -lntp 'sport = :443' | grep -F nginx >/dev/null
    echo | openssl s_client -connect "127.0.0.1:${VPS_PARAM_LOCAL_HTTPS_PORT}" \
      -servername "$VPS_PARAM_REALITY_SERVER_NAME" -alpn h2 \
      -verify_hostname "$VPS_PARAM_REALITY_SERVER_NAME" 2>/dev/null | \
      grep -F 'Verify return code: 0 (ok)' >/dev/null
    systemctl is-active --quiet mxh-certbot-renew.timer
  fi
else
  ! systemctl is-active --quiet xray.service 2>/dev/null
fi

if [[ "$VPS_PARAM_ANYTLS_ENABLED" == 'true' ]]; then
  : "${VPS_PARAM_ANYTLS_PORT:?}"
  : "${VPS_PARAM_ANYTLS_SERVER_NAME:?}"
  /usr/local/bin/sing-box-anytls check -c /etc/sing-box-anytls/config.json
  python3 - /etc/sing-box-anytls/config.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding='utf-8') as handle:
    config = json.load(handle)
scheme = config['inbounds'][0].get('padding_scheme')
assert isinstance(scheme, list) and len(scheme) >= 3
PY
  systemctl is-enabled --quiet sing-box-anytls.service
  systemctl is-active --quiet sing-box-anytls.service
  [[ "$VPS_PARAM_REALITY_ENABLED" == true ]] || ! systemctl is-active --quiet xray.service
  ss -H -lntp "sport = :${VPS_PARAM_ANYTLS_PORT}" | grep -F sing-box-anytl >/dev/null
  openssl x509 -in /etc/mxh-tls/anytls/fullchain.pem -noout -checkhost "$VPS_PARAM_ANYTLS_SERVER_NAME" >/dev/null
  [[ "$(stat -c '%a' /etc/sing-box-anytls/config.json)" == '640' ]]
  [[ "$(stat -c '%a' /etc/sing-box-anytls/ech-key.pem)" == '640' ]]
  systemctl is-active --quiet mxh-certbot-renew.timer
else
  ! systemctl is-active --quiet sing-box-anytls.service 2>/dev/null
fi

if [[ "$VPS_PARAM_SHADOWSOCKS_ENABLED" == 'true' ]]; then
  : "${VPS_PARAM_LANDING_PORT:?}"
  /usr/local/bin/sing-box check -c /etc/sing-box/config.json
  systemctl is-enabled --quiet sing-box.service
  systemctl is-active --quiet sing-box.service
  [[ "$(stat -c '%a' /etc/sing-box/config.json)" == '640' ]]
  grep -q sing-box <<< "$(ss -H -lntp "sport = :${VPS_PARAM_LANDING_PORT}")"
  grep -q sing-box <<< "$(ss -H -lnup "sport = :${VPS_PARAM_LANDING_PORT}")"
  if [[ "$firewall_mode" == 'ManagedNftables' ]]; then
    ruleset="$(nft list ruleset)"
    grep -Eq "tcp dport.*${VPS_PARAM_LANDING_PORT}|tcp dport ${VPS_PARAM_LANDING_PORT}" <<<"$ruleset"
    grep -Eq "udp dport.*${VPS_PARAM_LANDING_PORT}|udp dport ${VPS_PARAM_LANDING_PORT}" <<<"$ruleset"
    IFS=',' read -r -a trusted_addresses <<<"${VPS_PARAM_TRUSTED_ADDRESSES:-}"
    for address in "${trusted_addresses[@]}"; do
      [[ -z "$address" ]] && continue
      grep -Fq "$address" <<<"$ruleset" || { echo 'Trusted entry address is missing from nftables.' >&2; exit 1; }
    done
  fi
else
  ! systemctl is-active --quiet sing-box.service 2>/dev/null
fi

if [[ "$VPS_PARAM_KOMARI_ENABLED" == 'true' ]]; then
  systemctl is-active --quiet komari-agent.service
  [[ "$(stat -c '%a' /etc/komari-agent/config.json)" == '600' ]]
  ! grep -q komari-agent <<< "$(ss -H -lntup 2>/dev/null)"
fi

time_state="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
printf 'VPSDEPLOY_TIME_SYNC_B64=%s\n' "$(printf '%s' "$time_state" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_FINAL_OK\n'
