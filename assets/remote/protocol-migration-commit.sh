#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_BACKUP:?}"
exec 9>/var/lib/may-vps-deploy/transaction.lock
flock -n 9 || exit 1
if [[ -f "$VPS_PARAM_EXPECTED_BACKUP/transaction-committed" ]]; then printf '%s\n' 'VPSDEPLOY_MIGRATION_COMMITTED'; exit 0; fi
[[ "$(cat /var/lib/may-vps-deploy/transaction.owner)" == "$VPS_PARAM_EXPECTED_BACKUP" ]]
[[ ! -f "$VPS_PARAM_EXPECTED_BACKUP/rollback-executed" ]]
check_deadline(){
  local deadline
  [[ -f "$VPS_PARAM_EXPECTED_BACKUP/deadline-epoch" ]] || return 0
  deadline="$(cat "$VPS_PARAM_EXPECTED_BACKUP/deadline-epoch")"
  [[ "$deadline" =~ ^[0-9]+$ && "$(date +%s)" -lt "$deadline" ]] || { echo 'Rollback deadline passed; commit refused.' >&2; return 1; }
}
check_deadline
if systemctl is-active --quiet mxh-protocol-migration-rollback.service; then exit 1; fi

: "${VPS_PARAM_SOURCE_ROLE:?}"
: "${VPS_PARAM_TARGET_ROLE:?}"
: "${VPS_PARAM_TARGET_PORT:?}"

target_aux_port="${VPS_PARAM_TARGET_AUX_PORT:-}"
remove_role="${VPS_PARAM_REMOVE_ROLE:-}"
precommit_target_required="${VPS_PARAM_PRECOMMIT_TARGET_REQUIRED:-false}"

reality_enabled="${VPS_PARAM_FINAL_REALITY_ENABLED:-false}"
anytls_enabled="${VPS_PARAM_FINAL_ANYTLS_ENABLED:-false}"
shadowsocks_enabled="${VPS_PARAM_FINAL_SHADOWSOCKS_ENABLED:-false}"
if [[ -z "${VPS_PARAM_FINAL_REALITY_ENABLED:-}" && -z "${VPS_PARAM_FINAL_ANYTLS_ENABLED:-}" && -z "${VPS_PARAM_FINAL_SHADOWSOCKS_ENABLED:-}" ]]; then
  case "$VPS_PARAM_TARGET_ROLE" in
    RealityEntry) reality_enabled='true' ;;
    AnyTlsEntry) anytls_enabled='true' ;;
    ShadowsocksLanding) shadowsocks_enabled='true' ;;
  esac
fi
for value in "$reality_enabled" "$anytls_enabled" "$shadowsocks_enabled" "$precommit_target_required"; do
  [[ "$value" == 'true' || "$value" == 'false' ]] || exit 1
done
[[ "$reality_enabled" != 'true' || "$anytls_enabled" != 'true' ]] || exit 1

service_for_role() {
  case "$1" in
    RealityEntry) printf '%s' 'xray.service' ;;
    AnyTlsEntry) printf '%s' 'sing-box-anytls.service' ;;
    ShadowsocksLanding) printf '%s' 'sing-box.service' ;;
    MonitorOnly) printf '%s' '' ;;
    *) exit 1 ;;
  esac
}
target_service="$(service_for_role "$VPS_PARAM_TARGET_ROLE")"
if [[ "$precommit_target_required" == 'true' ]]; then
  [[ -n "$target_service" ]]
  systemctl is-active --quiet "$target_service"
fi

check_config() {
  case "$1" in
    RealityEntry) /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json ;;
    AnyTlsEntry) /usr/local/bin/sing-box-anytls check -c /etc/sing-box-anytls/config.json ;;
    ShadowsocksLanding) /usr/local/bin/sing-box check -c /etc/sing-box/config.json ;;
  esac
}
[[ "$reality_enabled" == 'false' ]] || check_config RealityEntry
[[ "$anytls_enabled" == 'false' ]] || check_config AnyTlsEntry
[[ "$shadowsocks_enabled" == 'false' ]] || check_config ShadowsocksLanding
check_deadline

if [[ "$reality_enabled" == 'false' ]]; then systemctl disable --now xray.service >/dev/null 2>&1 || true; fi
if [[ "$anytls_enabled" == 'false' ]]; then systemctl disable --now sing-box-anytls.service >/dev/null 2>&1 || true; fi
if [[ "$shadowsocks_enabled" == 'false' ]]; then systemctl disable --now sing-box.service >/dev/null 2>&1 || true; fi

if [[ "$reality_enabled" == 'true' ]]; then
  systemctl disable --now sing-box-anytls.service >/dev/null 2>&1 || true
  systemctl enable --now xray.service >/dev/null
fi
if [[ "$anytls_enabled" == 'true' ]]; then
  systemctl disable --now xray.service >/dev/null 2>&1 || true
  systemctl enable --now sing-box-anytls.service >/dev/null
fi
if [[ "$shadowsocks_enabled" == 'true' ]]; then systemctl enable --now sing-box.service >/dev/null; fi

check_state() {
  local service="$1" expected="$2"
  if [[ "$expected" == 'true' ]]; then
    systemctl is-enabled --quiet "$service"
    systemctl is-active --quiet "$service"
  else
    ! systemctl is-enabled --quiet "$service" 2>/dev/null
    ! systemctl is-active --quiet "$service" 2>/dev/null
  fi
}
check_state xray.service "$reality_enabled"
check_state sing-box-anytls.service "$anytls_enabled"
check_state sing-box.service "$shadowsocks_enabled"

if [[ "$reality_enabled" == 'true' ]]; then
  grep -Fq xray <<< "$(ss -H -lntp 'sport = :443')"
  if [[ -n "$target_aux_port" ]]; then grep -Fq xray <<< "$(ss -H -lntp "sport = :${target_aux_port}")"; fi
fi
if [[ "$anytls_enabled" == 'true' ]]; then
  grep -Fq sing-box-anytl <<< "$(ss -H -lntp 'sport = :443')"
fi
if [[ "$shadowsocks_enabled" == 'true' ]]; then
  grep -Fq sing-box <<< "$(ss -H -lntp "sport = :${VPS_PARAM_TARGET_PORT}")"
  grep -Fq sing-box <<< "$(ss -H -lnup "sport = :${VPS_PARAM_TARGET_PORT}")"
fi

case "$remove_role" in
  '') ;;
  RealityEntry) [[ ! -x /usr/local/bin/xray && ! -e /usr/local/etc/xray/config.json ]] ;;
  AnyTlsEntry) [[ ! -x /usr/local/bin/sing-box-anytls && ! -e /etc/sing-box-anytls/config.json ]] ;;
  ShadowsocksLanding) [[ ! -x /usr/local/bin/sing-box && ! -e /etc/sing-box/config.json ]] ;;
  *) exit 1 ;;
esac

check_deadline
systemctl stop mxh-protocol-migration-rollback.timer
systemctl disable mxh-protocol-migration-rollback.timer >/dev/null
if systemctl is-active --quiet mxh-protocol-migration-rollback.timer; then exit 1; fi
date -u +%FT%TZ > "$VPS_PARAM_EXPECTED_BACKUP/transaction-committed"
rm -f /var/lib/may-vps-deploy/transaction.owner
printf '%s\n' 'VPSDEPLOY_MIGRATION_COMMITTED'
