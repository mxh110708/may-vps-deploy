#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_ROLE:?}"
: "${VPS_PARAM_MEMORY_KIB:?}"
: "${VPS_PARAM_MODE:?}"
: "${VPS_PARAM_BUFFER_TARGET_BYTES:?}"
: "${VPS_PARAM_BUFFER_CAP_BYTES:?}"
: "${VPS_PARAM_QUEUE_FLOOR:?}"
: "${VPS_PARAM_PROFILE:?}"
check_only="${VPS_PARAM_CHECK_ONLY:-false}"

case "$VPS_PARAM_ROLE" in
  RealityEntry|AnyTlsEntry|ShadowsocksLanding|MonitorOnly) ;;
  *) echo 'Invalid network tuning role.' >&2; exit 1 ;;
esac
case "$VPS_PARAM_MODE" in
  BaselineOnly|AdaptiveConservative) ;;
  *) echo 'Invalid network tuning mode.' >&2; exit 1 ;;
esac
case "$check_only" in true|false) ;; *) exit 1 ;; esac
is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
for value in "$VPS_PARAM_MEMORY_KIB" "$VPS_PARAM_BUFFER_TARGET_BYTES" \
  "$VPS_PARAM_BUFFER_CAP_BYTES" "$VPS_PARAM_QUEUE_FLOOR"; do
  is_uint "$value" || { echo 'Invalid numeric network tuning input.' >&2; exit 1; }
done
if [[ -n "${VPS_PARAM_BANDWIDTH_MBPS:-}" ]]; then
  is_uint "$VPS_PARAM_BANDWIDTH_MBPS" || exit 1
  (( VPS_PARAM_BANDWIDTH_MBPS >= 1 && VPS_PARAM_BANDWIDTH_MBPS <= 100000 )) || exit 1
fi
if [[ "$VPS_PARAM_MODE" == 'AdaptiveConservative' ]]; then
  is_uint "${VPS_PARAM_BANDWIDTH_MBPS:-}" || exit 1
  is_uint "${VPS_PARAM_REFERENCE_RTT_MS:-}" || exit 1
  (( VPS_PARAM_BANDWIDTH_MBPS >= 1 && VPS_PARAM_BANDWIDTH_MBPS <= 100000 )) || exit 1
  (( VPS_PARAM_REFERENCE_RTT_MS >= 1 && VPS_PARAM_REFERENCE_RTT_MS <= 2000 )) || exit 1
  (( VPS_PARAM_BUFFER_TARGET_BYTES >= 1048576 )) || exit 1
  (( VPS_PARAM_BUFFER_TARGET_BYTES <= VPS_PARAM_BUFFER_CAP_BYTES )) || exit 1
fi

if [[ "$check_only" == true ]]; then
  config="$(mktemp)"
  backup_dir='check-only'
  trap 'rm -f "$config"' EXIT
else
  config='/etc/sysctl.d/99-mxh-vps-deploy.conf'
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  backup_dir="/root/vps-deploy-backups/${stamp}/sysctl"
  install -d -m 0700 "$backup_dir"
  if [[ -f "$config" ]]; then cp -a "$config" "$backup_dir/"; fi
fi

if [[ "$check_only" == false ]]; then modprobe tcp_bbr 2>/dev/null || true; fi
bbr_available=false
available_congestion_control="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)"
if grep -qw bbr <<< "$available_congestion_control"; then
  bbr_available=true
fi

buffer_mode='baseline-only'
buffer_applied=0
queue_applied=0
buffer_lines=()
queue_lines=()
if [[ "$VPS_PARAM_MODE" == 'AdaptiveConservative' ]]; then
  read -r tcp_r_min tcp_r_default tcp_r_max <<<"$(sysctl -n net.ipv4.tcp_rmem)"
  read -r tcp_w_min tcp_w_default tcp_w_max <<<"$(sysctl -n net.ipv4.tcp_wmem)"
  core_r_max="$(sysctl -n net.core.rmem_max)"
  core_w_max="$(sysctl -n net.core.wmem_max)"
  current_highest="$core_r_max"
  for value in "$core_w_max" "$tcp_r_max" "$tcp_w_max"; do
    if (( value > current_highest )); then current_highest="$value"; fi
  done
  if (( current_highest > VPS_PARAM_BUFFER_CAP_BYTES )); then
    buffer_mode='preserved-existing-over-cap'
    buffer_applied="$current_highest"
  else
    buffer_applied="$VPS_PARAM_BUFFER_TARGET_BYTES"
    if (( current_highest > buffer_applied )); then buffer_applied="$current_highest"; fi
    buffer_lines+=("net.core.rmem_max = ${buffer_applied}")
    buffer_lines+=("net.core.wmem_max = ${buffer_applied}")
    buffer_lines+=("net.ipv4.tcp_rmem = ${tcp_r_min} ${tcp_r_default} ${buffer_applied}")
    buffer_lines+=("net.ipv4.tcp_wmem = ${tcp_w_min} ${tcp_w_default} ${buffer_applied}")
    buffer_mode='adaptive-applied-no-reduction'
  fi
fi
if (( VPS_PARAM_QUEUE_FLOOR > 0 )); then
  somaxconn="$(sysctl -n net.core.somaxconn)"
  syn_backlog="$(sysctl -n net.ipv4.tcp_max_syn_backlog)"
  queue_applied="$VPS_PARAM_QUEUE_FLOOR"
  if (( somaxconn > queue_applied )); then queue_applied="$somaxconn"; fi
  if (( syn_backlog > queue_applied )); then queue_applied="$syn_backlog"; fi
  queue_lines+=("net.core.somaxconn = ${queue_applied}")
  queue_lines+=("net.ipv4.tcp_max_syn_backlog = ${queue_applied}")
fi

{
  echo '# Managed by May VPS Deploy. Conservative adaptive tuning.'
  echo "# profile=${VPS_PARAM_PROFILE} role=${VPS_PARAM_ROLE} memory_kib=${VPS_PARAM_MEMORY_KIB}"
  if [[ -n "${VPS_PARAM_BANDWIDTH_MBPS:-}" ]]; then
    echo "# nominal_bandwidth_mbps=${VPS_PARAM_BANDWIDTH_MBPS} (provider plan value; not an interface speed guess)"
  fi
  if [[ "$VPS_PARAM_MODE" == 'AdaptiveConservative' ]]; then
    echo "# reference_rtt_ms=${VPS_PARAM_REFERENCE_RTT_MS} buffer_cap_bytes=${VPS_PARAM_BUFFER_CAP_BYTES}"
  else
    echo '# buffer tuning disabled: baseline-only mode'
  fi
  echo 'net.core.default_qdisc = fq'
  if [[ "$bbr_available" == true ]]; then
    echo 'net.ipv4.tcp_congestion_control = bbr'
  fi
  echo 'net.ipv4.tcp_fastopen = 3'
  echo 'net.ipv4.tcp_mtu_probing = 1'
  printf '%s\n' "${buffer_lines[@]}"
  printf '%s\n' "${queue_lines[@]}"
} > "$config"

if [[ "$check_only" == true ]]; then
  grep -Fq 'net.core.default_qdisc = fq' "$config"
  grep -Fq 'net.ipv4.tcp_fastopen = 3' "$config"
  grep -Fq 'net.ipv4.tcp_mtu_probing = 1' "$config"
  if [[ "$buffer_mode" == 'adaptive-applied-no-reduction' ]]; then
    grep -Fq "net.core.rmem_max = ${buffer_applied}" "$config"
    grep -Fq "net.core.wmem_max = ${buffer_applied}" "$config"
  fi
  printf 'VPSDEPLOY_NETWORK_CHECK_OK\n'
  exit 0
fi

sysctl --system >/dev/null
[[ "$(sysctl -n net.core.default_qdisc)" == 'fq' ]]
if [[ "$bbr_available" == true ]]; then
  [[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == 'bbr' ]]
fi
if [[ "$buffer_mode" == 'adaptive-applied-no-reduction' ]]; then
  [[ "$(sysctl -n net.core.rmem_max)" == "$buffer_applied" ]]
  [[ "$(sysctl -n net.core.wmem_max)" == "$buffer_applied" ]]
  [[ "$(sysctl -n net.ipv4.tcp_rmem | awk '{print $3}')" == "$buffer_applied" ]]
  [[ "$(sysctl -n net.ipv4.tcp_wmem | awk '{print $3}')" == "$buffer_applied" ]]
fi
if (( queue_applied > 0 )); then
  [[ "$(sysctl -n net.core.somaxconn)" == "$queue_applied" ]]
  [[ "$(sysctl -n net.ipv4.tcp_max_syn_backlog)" == "$queue_applied" ]]
fi
printf 'VPSDEPLOY_BBR_B64=%s\n' "$(printf '%s' "$bbr_available" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_BUFFER_MODE_B64=%s\n' "$(printf '%s' "$buffer_mode" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_BUFFER_APPLIED_B64=%s\n' "$(printf '%s' "$buffer_applied" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_QUEUE_APPLIED_B64=%s\n' "$(printf '%s' "$queue_applied" | base64 | tr -d '\n')"
