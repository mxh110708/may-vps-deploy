#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_TRANSACTION:?}"
[[ "${VPS_PARAM_PROFILE:-}" == LandingBasic || "$VPS_PARAM_PROFILE" == EntryBasic || "$VPS_PARAM_PROFILE" == EntryMeasured ]] || exit 1
[[ "${VPS_PARAM_BUFFER_TARGET_BYTES:-0}" =~ ^[0-9]+$ && "${VPS_PARAM_BUFFER_CAP_BYTES:-0}" =~ ^[0-9]+$ ]] || exit 1
snapshot="$VPS_PARAM_EXPECTED_TRANSACTION"
[[ -f "$snapshot/network-state.json" && ! -L "$snapshot/network-state.json" ]]
config='/etc/sysctl.d/99-mxh-vps-deploy.conf'
[[ ! -L "$config" && ( ! -e "$config" || -f "$config" ) ]]
if [[ -e "$config" ]]; then grep -q '^# Managed by MXH VPS Deploy\.' "$config" || { echo 'Unmanaged sysctl collision.' >&2; exit 1; }; fi
modprobe tcp_bbr 2>/dev/null || true
available="$(sysctl -n net.ipv4.tcp_available_congestion_control)"
bbr=false
grep -qw bbr <<< "$available" && bbr=true
original_cc="$(sysctl -n net.ipv4.tcp_congestion_control)"
[[ "$original_cc" =~ ^[a-zA-Z0-9_-]+$ ]]
temporary="$(mktemp /etc/sysctl.d/.mxh-network-XXXXXX)"
trap 'rm -f "$temporary"' EXIT
adjust=false
if [[ "$VPS_PARAM_PROFILE" == EntryMeasured ]]; then
  target="$VPS_PARAM_BUFFER_TARGET_BYTES"; cap="$VPS_PARAM_BUFFER_CAP_BYTES"
  (( target >= 1048576 && target <= cap && cap <= 33554432 ))
  read -r r_min r_default r_max <<<"$(sysctl -n net.ipv4.tcp_rmem)"
  read -r w_min w_default w_max <<<"$(sysctl -n net.ipv4.tcp_wmem)"
  core_r="$(sysctl -n net.core.rmem_max)"; core_w="$(sysctl -n net.core.wmem_max)"
  if (( r_max <= cap && w_max <= cap && core_r <= cap && core_w <= cap )); then
    adjust=true
    (( w_max >= target )) || w_max="$target"
    (( core_w >= target )) || core_w="$target"
  fi
fi
export VPS_NETWORK_ADJUST="$adjust"
{
  echo '# Managed by MXH VPS Deploy. Measured network tuning.'
  printf '# profile=%s\n' "$VPS_PARAM_PROFILE"
  # Preserve the persistence of all parameters that this profile does not adjust.
  python3 - <<'PY'
import os, re
from pathlib import Path
path = Path('/etc/sysctl.d/99-mxh-vps-deploy.conf')
changed = {'net.core.default_qdisc', 'net.ipv4.tcp_congestion_control'}
if os.environ['VPS_NETWORK_ADJUST'] == 'true':
    changed.update(('net.core.wmem_max', 'net.ipv4.tcp_wmem'))
if path.exists():
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([a-zA-Z0-9_.]+)\s*=', line)
        if not match or match.group(1) not in changed:
            print(line)
PY
  echo 'net.core.default_qdisc = fq'
  if [[ "$bbr" == true ]]; then echo 'net.ipv4.tcp_congestion_control = bbr'; else printf 'net.ipv4.tcp_congestion_control = %s\n' "$original_cc"; fi
  if [[ "$adjust" == true ]]; then
    printf 'net.core.wmem_max = %s\n' "$core_w"
    printf 'net.ipv4.tcp_wmem = %s %s %s\n' "$w_min" "$w_default" "$w_max"
  fi
} > "$temporary"
chmod 0644 "$temporary"
mxh_network expect-file "$snapshot" "$config" "$temporary" 0644
mv -T "$temporary" "$config"
# Apply only this profile's selected keys. Retained historical TFO, MTU and
# buffer persistence must not be replayed by a basic fq/BBR operation.
apply_key(){ mxh_network expect-sysctl "$snapshot" "$1" "$2"; sysctl -w "$1=$2" >/dev/null; }
apply_key net.core.default_qdisc fq
if [[ "$bbr" == true ]]; then apply_key net.ipv4.tcp_congestion_control bbr; fi
if [[ "$adjust" == true ]]; then
  apply_key net.core.wmem_max "$core_w"
  apply_key net.ipv4.tcp_wmem "$w_min $w_default $w_max"
fi
mxh_network apply "$snapshot"
mxh_network verify "$snapshot"
[[ "$(sysctl -n net.core.default_qdisc)" == fq ]]
if [[ "$bbr" == true ]]; then [[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == bbr ]]; fi
helper='/usr/local/libexec/mxh-network-queue'
unit='/etc/systemd/system/mxh-network-queue.service'
if [[ ! -d /usr/local/libexec ]]; then mkdir -m 0755 /usr/local/libexec; fi
{
  echo '#!/usr/bin/env bash'
  echo '# Managed by MXH VPS Deploy. Network queue persistence.'
  echo 'set -euo pipefail'
  declare -f mxh_network
  printf 'mxh_network ensure %q\n' "$snapshot"
} > "$temporary"
mxh_network expect-file "$snapshot" "$helper" "$temporary" 0750
install -m 0750 "$temporary" "$helper"
cat > "$temporary" <<EOF
# Managed by MXH VPS Deploy. Network queue persistence.
[Unit]
Description=Apply MXH fq to approved default interfaces
After=network-online.target systemd-sysctl.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$helper
[Install]
WantedBy=multi-user.target
EOF
mxh_network expect-file "$snapshot" "$unit" "$temporary" 0644
install -m 0644 "$temporary" "$unit"
systemctl daemon-reload
systemctl enable --now mxh-network-queue.service >/dev/null
mxh_network verify "$snapshot"
printf 'VPSDEPLOY_NETWORK_APPLIED\n'
printf 'VPSDEPLOY_BBR_B64=%s\n' "$(printf '%s' "$bbr" | base64 | tr -d '\n')"
