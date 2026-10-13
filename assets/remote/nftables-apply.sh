#!/usr/bin/env bash
set -euo pipefail

: "${VPS_PARAM_TCP_PORTS:?}"

restricted_port="${VPS_PARAM_RESTRICTED_PORT:-}"
allowed_ipv4s="${VPS_PARAM_ALLOWED_IPV4S:-}"
allowed_ipv6s="${VPS_PARAM_ALLOWED_IPV6S:-}"
check_only="${VPS_PARAM_CHECK_ONLY:-false}"

IFS=',' read -r -a ports <<<"$VPS_PARAM_TCP_PORTS"
(( ${#ports[@]} >= 2 )) || { echo 'At least two TCP ports are required.' >&2; exit 1; }
for port in "${ports[@]}"; do
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || exit 1
done
ports_rendered="$(IFS=', '; echo "${ports[*]}")"

restricted_rules=''
if [[ -n "$restricted_port" ]]; then
  [[ "$restricted_port" =~ ^[0-9]+$ ]] && (( restricted_port >= 1 && restricted_port <= 65535 )) || exit 1
  [[ -n "$allowed_ipv4s" || -n "$allowed_ipv6s" ]] || {
    echo 'Restricted port requires at least one source IP.' >&2
    exit 1
  }
  if [[ -n "$allowed_ipv4s" ]]; then
    python3 - "$allowed_ipv4s" 4 <<'PY'
import ipaddress
import sys
for value in sys.argv[1].split(','):
    if ipaddress.ip_address(value).version != int(sys.argv[2]):
        raise SystemExit("Invalid IPv4 allowlist")
PY
    IFS=',' read -r -a ipv4_items <<<"$allowed_ipv4s"
    ipv4_rendered="$(IFS=','; echo "${ipv4_items[*]}")"
    restricted_rules+="    ip saddr { ${ipv4_rendered} } tcp dport ${restricted_port} accept"$'\n'
    restricted_rules+="    ip saddr { ${ipv4_rendered} } udp dport ${restricted_port} accept"$'\n'
  fi
  if [[ -n "$allowed_ipv6s" ]]; then
    python3 - "$allowed_ipv6s" 6 <<'PY'
import ipaddress
import sys
for value in sys.argv[1].split(','):
    if ipaddress.ip_address(value).version != int(sys.argv[2]):
        raise SystemExit("Invalid IPv6 allowlist")
PY
    IFS=',' read -r -a ipv6_items <<<"$allowed_ipv6s"
    ipv6_rendered="$(IFS=','; echo "${ipv6_items[*]}")"
    restricted_rules+="    ip6 saddr { ${ipv6_rendered} } tcp dport ${restricted_port} accept"$'\n'
    restricted_rules+="    ip6 saddr { ${ipv6_rendered} } udp dport ${restricted_port} accept"$'\n'
  fi
fi

temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT
cat > "$temporary" <<EOF
#!/usr/sbin/nft -f

# Managed by MXH VPS Deploy.
table inet filter {}
flush table inet filter

table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;

    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    tcp dport { ${ports_rendered} } accept
${restricted_rules}    udp sport 67 udp dport 68 accept
    udp sport 547 udp dport 546 accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF

nft -c -f "$temporary"
if [[ "$check_only" == 'true' ]]; then
  printf 'VPSDEPLOY_NFT_CHECK_OK\n'
  exit 0
fi

config='/etc/nftables.conf'
if [[ -n "${VPS_PARAM_EXPECTED_TRANSACTION:-}" ]]; then
  mxh_firewall intent "$VPS_PARAM_EXPECTED_TRANSACTION/firewall-state.json" "$temporary"
fi
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/nftables"
install -d -m 0700 "$backup_dir"
if [[ -f "$config" ]]; then cp -a "$config" "$backup_dir/nftables.conf"; fi
install -o root -g root -m 0755 "$temporary" "$config"
nft -f "$config"
systemctl enable nftables.service
# Debian's ExecStop flushes every table. Do not restart during maintenance.
if ! systemctl is-active --quiet nftables.service; then systemctl start nftables.service; fi
systemctl is-active --quiet nftables.service
active_ruleset="$(nft list ruleset)"
tcp_rules="$(grep -E 'tcp dport' <<<"$active_ruleset" || true)"
udp_rules="$(grep -E 'udp dport' <<<"$active_ruleset" || true)"
for port in "${ports[@]}"; do
  grep -Eq "(^|[^0-9])${port}([^0-9]|$)" <<<"$tcp_rules" || {
    echo "Port missing from nftables: $port" >&2
    exit 1
  }
done
if [[ -n "$restricted_port" ]]; then
  grep -Eq "(^|[^0-9])${restricted_port}([^0-9]|$)" <<<"$tcp_rules" || exit 1
  grep -Eq "(^|[^0-9])${restricted_port}([^0-9]|$)" <<<"$udp_rules" || exit 1
fi
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
