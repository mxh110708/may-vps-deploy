#!/usr/bin/env bash
set -Eeuo pipefail

phase='initialization'
emit_safe_error() {
  local message="$1"
  printf 'VPSDEPLOY_CERTBOT_SAFE_ERROR_B64=%s\n' "$(printf '%s' "$message" | base64 | tr -d '\n')"
}
report_failure() {
  local status="$?"
  trap - ERR
  emit_safe_error "Certbot DNS-01 在阶段 ${phase} 失败（退出码 ${status}）；敏感输出已隐藏。请修复该阶段后继续未完成部署。"
  exit "$status"
}
trap report_failure ERR

: "${VPS_PARAM_CLOUDFLARE_TOKEN:?}"
: "${VPS_PARAM_ZONE_NAME:?}"
: "${VPS_PARAM_EMAIL:?}"
anytls_enabled="${VPS_PARAM_ANYTLS_ENABLED:-false}"
reality_enabled="${VPS_PARAM_REALITY_ENABLED:-false}"
propagation_seconds="${VPS_PARAM_PROPAGATION_SECONDS:-30}"
preserve_credentials="${VPS_PARAM_PRESERVE_EXISTING_CREDENTIALS:-false}"
[[ "$preserve_credentials" == true || "$preserve_credentials" == false ]]
credentials_path=/etc/letsencrypt/cloudflare.ini
if [[ "$preserve_credentials" == true ]]; then credentials_path=/etc/letsencrypt/mxh-anytls-cloudflare.ini; fi

[[ "$anytls_enabled" == 'true' || "$reality_enabled" == 'true' ]] || {
  echo 'No trusted TLS certificate was requested.' >&2
  exit 1
}

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
zone_json="$work/zone.json"
runner_path=/usr/local/libexec/mxh-certbot-dns
if [[ -e "$runner_path" || -L "$runner_path" ]]; then
  if [[ ! -f "$runner_path" || -L "$runner_path" ]] || ! grep -Fxq '# MXH managed Cloudflare DNS API transport' "$runner_path"; then
    emit_safe_error 'DNS API 执行器路径已被其他文件占用，未覆盖。'
    exit 22
  fi
fi
phase='cloudflare-zone-api'
# Prefer IPv4, then try IPv6. A dual-stack machine may have several IPv6
# addresses while the token permits only one. Keep the successful source for
# issuance and renewal rather than letting each Python request choose again.
zone_curl_status=1
for api_family in -4 -6; do
  set +e
  zone_meta="$(curl "$api_family" --silent --show-error --get --output "$zone_json" \
    --connect-timeout 15 --max-time 45 --write-out $'%{http_code}\t%{local_ip}' \
    --header "Authorization: Bearer ${VPS_PARAM_CLOUDFLARE_TOKEN}" \
    --data-urlencode "name=${VPS_PARAM_ZONE_NAME}" \
    'https://api.cloudflare.com/client/v4/zones')"
  zone_curl_status="$?"
  set -e
  if [[ "$zone_curl_status" -eq 0 ]] && python3 - "$zone_json" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        body = json.load(handle)
    ok = body.get("success") and len(body.get("result") or []) == 1
except (OSError, ValueError, AttributeError):
    ok = False
raise SystemExit(0 if ok else 1)
PY
  then break; fi
done
if [[ "$zone_curl_status" -ne 0 ]]; then
  safe_error='Cloudflare Zone API 连接失败；请检查 VPS 的 DNS、IPv4/IPv6 出口和到 api.cloudflare.com 的 HTTPS 连通性。'
  emit_safe_error "$safe_error"
  exit 20
fi
zone_http="${zone_meta%%$'\t'*}"
zone_local_ip="${zone_meta#*$'\t'}"
zone_error="$(python3 - "$zone_json" "$zone_http" "$zone_local_ip" <<'PY'
import json
import sys

path, http_status, local_ip = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except Exception:
    print(f"Cloudflare Zone API 返回了不可解析响应（HTTP {http_status}）。")
    raise SystemExit

results = data.get("result") or []
if data.get("success") and len(results) == 1:
    raise SystemExit

codes = ",".join(str(item.get("code")) for item in (data.get("errors") or []) if isinstance(item, dict)) or "unknown"
family = "IPv6" if ":" in local_ip else "IPv4"
print(
    f"Cloudflare Zone API 拒绝 Token（HTTP {http_status} / code {codes}；"
    f"实际请求源地址 {local_ip}，{family}）。请确认 Token 为有效 API Token、"
    "包含 Zone:Read 与 DNS:Edit，并把该 VPS 实际使用的 IPv4/IPv6 地址加入客户端 IP 筛选。"
)
PY
)"
if [[ -n "$zone_error" ]]; then
  emit_safe_error "$zone_error"
  exit 21
fi

phase='backup-existing-certbot-state'
stamp="$(date -u +%Y%m%d-%H%M%S)"
backup_dir="/root/vps-deploy-backups/${stamp}/certbot-dns"
install -d -m 0700 "$backup_dir"
for existing in \
  /etc/letsencrypt/cloudflare.ini \
  /usr/local/libexec/mxh-certbot-dns \
  /usr/local/libexec/mxh-certbot-deploy \
  /etc/systemd/system/mxh-certbot-renew.service \
  /etc/systemd/system/mxh-certbot-renew.timer; do
  if [[ -f "$existing" ]]; then
    cp -a "$existing" "$backup_dir/$(basename "$existing")"
  fi
done

export DEBIAN_FRONTEND=noninteractive
apt_get_retry() {
  local attempt output status
  for attempt in 1 2 3 4 5 6; do
    set +e
    output="$(apt-get -o DPkg::Lock::Timeout=60 "$@" 2>&1)"
    status="$?"
    set -e
    if [[ "$status" -eq 0 ]]; then printf '%s\n' "$output"; return 0; fi
    if ! grep -Eqi 'could not get lock|unable to acquire.*lock|is another process using it' <<<"$output"; then printf '%s\n' "$output" >&2; return "$status"; fi
    printf 'Waiting for apt/dpkg lock (attempt %s/6).\n' "$attempt" >&2
    sleep 5
  done
  printf '%s\n' "$output" >&2
  return "$status"
}
phase='apt-update'
apt_get_retry update -qq
phase='apt-install-certbot'
apt_get_retry install -y -qq certbot python3-certbot-dns-cloudflare ca-certificates >/dev/null
phase='certbot-runtime-validation'
certbot_plugins="$(certbot plugins 2>/dev/null)"
grep -Fq 'dns-cloudflare' <<< "$certbot_plugins"
# The distribution timer does not run our explicit deploy hook. Keep a single
# renewal owner so a renewed certificate is always copied and the service is
# reloaded in the same transaction.
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
systemctl disable --now certbot.timer >/dev/null 2>&1 || true

phase='cloudflare-credentials-install'
install -d -o root -g root -m 0700 /etc/letsencrypt
credentials_tmp="$work/cloudflare.ini"
printf 'dns_cloudflare_api_token = %s\n' "$VPS_PARAM_CLOUDFLARE_TOKEN" > "$credentials_tmp"
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
install -o root -g root -m 0600 "$credentials_tmp" "$credentials_path"

if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
install -d -o root -g root -m 0755 /usr/local/libexec
[[ ! -L /usr/local/libexec/mxh-certbot-dns ]]
# Migrate the historical global source to the original credential file before
# replacing the runner. Each credential keeps its own transport thereafter.
python3 - "$runner_path" "$credentials_path" "$zone_local_ip" <<'PY'
import ipaddress, os, pathlib, re, sys
runner, credentials, source = map(str, sys.argv[1:])
old = pathlib.Path('/etc/letsencrypt/cloudflare.ini.mxh-source')
if pathlib.Path(runner).exists() and not old.exists():
    match = re.search(r'^DNS_API_SOURCE = "([^"\n]+)"$', pathlib.Path(runner).read_text(), re.M)
    if match:
        old.write_text(str(ipaddress.ip_address(match[1])) + '\n'); os.chmod(old, 0o600)
path = pathlib.Path(credentials + '.mxh-source')
if path.is_symlink() or any(p.is_symlink() for p in path.parents): raise SystemExit('Linked DNS source metadata.')
path.write_text(str(ipaddress.ip_address(source)) + '\n'); os.chmod(path, 0o600)
PY
certbot_runner="$work/mxh-certbot-dns"
printf '#!/usr/bin/python3\n# MXH managed Cloudflare DNS API transport\n' > "$certbot_runner"
cat >> "$certbot_runner" <<'RUNNER'
import configparser
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib3.util import connection

def option(name):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else None

if len(sys.argv) > 1 and sys.argv[1] == 'renew' and '--cert-name' not in sys.argv:
    # One process per lineage lets different DNS tokens bind different sources.
    outcomes = [subprocess.run([sys.executable, sys.argv[0], *sys.argv[1:], '--cert-name', path.stem]).returncode for path in sorted(Path('/etc/letsencrypt/renewal').glob('*.conf'))]
    sys.exit(1 if any(outcomes) else 0)

credentials = option('--dns-cloudflare-credentials')
if credentials is None and option('--cert-name'):
    name = option('--cert-name')
    if Path(name).name != name: raise SystemExit('Invalid certificate lineage.')
    settings = configparser.ConfigParser(interpolation=None)
    settings.read_string('[lineage]\n' + Path('/etc/letsencrypt/renewal/' + name + '.conf').read_text())
    credentials = settings.get('renewalparams', 'dns_cloudflare_credentials', fallback=None)
source_text = globals().get('DNS_API_SOURCE')  # compatibility with older saved runners
if credentials:
    metadata = Path(credentials + '.mxh-source')
    if metadata.is_symlink() or any(p.is_symlink() for p in metadata.parents): raise SystemExit('Linked DNS source metadata.')
    if metadata.exists():
        if metadata.stat().st_uid != 0 or metadata.stat().st_mode & 0o077: raise SystemExit('Unowned DNS source metadata.')
        source_text = metadata.read_text().strip()
if source_text is None:
    from certbot.main import main
    sys.exit(main())
source = ipaddress.ip_address(source_text)
source_family = socket.AF_INET6 if source.version == 6 else socket.AF_INET
getaddrinfo = socket.getaddrinfo
create_connection = connection.create_connection

def is_cloudflare_api(host):
    if isinstance(host, bytes):
        host = host.decode("ascii")
    return isinstance(host, str) and host.rstrip(".").lower() == "api.cloudflare.com"

def resolve(host, port, family=0, type=0, proto=0, flags=0):
    return getaddrinfo(host, port, source_family if is_cloudflare_api(host) else family,
                       type, proto, flags)

def connect(address, *args, **kwargs):
    if is_cloudflare_api(address[0]):
        if len(args) >= 2:
            args = (args[0], (str(source), 0), *args[2:])
        else:
            kwargs["source_address"] = (str(source), 0)
    return create_connection(address, *args, **kwargs)

# This process alone pins Cloudflare's DNS API. ACME traffic, certificate
# validation, DNS resolution for other services and global routing are unchanged.
socket.getaddrinfo = resolve
connection.create_connection = connect
from certbot.main import main
sys.exit(main())
RUNNER
install -o root -g root -m 0750 "$certbot_runner" /usr/local/libexec/mxh-certbot-dns
cat > /usr/local/libexec/mxh-certbot-deploy <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail

: "${RENEWED_LINEAGE:?}"
cert_name="$(basename "$RENEWED_LINEAGE")"
case "$cert_name" in
  mxh-anytls)
    destination='/etc/mxh-tls/anytls'
    group='sing-box-anytls'
    ;;
  mxh-reality-target)
    destination='/etc/mxh-tls/reality-target'
    group='root'
    ;;
  *)
    exit 0
    ;;
esac

getent group "$group" >/dev/null 2>&1 || groupadd --system "$group"
install -d -o root -g "$group" -m 0750 "$destination"
fullchain_tmp="$(mktemp -p "$destination" .fullchain.XXXXXX)"
privkey_tmp="$(mktemp -p "$destination" .privkey.XXXXXX)"
cleanup() { rm -f "$fullchain_tmp" "$privkey_tmp"; }
trap cleanup EXIT
install -o root -g "$group" -m 0644 "$RENEWED_LINEAGE/fullchain.pem" "$fullchain_tmp"
install -o root -g "$group" -m 0640 "$RENEWED_LINEAGE/privkey.pem" "$privkey_tmp"
mv -f "$fullchain_tmp" "$destination/fullchain.pem"
mv -f "$privkey_tmp" "$destination/privkey.pem"

if [[ "$cert_name" == 'mxh-anytls' ]] && systemctl is-active --quiet sing-box-anytls.service; then
  /usr/local/bin/sing-box-anytls check -c /etc/sing-box-anytls/config.json
  systemctl restart sing-box-anytls.service
fi
if [[ "$cert_name" == 'mxh-reality-target' ]] && systemctl is-active --quiet nginx.service; then
  nginx -t
  systemctl reload nginx.service
fi
HOOK
chmod 0750 /usr/local/libexec/mxh-certbot-deploy

cat > /etc/systemd/system/mxh-certbot-renew.service <<'EOF'
[Unit]
Description=MXH Certbot DNS-01 certificate renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/mxh-certbot-dns renew --quiet --no-random-sleep-on-renew --deploy-hook /usr/local/libexec/mxh-certbot-deploy
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

cat > /etc/systemd/system/mxh-certbot-renew.timer <<'EOF'
[Unit]
Description=Run MXH Certbot renewal twice daily

[Timer]
OnCalendar=*-*-* 03,15:17:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/mxh-certbot-renew.service /etc/systemd/system/mxh-certbot-renew.timer

issue_certificate() {
  local cert_name="$1"
  local domains_csv="$2"
  local -a domain_args=()
  local domain
  IFS=',' read -r -a domains <<<"$domains_csv"
  for domain in "${domains[@]}"; do
    [[ -n "$domain" ]] || continue
    domain_args+=('-d' "$domain")
  done
  [[ "${#domain_args[@]}" -gt 0 ]] || { echo 'Certificate domain list is empty.' >&2; exit 1; }

  phase='certificate-issuance'
  if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
  /usr/local/libexec/mxh-certbot-dns certonly \
    --non-interactive --agree-tos --email "$VPS_PARAM_EMAIL" \
    --dns-cloudflare --dns-cloudflare-credentials "$credentials_path" \
    --dns-cloudflare-propagation-seconds "$propagation_seconds" \
    --key-type ecdsa --elliptic-curve secp256r1 \
    --cert-name "$cert_name" --keep-until-expiring \
    "${domain_args[@]}" >/dev/null
  # certonly can keep a still-valid certificate and its old renewal parameters.
  # Bind only this managed lineage to its selected credential file; otherwise a
  # reinstallation would dry-run/renew with the previous token's transport.
  python3 - "$cert_name" "$credentials_path" <<'RENEWAL'
import configparser, os, pathlib, re, sys
name, credentials = sys.argv[1:]
if pathlib.Path(name).name != name: raise SystemExit('Invalid managed lineage.')
path = pathlib.Path('/etc/letsencrypt/renewal') / (name + '.conf')
if path.is_symlink() or any(p.is_symlink() for p in path.parents) or path.stat().st_uid != 0: raise SystemExit('Unowned renewal configuration.')
text = path.read_text(); parser = configparser.ConfigParser(interpolation=None); parser.read_string('[lineage]\n'+text)
section = parser['renewalparams']
allowed = ('/etc/letsencrypt/cloudflare.ini', '/etc/letsencrypt/mxh-anytls-cloudflare.ini')
if section.get('authenticator') != 'dns-cloudflare' or section.get('dns_cloudflare_credentials') not in allowed or credentials not in allowed: raise SystemExit('Unmanaged DNS renewal configuration.')
head, body = text.split('[renewalparams]', 1)
updated, count = re.subn(r'(?m)^dns_cloudflare_credentials\s*=.*$', 'dns_cloudflare_credentials = '+credentials, body)
if count != 1: raise SystemExit('Ambiguous renewal credentials.')
temporary = path.with_suffix('.mxh-write')
if temporary.exists() or temporary.is_symlink(): raise SystemExit('Renewal update path occupied.')
with temporary.open('x') as file: file.write(head+'[renewalparams]'+updated)
os.chmod(temporary, path.stat().st_mode & 0o777); os.replace(temporary, path)
RENEWAL
  phase='certificate-deploy-hook'
  if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
  RENEWED_LINEAGE="/etc/letsencrypt/live/$cert_name" \
    RENEWED_DOMAINS="$domains_csv" /usr/local/libexec/mxh-certbot-deploy
  phase='certificate-renewal-dry-run'
  /usr/local/libexec/mxh-certbot-dns renew --cert-name "$cert_name" --dry-run --quiet --no-random-sleep-on-renew >/dev/null
}

if [[ "$anytls_enabled" == 'true' ]]; then
  : "${VPS_PARAM_ANYTLS_CERT_NAME:?}"
  : "${VPS_PARAM_ANYTLS_DOMAINS:?}"
  issue_certificate "$VPS_PARAM_ANYTLS_CERT_NAME" "$VPS_PARAM_ANYTLS_DOMAINS"
fi
if [[ "$reality_enabled" == 'true' ]]; then
  : "${VPS_PARAM_REALITY_CERT_NAME:?}"
  : "${VPS_PARAM_REALITY_DOMAINS:?}"
  issue_certificate "$VPS_PARAM_REALITY_CERT_NAME" "$VPS_PARAM_REALITY_DOMAINS"
fi

phase='renewal-timer-validation'
if declare -F vps_transaction_check >/dev/null; then vps_transaction_check; fi
systemctl daemon-reload
systemctl enable --now mxh-certbot-renew.timer >/dev/null
systemctl is-enabled --quiet mxh-certbot-renew.timer
systemctl is-active --quiet mxh-certbot-renew.timer
! systemctl is-active --quiet certbot.timer
[[ "$(stat -c '%a' "$credentials_path")" == '600' ]]

certbot_version="$(certbot --version 2>&1 | awk '{print $2}')"
printf 'VPSDEPLOY_CERTBOT_VERSION_B64=%s\n' "$(printf '%s' "$certbot_version" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_BACKUP_DIR_B64=%s\n' "$(printf '%s' "$backup_dir" | base64 | tr -d '\n')"
printf 'VPSDEPLOY_CERTBOT_DNS_OK\n'
