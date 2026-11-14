#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_EXPECTED_TRANSACTION:?}"
export DEBIAN_FRONTEND=noninteractive
if ! /usr/bin/python3 -c 'import certbot.main, certbot_dns_cloudflare'; then
  apt-get -o DPkg::Lock::Timeout=60 update -qq >/dev/null
  vps_transaction_check
  apt-get -o DPkg::Lock::Timeout=60 install -y -qq certbot python3-certbot-dns-cloudflare ca-certificates openssl >/dev/null
fi
/usr/bin/python3 -c 'import certbot.main, certbot_dns_cloudflare'
printf '%s\n' VPSDEPLOY_CERTIFICATE_PREPARED
