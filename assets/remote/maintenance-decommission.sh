#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_SCOPE:?}"
[[ "$VPS_PARAM_SCOPE" == 'Disable' || "$VPS_PARAM_SCOPE" == 'RemoveManaged' ]]
remove_controller="${VPS_PARAM_REMOVE_CONTROLLER:-false}"
[[ "$remove_controller" == 'true' || "$remove_controller" == 'false' ]]
for service in xray.service sing-box-anytls.service sing-box.service komari-agent.service; do systemctl disable --now "$service" >/dev/null 2>&1 || true; done
if [[ "$VPS_PARAM_SCOPE" == 'RemoveManaged' ]]; then
  rm -f /usr/local/bin/xray /usr/local/bin/sing-box-anytls /usr/local/bin/sing-box /usr/local/bin/komari-agent
  rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/sing-box-anytls /var/lib/sing-box-anytls /etc/sing-box /var/lib/sing-box /etc/komari-agent /var/lib/komari-agent
  rm -f /etc/systemd/system/xray.service /etc/systemd/system/xray@.service /etc/systemd/system/sing-box-anytls.service /etc/systemd/system/sing-box.service /etc/systemd/system/komari-agent.service
  rm -rf /etc/systemd/system/xray.service.d /etc/systemd/system/sing-box.service.d
  rm -f /etc/nginx/sites-enabled/mxh-reality-target /etc/nginx/sites-available/mxh-reality-target
  rm -rf /var/www/mxh-reality-target
  # Certificates and their renewal owner are shared, retained materials, just
  # as in individual protocol uninstall. Keep them for safe reinstallation.
  systemctl daemon-reload
fi
if [[ "$remove_controller" == 'true' ]]; then
  systemctl disable --now cloudflared.service komari.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/cloudflared.service /etc/systemd/system/komari.service /usr/local/bin/cloudflared /usr/local/bin/komari
  rm -rf /var/lib/komari /opt/komari
  systemctl daemon-reload
fi
for service in xray.service sing-box-anytls.service sing-box.service komari-agent.service; do ! systemctl is-active --quiet "$service" 2>/dev/null; done
printf '%s\n' 'VPSDEPLOY_DECOMMISSION_OK'
