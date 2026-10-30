#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import ipaddress, json, os, socket, time, base64
host = str(ipaddress.ip_address(os.environ['VPS_PARAM_ADDRESS']))
port = int(os.environ['VPS_PARAM_PORT'])
if not 1 <= port <= 65535:
    raise SystemExit('Invalid TCP path port.')
started = time.monotonic()
udp = os.environ.get('VPS_PARAM_TRANSPORT', 'TCP') == 'UDP'
family = socket.AF_INET6 if ':' in host else socket.AF_INET
with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as stream:
    stream.settimeout(8)
    stream.connect((host, port))
    result = {'Address': host, 'Port': port, 'SourceAddress': stream.getsockname()[0],
              'Status': 'RouteAvailable' if udp else 'Connected', 'Scope': 'UdpRouteOnly' if udp else 'TcpConnectOnly', 'Milliseconds': round((time.monotonic()-started)*1000)}
print('VPSDEPLOY_TCP_CHAIN_PROBE_B64=' + base64.b64encode(json.dumps(result).encode()).decode())
PY
printf '%s\n' VPSDEPLOY_TCP_CHAIN_PROBED
