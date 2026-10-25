#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import ipaddress, json, os, socket, time, base64
host = str(ipaddress.IPv4Address(os.environ['VPS_PARAM_ADDRESS']))
port = int(os.environ['VPS_PARAM_PORT'])
if not 1 <= port <= 65535:
    raise SystemExit('Invalid TCP path port.')
started = time.monotonic()
with socket.create_connection((host, port), 8) as stream:
    result = {'Address': host, 'Port': port, 'SourceAddress': stream.getsockname()[0],
              'Status': 'Connected', 'Scope': 'TcpConnectOnly', 'Milliseconds': round((time.monotonic()-started)*1000)}
print('VPSDEPLOY_TCP_CHAIN_PROBE_B64=' + base64.b64encode(json.dumps(result).encode()).decode())
PY
printf '%s\n' VPSDEPLOY_TCP_CHAIN_PROBED
