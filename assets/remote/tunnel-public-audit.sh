#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_PUBLIC_URL:?}" "${VPS_PARAM_CONTROLLER_PORT:?}" "${VPS_PARAM_METRICS_PORT:?}"
python3 - <<'PY'
import base64
import json
import os
import socket
import ssl
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
result = {'Passed': False, 'Code': '', 'ConnectorReady': False, 'LocalVersion': '', 'PublicVersion': '', 'HttpStatus': 0}

def get(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'May-VPS-Deploy/TunnelAccess', 'Accept': 'application/json'})
    with opener.open(request, timeout=15) as response:
        data = response.read(65537)
        if response.status != 200 or len(data) > 65536:
            raise ValueError('WrongApplication')
        return data

def version(url):
    data = json.loads(get(url))
    value = data.get('data', {}).get('version') if isinstance(data, dict) else None
    if not isinstance(value, str) or not value: raise ValueError('WrongApplication')
    return value.removeprefix('v')

try:
    try:
        get('http://127.0.0.1:' + os.environ['VPS_PARAM_METRICS_PORT'] + '/ready')
        result['ConnectorReady'] = True
    except Exception:
        raise ValueError('TunnelNotConnected')
    try:
        result['LocalVersion'] = version('http://127.0.0.1:' + os.environ['VPS_PARAM_CONTROLLER_PORT'] + '/api/version')
    except Exception:
        raise ValueError('ControllerUnavailable')
    result['PublicVersion'] = version(os.environ['VPS_PARAM_PUBLIC_URL'].rstrip('/') + '/api/version')
    if result['PublicVersion'] != result['LocalVersion']: raise ValueError('VersionMismatch')
    result['Passed'] = True
except urllib.error.HTTPError as error:
    result['Code'] = 'HttpRejected'
    result['HttpStatus'] = error.code
except urllib.error.URLError as error:
    result['Code'] = 'DnsFailure' if isinstance(error.reason, socket.gaierror) else 'TlsFailure' if isinstance(error.reason, ssl.SSLError) else 'Timeout' if isinstance(error.reason, TimeoutError) else 'HttpRejected'
except (TimeoutError, socket.timeout):
    result['Code'] = 'Timeout'
except (ValueError, TypeError, AttributeError, KeyError) as error:
    result['Code'] = str(error) if str(error) in ('TunnelNotConnected', 'ControllerUnavailable', 'VersionMismatch') else 'WrongApplication'
print('VPSDEPLOY_TUNNEL_ACCESS_B64=' + base64.b64encode(json.dumps(result).encode()).decode())
PY
printf '%s\n' 'VPSDEPLOY_TUNNEL_ACCESS_OK'
