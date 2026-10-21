#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_ROLE:?}"
: "${VPS_PARAM_PROBES_JSON:?}"
case "$VPS_PARAM_ROLE" in
  RealityEntry) binary=/usr/local/bin/xray ;;
  AnyTlsEntry) binary=/usr/local/bin/sing-box-anytls ;;
  *) exit 1 ;;
esac
for path in /usr/local /usr/local/bin "$binary"; do [[ ! -L "$path" ]] || exit 1; done
[[ -f "$binary" && -x "$binary" ]]
exec python3 - "$binary" "$VPS_PARAM_ROLE" <<'PY'
import base64
import copy
import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

PROBE_HOST_V4 = 'api.ipify.org'
PROBE_HOST_V6 = 'api64.ipify.org'
PROBE_PORT = 443


def interrupted(*_):
    raise InterruptedError('Probe interrupted')


def exact(sock, count):
    result = b''
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise ValueError('Incomplete SOCKS response')
        result += chunk
    return result


def query(port, host, timeout):
    context = ssl.create_default_context()
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(bytes([5, 1, 0]))
        if exact(stream, 2) != bytes([5, 0]):
            raise ValueError('SOCKS negotiation failed')
        encoded = host.encode('idna')
        stream.sendall(bytes([5, 1, 0, 3, len(encoded)]) + encoded + PROBE_PORT.to_bytes(2, 'big'))
        header = exact(stream, 4)
        if header[:3] != bytes([5, 0, 0]):
            raise ValueError('SOCKS connect failed')
        size = 4 if header[3] == 1 else 16 if header[3] == 4 else exact(stream, 1)[0] if header[3] == 3 else 0
        if not size:
            raise ValueError('Invalid SOCKS address')
        exact(stream, size + 2)
        with context.wrap_socket(stream, server_hostname=host) as tls:
            connection = http.client.HTTPSConnection(host, PROBE_PORT, timeout=timeout)
            connection.sock = tls
            try:
                connection.request('GET', '/', headers={'Host': host, 'Connection': 'close', 'User-Agent': 'May-Deploy-Validation'})
                response = connection.getresponse()
                payload = response.read(129)
                if response.status != 200 or len(payload) > 128:
                    raise ValueError('Invalid egress response')
                return str(ipaddress.ip_address(payload.decode('ascii').strip()))
            finally:
                connection.close()


def validate(probes, role):
    if role not in ('RealityEntry', 'AnyTlsEntry') or not isinstance(probes, list) or not 1 <= len(probes) <= 7:
        raise ValueError('Invalid probe scope')
    seen = set()
    methods = {'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'}
    for item in probes:
        if not isinstance(item, dict) or set(item) != {'Id', 'ExpectedAddress', 'Outbound'} or not isinstance(item['Id'], str) or not re.fullmatch('[a-f0-9]{16}', item['Id']) or item['Id'] in seen:
            raise ValueError('Invalid probe reference')
        seen.add(item['Id'])
        ipaddress.ip_address(item['ExpectedAddress'])
        native = item['Outbound']
        if not isinstance(native, dict):
            raise ValueError('Invalid outbound')
        if role == 'RealityEntry':
            if set(native) != {'tag', 'protocol', 'settings'} or native['protocol'] != 'shadowsocks' or set(native['settings']) != {'servers'} or len(native['settings']['servers']) != 1:
                raise ValueError('Invalid Xray outbound')
            server = native['settings']['servers'][0]
            if set(server) != {'address', 'port', 'method', 'password'}:
                raise ValueError('Invalid Xray server')
            host, port = server['address'], server['port']
        else:
            if set(native) != {'tag', 'type', 'server', 'server_port', 'method', 'password'} or native['type'] != 'shadowsocks':
                raise ValueError('Invalid sing-box outbound')
            server = native
            host, port = server['server'], server['server_port']
        ipaddress.ip_address(host)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or server['method'] not in methods or not isinstance(server['password'], str) or not 1 <= len(server['password']) <= 4096:
            raise ValueError('Invalid Shadowsocks parameters')
        if native['tag'] != 'may-hop-' + item['Id']:
            raise ValueError('Unowned outbound tag')


def run_probe(binary, role, item):
    deadline = time.monotonic() + 20
    with tempfile.TemporaryDirectory(prefix='may-hop-probe-') as directory:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        outbound = copy.deepcopy(item['Outbound'])
        outbound['tag'] = 'probe-out'
        if role == 'RealityEntry':
            configuration = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}], 'outbounds': [outbound]}
        else:
            configuration = {'log': {'level': 'error'}, 'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}], 'outbounds': [outbound], 'route': {'final': 'probe-out'}}
        path = Path(directory) / 'probe.json'
        path.write_text(json.dumps(configuration), encoding='utf-8')
        command = [binary, 'run', '-config' if role == 'RealityEntry' else '-c', str(path)]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            while True:
                if process.poll() is not None or time.monotonic() > deadline - 12:
                    raise ValueError('Probe core not ready')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.15):
                        break
                except OSError:
                    time.sleep(0.05)
            expected = ipaddress.ip_address(item['ExpectedAddress'])
            actual = query(port, PROBE_HOST_V6 if expected.version == 6 else PROBE_HOST_V4, min(10, deadline - time.monotonic()))
            if actual != str(expected):
                raise ValueError('Egress mismatch')
            return {'Id': item['Id'], 'Status': 'Passed', 'Egress': actual, 'From': 'EntryServer', 'Network': 'TCP'}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            process.wait(timeout=2)


def main():
    os.umask(0o077)
    for name in ('SIGTERM', 'SIGHUP', 'SIGALRM'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    if hasattr(signal, 'alarm'):
        signal.alarm(210)
    probes = json.loads(os.environ['VPS_PARAM_PROBES_JSON'])
    binary, role = sys.argv[1:3]
    validate(probes, role)
    result = {'Status': 'Passed', 'Items': [run_probe(binary, role, item) for item in probes], 'At': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    print('VPSDEPLOY_HOP_VALIDATION_B64=' + base64.b64encode(json.dumps(result).encode()).decode())
    print('VPSDEPLOY_SERVER_HOPS_PASSED')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Server TCP next-hop verification failed; no service configuration was changed by this probe.', file=sys.stderr)
        sys.exit(1)
PY
