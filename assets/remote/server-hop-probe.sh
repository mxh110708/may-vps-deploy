#!/usr/bin/env bash
set -euo pipefail
: "${VPS_PARAM_ROLE:?}"
: "${VPS_PARAM_PROBES_JSON_FILE:?}"
case "$VPS_PARAM_ROLE" in
  RealityEntry) binary=/usr/local/bin/xray ;;
  AnyTlsEntry) binary=/usr/local/bin/sing-box-anytls ;;
  *) exit 1 ;;
esac
for path in /usr/local /usr/local/bin "$binary"; do [[ ! -L "$path" ]] || exit 1; done
[[ -f "$binary" && -x "$binary" ]]
python3 - "$binary" "$VPS_PARAM_ROLE" <<'PY'
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
import uuid

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


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise ValueError('Unsupported next-hop fields')


def tls_parameters(value, xray=False):
    if xray:
        fields(value, ('serverName', 'allowInsecure', 'minVersion', 'alpn'), ('certificates', 'disableSystemRoot'))
        if value['allowInsecure'] is not False or value['minVersion'] != '1.3' or value['alpn'] != ['h3']:
            raise ValueError('Invalid Xray TLS trust')
        name = value['serverName']
        if 'certificates' in value:
            if value.get('disableSystemRoot') is not True or not isinstance(value['certificates'], list) or len(value['certificates']) != 1:
                raise ValueError('Invalid Xray trust scope')
            cert = value['certificates'][0]
            fields(cert, ('usage', 'certificate'))
            if cert['usage'] != 'verify':
                raise ValueError('Invalid trust usage')
            pem = cert['certificate']
        else:
            if 'disableSystemRoot' in value:
                raise ValueError('Invalid trust scope')
            pem = None
    else:
        fields(value, ('enabled', 'server_name'), ('insecure', 'min_version', 'alpn', 'certificate'))
        if value['enabled'] is not True or value.get('insecure', False) is not False or value.get('min_version', '1.3') != '1.3' or value.get('alpn', ['h3']) != ['h3']:
            raise ValueError('Invalid sing-box TLS trust')
        name, pem = value['server_name'], value.get('certificate')
    if not isinstance(name, str) or not 1 <= len(name) <= 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', name):
        raise ValueError('Invalid SNI')
    if pem is not None:
        if isinstance(pem, list) and all(isinstance(line, str) for line in pem):
            pem = '\n'.join(pem)
        if not isinstance(pem, str) or not 1 <= len(pem) <= 65536 or 'PRIVATE KEY' in pem:
            raise ValueError('Invalid public trust certificate')
        ssl.create_default_context().load_verify_locations(cadata=pem)


def quic_parameters(native, xray):
    if xray:
        fields(native, ('tag', 'protocol', 'settings', 'streamSettings'))
        settings, stream = native['settings'], native['streamSettings']
        fields(settings, ('version', 'address', 'port'))
        fields(stream, ('network', 'security', 'tlsSettings', 'hysteriaSettings', 'finalmask'))
        fields(stream['hysteriaSettings'], ('version', 'auth'))
        if settings['version'] != 2 or stream['network'] != 'hysteria' or stream['security'] != 'tls' or stream['hysteriaSettings']['version'] != 2:
            raise ValueError('Invalid Hysteria transport')
        tls_parameters(stream['tlsSettings'], True)
        mask = stream['finalmask']; fields(mask, ('quicParams',), ('udp',))
        params = mask['quicParams']; fields(params, ('congestion',), ('brutalUp', 'brutalDown', 'udpHop'))
        if params['congestion'] not in ('bbr', 'brutal'):
            raise ValueError('Invalid Hysteria congestion')
        for rate in ('brutalUp', 'brutalDown'):
            if rate in params and (not isinstance(params[rate], str) or not re.fullmatch(r'[1-9][0-9]{0,5} Mbps', params[rate])):
                raise ValueError('Invalid Hysteria rate')
        if 'udpHop' in params:
            fields(params['udpHop'], ('ports', 'interval'))
            if not isinstance(params['udpHop']['ports'], str) or not re.fullmatch(r'[0-9,-]{1,1024}', params['udpHop']['ports']):
                raise ValueError('Invalid hopping ports')
            interval = params['udpHop']['interval']
            if isinstance(interval, bool) or not isinstance(interval, (int, str)) or not re.fullmatch(r'[0-9]{1,4}(?:-[0-9]{1,4})?', str(interval)):
                raise ValueError('Invalid hopping interval')
        if 'udp' in mask:
            if not isinstance(mask['udp'], list) or len(mask['udp']) != 1:
                raise ValueError('Invalid UDP mask')
            fields(mask['udp'][0], ('type', 'settings')); fields(mask['udp'][0]['settings'], ('password',))
            if mask['udp'][0]['type'] != 'salamander':
                raise ValueError('Invalid UDP mask type')
        host, port, password = settings['address'], settings['port'], stream['hysteriaSettings']['auth']
    else:
        tuic = native['type'] == 'tuic'
        fields(native, ('tag', 'type', 'server', 'server_port', 'password', 'tls'),
               ('uuid', 'congestion_control', 'udp_relay_mode', 'heartbeat', 'zero_rtt_handshake') if tuic else ('up_mbps', 'down_mbps', 'obfs', 'server_ports', 'hop_interval', 'hop_interval_max'))
        tls_parameters(native['tls'])
        if tuic:
            import uuid
            if not uuid.UUID(native['uuid']).int or native.get('zero_rtt_handshake', False) is not False or native.get('congestion_control', 'cubic') not in ('cubic', 'new_reno', 'bbr') or native.get('udp_relay_mode', 'native') not in ('native', 'quic'):
                raise ValueError('Invalid TUIC v5')
        elif 'obfs' in native:
            fields(native['obfs'], ('type', 'password'))
            if native['obfs']['type'] != 'salamander':
                raise ValueError('Invalid obfuscation')
        host, port, password = native['server'], native['server_port'], native['password']
    if not isinstance(password, str) or not 1 <= len(password) <= 4096 or any(ord(char) < 32 for char in password):
        raise ValueError('Invalid next-hop authentication')
    return host, port


def stream_parameters(native, xray=False):
    fingerprints = ('chrome','firefox','edge','safari','ios','android','random')
    def text(value, field, fallback=''):
        result = value.get(field, fallback)
        if not isinstance(result, str): raise ValueError('Invalid stream text')
        return result
    def tls(value, reality=False):
        if reality:
            fields(value, ('serverName','fingerprint','publicKey','shortId'))
            name = value['serverName']
            if value['fingerprint'] not in fingerprints or not re.fullmatch('[A-Za-z0-9_-]{43}', text(value,'publicKey')) or not re.fullmatch('(?:[a-f0-9]{2}){0,8}', text(value,'shortId')): raise ValueError('Invalid Reality identity')
        elif xray:
            fields(value, ('serverName','allowInsecure'), ('minVersion','maxVersion','alpn','certificates','disableSystemRoot','fingerprint'))
            if value['allowInsecure'] is not False: raise ValueError('TLS verification disabled')
            name = value['serverName']
            if 'fingerprint' in value and value['fingerprint'] not in fingerprints: raise ValueError('Invalid TLS fingerprint')
        else:
            fields(value, ('enabled','server_name'), ('insecure','min_version','max_version','alpn','certificate','utls','reality','ech'))
            if value['enabled'] is not True or value.get('insecure',False) is not False: raise ValueError('TLS verification disabled')
            name = value['server_name']
            if 'utls' in value:
                u=value['utls'];fields(u,('enabled','fingerprint'))
                if u['enabled'] is not True or u['fingerprint'] not in fingerprints: raise ValueError('Invalid TLS fingerprint')
            if 'reality' in value:
                r=value['reality'];fields(r,('enabled','public_key','short_id'));fields(value,('enabled','server_name','utls','reality'),('insecure',))
                if r['enabled'] is not True or not re.fullmatch('[A-Za-z0-9_-]{43}',text(r,'public_key')) or not re.fullmatch('(?:[a-f0-9]{2}){0,8}',text(r,'short_id')): raise ValueError('Invalid Reality identity')
            if 'ech' in value:
                e=value['ech'];fields(e,('enabled','config'))
                if e['enabled'] is not True or not isinstance(e['config'],list) or not 1<=len(e['config'])<=512 or any(not isinstance(v,str) for v in e['config']): raise ValueError('Invalid ECH config')
                pem='\n'.join(e['config']).strip();begin,end='-----BEGIN ECH CONFIGS-----','-----END ECH CONFIGS-----'
                if len(pem)>32768 or not pem.startswith(begin) or not pem.endswith(end): raise ValueError('ECH must be public inline config')
                data=base64.b64decode(''.join(pem[len(begin):-len(end)].split()),validate=True)
                if not 1<=len(data)<=16384: raise ValueError('ECH config exceeds its bound')
        if not isinstance(name,str) or not 1<=len(name)<=253 or any(ord(c)<33 or ord(c)>126 for c in name): raise ValueError('Invalid TLS name')
        minimum,maximum=value.get('minVersion' if xray else 'min_version'),value.get('maxVersion' if xray else 'max_version')
        if minimum not in (None,'1.2','1.3') or maximum not in (None,'1.2','1.3') or minimum=='1.3' and maximum=='1.2': raise ValueError('Invalid TLS versions')
        if 'alpn' in value and (not isinstance(value['alpn'],list) or not 1<=len(value['alpn'])<=8 or any(not isinstance(v,str) or not 1<=len(v)<=32 or any(ord(c)<33 or ord(c)>126 for c in v) for v in value['alpn']) or len(set(value['alpn']))!=len(value['alpn'])): raise ValueError('Invalid ALPN')
        certificate=None
        if xray and 'certificates' in value:
            if value.get('disableSystemRoot') is not True or not isinstance(value['certificates'],list) or len(value['certificates'])!=1: raise ValueError('Invalid TLS trust scope')
            c=value['certificates'][0];fields(c,('usage','certificate'))
            if c['usage']!='verify': raise ValueError('Invalid certificate usage')
            certificate=c['certificate']
        elif xray and 'disableSystemRoot' in value: raise ValueError('Unbound TLS trust scope')
        elif not xray: certificate=value.get('certificate')
        if certificate is not None:
            pem='\n'.join(certificate) if isinstance(certificate,list) and all(isinstance(v,str) for v in certificate) else certificate
            if not isinstance(pem,str) or not 1<=len(pem)<=65536 or 'PRIVATE KEY' in pem or '-----BEGIN CERTIFICATE-----' not in pem: raise ValueError('Invalid public trust certificate')
    if xray:
        fields(native,('tag','protocol','settings','streamSettings'))
        protocol=native['protocol'];settings=native['settings'];stream=native['streamSettings'];security=stream.get('security')
        if protocol not in ('vless','trojan') or security not in ('tls','reality') or protocol=='trojan' and security=='reality': raise ValueError('Unsupported stream protocol')
        fields(stream,('network','security','realitySettings' if security=='reality' else 'tlsSettings'))
        if stream['network']!='raw': raise ValueError('Unsupported Xray next-hop transport')
        tls(stream['realitySettings' if security=='reality' else 'tlsSettings'],security=='reality')
        if protocol=='vless':
            fields(settings,('vnext',))
            if not isinstance(settings['vnext'],list) or len(settings['vnext'])!=1: raise ValueError('Multiple VLESS endpoints')
            server=settings['vnext'][0];fields(server,('address','port','users'))
            if not isinstance(server['users'],list) or len(server['users'])!=1: raise ValueError('Multiple VLESS users')
            user=server['users'][0];fields(user,('id','encryption'),('flow',))
            if user['encryption']!='none' or not uuid.UUID(text(user,'id')).int or text(user,'flow') not in ('','xtls-rprx-vision'): raise ValueError('Invalid VLESS identity')
        else:
            fields(settings,('servers',))
            if not isinstance(settings['servers'],list) or len(settings['servers'])!=1: raise ValueError('Multiple Trojan endpoints')
            server=settings['servers'][0];fields(server,('address','port','password'));password=text(server,'password')
            if not 1<=len(password)<=4096 or any(ord(c)<32 for c in password): raise ValueError('Invalid Trojan identity')
        return server['address'],server['port']
    protocol=native['type']
    fields(native,('tag','type','server','server_port','tls','uuid' if protocol=='vless' else 'password'),('flow','packet_encoding','transport') if protocol=='vless' else ('transport',) if protocol=='trojan' else ('idle_session_check_interval','idle_session_timeout','min_idle_session','client_metadata'))
    tls(native['tls'])
    if protocol=='vless':
        if not uuid.UUID(text(native,'uuid')).int or text(native,'flow') not in ('','xtls-rprx-vision') or text(native,'packet_encoding','xudp')!='xudp': raise ValueError('Invalid VLESS identity')
    else:
        password=text(native,'password')
        if not 1<=len(password)<=4096 or any(ord(c)<32 for c in password): raise ValueError('Invalid stream password')
        if 'reality' in native['tls']: raise ValueError('Reality requires VLESS')
    if native.get('flow') and native['tls'].get('max_version')=='1.2': raise ValueError('Vision requires TLS 1.3')
    if 'transport' in native:
        t=native['transport'];kind=t.get('type')
        if native.get('flow') or 'reality' in native['tls']: raise ValueError('Invalid transported Vision/Reality')
        if kind=='grpc':
            fields(t,('type','service_name'))
            if not re.fullmatch('[A-Za-z0-9_.-]{1,128}',text(t,'service_name')): raise ValueError('Invalid gRPC service')
        elif kind=='ws':
            fields(t,('type',),('path','headers','max_early_data','early_data_header_name'));path=text(t,'path','/')
            if not 1<=len(path)<=2048 or not path.startswith('/') or path.startswith('//') or any(ord(c)<32 for c in path): raise ValueError('Invalid WebSocket path')
            headers=t.get('headers',{})
            if not isinstance(headers,dict) or len(headers)>16 or len({k.lower() for k in headers})!=len(headers): raise ValueError('Invalid WebSocket headers')
            for k,v in headers.items():
                if not re.fullmatch('[A-Za-z0-9-]{1,64}',k) or k.lower() in ('connection','upgrade','sec-websocket-key','sec-websocket-version','sec-websocket-protocol','content-length','transfer-encoding') or not isinstance(v,str) or not 1<=len(v)<=2048 or any(ord(c)<32 or ord(c)>126 for c in v): raise ValueError('Unsafe WebSocket header')
            early=t.get('max_early_data',0)
            if type(early) is not int or not 0<=early<=2048 or (text(t,'early_data_header_name')!='Sec-WebSocket-Protocol' if early else text(t,'early_data_header_name')!=''): raise ValueError('Invalid WebSocket early data')
        else: raise ValueError('Unsupported stream transport')
    if protocol=='anytls':
        if native['tls'].get('min_version','1.3')!='1.3' or native['tls'].get('max_version')=='1.2': raise ValueError('AnyTLS requires TLS 1.3')
        for field in ('idle_session_check_interval','idle_session_timeout'):
            if field in native and (not re.fullmatch('[0-9]{1,4}s',text(native,field)) or not 5<=int(native[field][:-1])<=3600): raise ValueError('Invalid AnyTLS session interval')
        if 'min_idle_session' in native and (type(native['min_idle_session']) is not int or not 0<=native['min_idle_session']<=32): raise ValueError('Invalid AnyTLS session minimum')
        metadata=text(native,'client_metadata')
        if len(metadata)>512 or any(ord(c)<32 for c in metadata): raise ValueError('Invalid AnyTLS metadata')
    return native['server'],native['server_port']


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
            if native.get('protocol') in ('vless','trojan'):
                host, port = stream_parameters(native, True)
                server = None
            elif native.get('protocol') == 'hysteria':
                host, port = quic_parameters(native, True)
                server = None
            elif set(native) != {'tag', 'protocol', 'settings'} or native['protocol'] != 'shadowsocks' or set(native['settings']) != {'servers'} or len(native['settings']['servers']) != 1:
                raise ValueError('Invalid Xray outbound')
            else:
                server = native['settings']['servers'][0]
                if set(server) != {'address', 'port', 'method', 'password'}:
                    raise ValueError('Invalid Xray server')
                host, port = server['address'], server['port']
        else:
            if native.get('type') in ('vless','trojan','anytls'):
                host, port = stream_parameters(native)
                server = None
            elif native.get('type') in ('hysteria2', 'tuic'):
                host, port = quic_parameters(native, False)
                server = None
            elif set(native) != {'tag', 'type', 'server', 'server_port', 'method', 'password'} or native['type'] != 'shadowsocks':
                raise ValueError('Invalid sing-box outbound')
            else:
                server = native
                host, port = server['server'], server['server_port']
        ipaddress.ip_address(host)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError('Invalid server port')
        if server is not None and (server['method'] not in methods or not isinstance(server['password'], str) or not 1 <= len(server['password']) <= 4096):
            raise ValueError('Invalid Shadowsocks authentication')
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
            configuration = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}], 'outbounds': [outbound], 'routing': {'domainStrategy':'AsIs','rules':[{'type':'field','network':'tcp','outboundTag':'probe-out'}]}}
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
            protocol = ('hysteria2' if outbound.get('protocol') == 'hysteria' else outbound['protocol']) if role == 'RealityEntry' else outbound['type']
            return {'Id': item['Id'], 'Status': 'Passed', 'Egress': actual, 'From': 'EntryServer', 'Network': 'TCP', 'Transport': 'QUIC' if protocol in ('hysteria2', 'tuic') else 'TCP', 'ValidatedProtocol': protocol}
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
    filename = Path(os.environ['VPS_PARAM_PROBES_JSON_FILE'])
    if filename.is_symlink() or not filename.is_file() or filename.stat().st_size > 1048576:
        raise ValueError('Invalid private probe input')
    probes = json.loads(filename.read_text(encoding='utf-8'))
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
