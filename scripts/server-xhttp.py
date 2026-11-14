"""Bounded Xray XHTTP next-hop validation and private identity proof.

Bundled into existing SSH programs; no listener, service or network mutation.
"""
import base64
import hashlib
import ipaddress
import json
import re
import ssl
import subprocess
import uuid


def require_xhttp_binary(binary):
    result = subprocess.run([str(binary), 'version'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=8, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    first = result.stdout.decode('ascii', errors='replace').splitlines()
    if result.returncode or not first or not re.match(r'^Xray 26\.3\.27(?:\s|$)', first[0]):
        raise ValueError('XHTTP next hop requires the reviewed pinned Xray version.')


def xhttp_fingerprint(value):
    def string(text):
        return 's' + base64.b64encode(text.encode('utf-8')).decode('ascii')
    def canonical(item):
        if isinstance(item, dict):
            return '{' + ','.join(string(k) + ':' + canonical(item[k]) for k in sorted(item)) + '}'
        if isinstance(item, list):
            return '[' + ','.join(canonical(v) for v in item) + ']'
        return string(item) if isinstance(item, str) else json.dumps(item, separators=(',', ':'))
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def xhttp_fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise ValueError('Unknown or incomplete XHTTP fields.')


def xhttp_extra(value):
    ranges = {'xPaddingBytes', 'scMaxEachPostBytes', 'scMinPostsIntervalMs', 'scStreamUpServerSecs', 'uplinkChunkSize'}
    switches = {'noGRPCHeader', 'noSSEHeader', 'xPaddingObfsMode'}
    integers = {'scMaxBufferedPosts', 'serverMaxHeaderBytes'}
    texts = {'xPaddingKey', 'xPaddingHeader', 'xPaddingPlacement', 'xPaddingMethod', 'uplinkHTTPMethod', 'sessionPlacement', 'sessionKey', 'seqPlacement', 'seqKey', 'uplinkDataPlacement', 'uplinkDataKey'}
    xhttp_fields(value, (), ranges | switches | integers | texts | {'headers', 'xmux', 'downloadSettings'})
    def bounds(v):
        if type(v) is int: a = b = v
        elif isinstance(v, str) and re.fullmatch(r'\d+(?:-\d+)?', v):
            ends = v.split('-'); a, b = int(ends[0]), int(ends[-1])
        elif isinstance(v, dict) and set(v) == {'from', 'to'} and all(type(n) is int for n in v.values()): a, b = v['from'], v['to']
        else: raise ValueError('Invalid XHTTP range.')
        if not 0 <= a <= b <= 2147483647: raise ValueError('Invalid XHTTP bounds.')
        return a, b
    for k, v in value.items():
        if k in ranges and bounds(v)[1] > 16 * 1024 * 1024: raise ValueError('XHTTP resource bound exceeded.')
        if k in switches and type(v) is not bool: raise ValueError('Invalid XHTTP switch.')
        if k in integers and (type(v) is not int or not 0 <= v <= 2147483647): raise ValueError('Invalid XHTTP limit.')
        if k in texts and (not isinstance(v, str) or any(ord(c) < 32 for c in v)): raise ValueError('Invalid XHTTP text.')
        if k == 'headers':
            if not isinstance(v, dict) or len(v) > 64 or len({n.lower() for n in v}) != len(v): raise ValueError('Invalid XHTTP headers.')
            for n, text in v.items():
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", n) or n.lower() in ('host', 'content-length', 'transfer-encoding', 'connection') or not isinstance(text, str) or any(c in text for c in '\r\n\x00'): raise ValueError('Unsafe XHTTP header.')
        if k == 'xmux':
            xhttp_fields(v, (), ('maxConcurrency', 'maxConnections', 'cMaxReuseTimes', 'hMaxRequestTimes', 'hMaxReusableSecs', 'hKeepAlivePeriod'))
            for n, number in v.items():
                if n == 'hKeepAlivePeriod':
                    if type(number) is not int: raise ValueError('Invalid XMux keepalive.')
                else: bounds(number)
            if bounds(v.get('maxConcurrency', 0))[1] and bounds(v.get('maxConnections', 0))[1]: raise ValueError('Conflicting XMux bounds.')
    for k in ('sessionPlacement', 'seqPlacement'):
        if value.get(k, '') not in ('', 'path', 'query', 'header', 'cookie'): raise ValueError('Invalid session placement.')
    if value.get('uplinkDataPlacement', '') not in ('', 'auto', 'body', 'header', 'cookie') or value.get('xPaddingPlacement', '') not in ('', 'header', 'cookie', 'query', 'queryInHeader') or value.get('xPaddingMethod', '') not in ('', 'repeat-x', 'tokenish'):
        raise ValueError('Invalid XHTTP placement.')


def xhttp_security(stream):
    reality = stream['security'] == 'reality'
    tls = stream['realitySettings' if reality else 'tlsSettings']
    fingerprints = ('chrome', 'firefox', 'edge', 'safari', 'ios', 'android', 'random')
    xhttp_fields(tls, ('serverName', 'fingerprint', 'publicKey', 'shortId') if reality else ('serverName', 'allowInsecure'),
                 () if reality else ('minVersion', 'maxVersion', 'alpn', 'certificates', 'disableSystemRoot', 'fingerprint'))
    name = tls['serverName']
    if not isinstance(name, str) or len(name) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in name.split('.')): raise ValueError('Invalid XHTTP SNI.')
    if 'fingerprint' in tls and tls['fingerprint'] not in fingerprints: raise ValueError('Invalid XHTTP fingerprint.')
    if reality:
        if not isinstance(tls['publicKey'], str) or not re.fullmatch('[A-Za-z0-9_-]{43}', tls['publicKey']) or len(base64.urlsafe_b64decode(tls['publicKey'] + '=')) != 32 or not isinstance(tls['shortId'], str) or not re.fullmatch('(?:[a-f0-9]{2}){0,8}', tls['shortId']): raise ValueError('Invalid XHTTP Reality identity.')
        return 'h2'
    if tls['allowInsecure'] is not False or tls.get('minVersion') not in (None, '1.2', '1.3') or tls.get('maxVersion') not in (None, '1.2', '1.3') or tls.get('minVersion') == '1.3' and tls.get('maxVersion') == '1.2': raise ValueError('Invalid XHTTP TLS validation.')
    if tls.get('alpn') not in (['http/1.1'], ['h2'], ['h3']): raise ValueError('Explicit XHTTP ALPN required.')
    if tls['alpn'] == ['h3'] and ('fingerprint' in tls or tls.get('maxVersion') == '1.2'): raise ValueError('Invalid HTTP/3 TLS.')
    if 'certificates' in tls:
        if tls.get('disableSystemRoot') is not True or not isinstance(tls['certificates'], list) or len(tls['certificates']) != 1: raise ValueError('Invalid XHTTP trust scope.')
        cert = tls['certificates'][0]; xhttp_fields(cert, ('usage', 'certificate'))
        if cert['usage'] != 'verify' or not isinstance(cert['certificate'], list) or not cert['certificate'] or any(not isinstance(s, str) for s in cert['certificate']): raise ValueError('Invalid XHTTP public certificate.')
        pem = '\n'.join(cert['certificate'])
        if len(pem) > 65536 or 'PRIVATE KEY' in pem: raise ValueError('Invalid XHTTP public trust.')
        ssl.create_default_context().load_verify_locations(cadata=pem)
    elif 'disableSystemRoot' in tls: raise ValueError('Unbound XHTTP trust setting.')
    return tls['alpn'][0]


def validate_xray_xhttp(outbound):
    xhttp_fields(outbound, ('tag', 'protocol', 'settings', 'streamSettings'))
    if outbound['protocol'] != 'vless': raise ValueError('XHTTP next hop requires VLESS.')
    settings = outbound['settings']; xhttp_fields(settings, ('vnext',))
    if not isinstance(settings['vnext'], list) or len(settings['vnext']) != 1: raise ValueError('One XHTTP peer required.')
    server = settings['vnext'][0]; xhttp_fields(server, ('address', 'port', 'users'))
    if not isinstance(server['users'], list) or len(server['users']) != 1: raise ValueError('One XHTTP identity required.')
    user = server['users'][0]; xhttp_fields(user, ('id', 'encryption'), ('flow',))
    if not isinstance(user['id'], str) or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', user['id']) or not uuid.UUID(user['id']).int or user['encryption'] != 'none' or user.get('flow', '') != '': raise ValueError('Invalid XHTTP VLESS identity.')
    def endpoint(address, port):
        if not isinstance(address, str) or '%' in address: raise ValueError('Literal unscoped XHTTP peer address required.')
        ip = ipaddress.ip_address(address)
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.version == 4 and (ip.packed[0] == 0 or ip.packed[0] >= 224) or ip.version == 6 and ip.ipv4_mapped or type(port) is not int or not 1 <= port <= 65535: raise ValueError('Invalid XHTTP peer endpoint.')
    def transport(stream, download=False):
        if not isinstance(stream, dict) or stream.get('security') not in ('tls', 'reality'): raise ValueError('XHTTP needs verified TLS or Reality.')
        security = stream['security']
        xhttp_fields(stream, ('network', 'security', 'xhttpSettings', 'realitySettings' if security == 'reality' else 'tlsSettings') + (('address', 'port') if download else ()))
        if stream['network'] != 'xhttp': raise ValueError('XHTTP transport cannot be discarded.')
        alpn = xhttp_security(stream)
        if download: endpoint(stream['address'], stream['port'])
        x = stream['xhttpSettings']; xhttp_fields(x, ('host', 'path', 'mode'), ('extra',))
        if not isinstance(x['path'], str) or len(x['path']) > 8192 or any(ord(c) < 32 for c in x['path']) or not isinstance(x['host'], str) or len(x['host']) > 253 or any(c.isspace() or ord(c) < 32 or c in '/?#@\\' for c in x['host']) or x['mode'] not in ('', 'auto', 'stream-one', 'stream-up', 'packet-up'): raise ValueError('Invalid XHTTP path, Host or mode.')
        extra = x.get('extra', {}); xhttp_extra(extra)
        if x['mode'] != 'packet-up' and (extra.get('uplinkHTTPMethod', '').upper() == 'GET' or extra.get('uplinkDataPlacement') in ('header', 'cookie')): raise ValueError('Packet metadata requires packet-up.')
        if 'downloadSettings' in extra:
            if download or x['mode'] == 'stream-one': raise ValueError('Invalid nested or stream-one download.')
            transport(extra['downloadSettings'], True)
        return alpn
    endpoint(server['address'], server['port']); transport(outbound['streamSettings'])
    return server['address'], server['port']


def xhttp_proof(outbound):
    validate_xray_xhttp(outbound)
    stream = outbound['streamSettings']
    return {'Transport': 'xhttp', 'ValidatedProtocol': 'vless', 'TransportSecurity': stream['security'],
            'TransportAlpn': xhttp_security(stream), 'XhttpFingerprint': xhttp_fingerprint(stream)}
