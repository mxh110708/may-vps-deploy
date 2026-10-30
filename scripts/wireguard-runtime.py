"""One-shot kernel WireGuard setup and bounded, source-checked path proofs.
No general shell hooks, default routes, DNS, NAT, or forwarding sysctls.
"""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import time

WG_DIRECTORY = '/etc/may-vps-deploy-wireguard'
WG_CONFIG = WG_DIRECTORY + '/configuration.json'
WG_KEY = WG_DIRECTORY + '/private.key'
WG_INTERFACE = 'maywg0'


def wg_command(args, *, check=True, input=None):
    response = subprocess.run(args, input=input, capture_output=True, text=True, timeout=12)
    if check and response.returncode:
        raise ValueError('WireGuard host operation failed: ' + args[0] + ' ' + args[1])
    return response


def wg_key(text):
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        raise ValueError('Invalid WireGuard public key.') from None
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != text:
        raise ValueError('Invalid WireGuard public key.')
    return text


def wg_inner(text):
    if not isinstance(text, str): raise ValueError('Invalid WireGuard address type.')
    ip = ipaddress.ip_address(text)
    if ip.version != 4 or str(ip) != text or not any(ip in n for n in (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))):
        raise ValueError('Only explicit RFC1918 IPv4 host addresses are supported.')
    return text


def wg_normalize(value, keys=True):
    names = {'Version', 'Id', 'Family', 'Endpoint', 'SourceAddress', 'ListenPort', 'EndpointPort', 'LocalAddress', 'PeerAddress', 'Mtu', 'KeepaliveSeconds'}
    if keys:
        names |= {'PublicKey', 'PeerPublicKey'}
    if not isinstance(value, dict) or any(not isinstance(value.get(k), str) for k in ('Id', 'Family', 'Endpoint', 'SourceAddress', 'LocalAddress', 'PeerAddress')):
        raise ValueError('Invalid WireGuard text fields.')
    if not isinstance(value, dict) or set(value) != names or type(value['Version']) is not int or value['Version'] != 1 or not re.fullmatch('[a-f0-9]{32}', value['Id']):
        raise ValueError('Invalid WireGuard configuration identity or fields.')
    if value['Family'] not in ('IPv4', 'IPv6'):
        raise ValueError('Invalid WireGuard outer address family.')
    for name in ('Endpoint', 'SourceAddress'):
        ip = ipaddress.ip_address(value[name])
        if ip.version != (6 if value['Family'] == 'IPv6' else 4) or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or '%' in value[name] or getattr(ip, 'ipv4_mapped', None) or str(ip) != value[name] or ip.version == 4 and (ip.packed[0] == 0 or ip.packed[0] >= 224):
            raise ValueError('Unsupported WireGuard outer address.')
    for name in ('LocalAddress', 'PeerAddress'):
        wg_inner(value[name])
    if value['LocalAddress'] == value['PeerAddress'] or value['Endpoint'] == value['SourceAddress'] or any(value[n] in (value['SourceAddress'], value['Endpoint']) for n in ('LocalAddress', 'PeerAddress')):
        raise ValueError('WireGuard addresses overlap.')
    for name, low, high in (('ListenPort', 1024, 65535), ('EndpointPort', 1024, 65535), ('Mtu', 1280, 1420), ('KeepaliveSeconds', 0, 120)):
        if type(value[name]) is not int or not low <= value[name] <= high or name == 'KeepaliveSeconds' and 0 < value[name] < 15:
            raise ValueError('Invalid WireGuard port, MTU or keepalive.')
    if keys:
        wg_key(value['PublicKey']); wg_key(value['PeerPublicKey'])
        if value['PublicKey'] == value['PeerPublicKey']:
            raise ValueError('WireGuard peer keys must differ.')
    return value


def wg_regular(path):
    p = Path(path)
    if not p.is_file() or p.is_symlink() or any(d.is_symlink() for d in p.parents) or p.stat().st_uid != 0 or p.stat().st_mode & 0o077:
        raise ValueError('WireGuard configuration permissions or ownership changed.')
    return p


def wg_load():
    return wg_normalize(json.loads(wg_regular(WG_CONFIG).read_text()))


def wg_alias(config):
    identity = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return 'may-vps-deploy:wireguard:' + config['Id'] + ':' + identity


def wg_links():
    return json.loads(wg_command(['ip', '-j', 'link', 'show']).stdout)


def wg_endpoint(c):
    return ('[' + c['Endpoint'] + ']' if c['Family'] == 'IPv6' else c['Endpoint']) + ':' + str(c['EndpointPort'])


def wg_runtime_check(c, *, handshake=False):
    links = [v for v in wg_links() if v['ifname'] == WG_INTERFACE]
    if len(links) != 1 or links[0].get('ifalias') != wg_alias(c) or links[0]['mtu'] != c['Mtu'] or 'UP' not in links[0]['flags']:
        raise ValueError('WireGuard interface identity, state or MTU differs.')
    for prop, expected in (('public-key', c['PublicKey']), ('listen-port', str(c['ListenPort'])), ('peers', c['PeerPublicKey']), ('allowed-ips', c['PeerPublicKey'] + '\t' + c['PeerAddress'] + '/32'), ('endpoints', c['PeerPublicKey'] + '\t' + wg_endpoint(c)), ('persistent-keepalive', c['PeerPublicKey'] + '\t' + (str(c['KeepaliveSeconds']) if c['KeepaliveSeconds'] else 'off'))):
        if wg_command(['wg', 'show', WG_INTERFACE, prop]).stdout.strip() != expected:
            raise ValueError('WireGuard runtime peer configuration differs: ' + prop)
    addresses = json.loads(wg_command(['ip', '-j', '-4', 'address', 'show', 'dev', WG_INTERFACE]).stdout)
    if [(a['local'], a['prefixlen']) for item in addresses for a in item.get('addr_info', []) if a['family'] == 'inet'] != [(c['LocalAddress'], 32)]:
        raise ValueError('WireGuard local address differs.')
    route = json.loads(wg_command(['ip', '-j', '-4', 'route', 'get', c['PeerAddress'], 'from', c['LocalAddress']]).stdout)
    if len(route) != 1 or route[0].get('dev') != WG_INTERFACE:
        raise ValueError('Peer traffic does not use the owned WireGuard interface.')
    routes = json.loads(wg_command(['ip', '-j', '-4', 'route', 'show', 'dev', WG_INTERFACE]).stdout)
    if len(routes) != 1 or routes[0].get('dst') not in (c['PeerAddress'], c['PeerAddress'] + '/32'):
        raise ValueError('Unexpected routes occupy the WireGuard interface.')
    if handshake:
        value = wg_command(['wg', 'show', WG_INTERFACE, 'latest-handshakes']).stdout.strip().split('\t')
        if len(value) != 2 or value[0] != c['PeerPublicKey'] or not value[1].isdigit() or not 0 < time.time() - int(value[1]) < 180:
            raise ValueError('A recent authenticated handshake is missing after path proof.')


def wg_down(c):
    links = [v for v in wg_links() if v['ifname'] == WG_INTERFACE]
    if not links:
        return
    if len(links) != 1 or links[0].get('ifalias') != wg_alias(c):
        raise ValueError('An unowned interface occupies maywg0; refusing removal.')
    # Verify cryptographic identity before deleting an existing interface.
    if wg_command(['wg', 'show', WG_INTERFACE, 'public-key']).stdout.strip() != c['PublicKey']:
        raise ValueError('WireGuard interface was replaced externally.')
    wg_command(['ip', 'link', 'delete', 'dev', WG_INTERFACE])


def wg_up(c):
    if any(v['ifname'] == WG_INTERFACE for v in wg_links()):
        raise ValueError('WireGuard interface already exists; no implicit replacement.')
    key = wg_regular(WG_KEY).read_text().strip()
    if wg_command(['wg', 'pubkey'], input=key + '\n').stdout.strip() != c['PublicKey']:
        raise ValueError('WireGuard private key does not match the saved public identity.')
    wg_command(['ip', 'link', 'add', 'dev', WG_INTERFACE, 'type', 'wireguard'])
    try:
        wg_command(['ip', 'link', 'set', 'dev', WG_INTERFACE, 'alias', wg_alias(c)])
        configuration = '[Interface]\nPrivateKey = ' + key + '\nListenPort = ' + str(c['ListenPort']) + '\n[Peer]\nPublicKey = ' + c['PeerPublicKey'] + '\nAllowedIPs = ' + c['PeerAddress'] + '/32\nEndpoint = ' + wg_endpoint(c) + '\nPersistentKeepalive = ' + str(c['KeepaliveSeconds']) + '\n'
        wg_command(['wg', 'setconf', WG_INTERFACE, '/dev/stdin'], input=configuration)
        wg_command(['ip', 'address', 'add', c['LocalAddress'] + '/32', 'dev', WG_INTERFACE])
        wg_command(['ip', 'link', 'set', 'dev', WG_INTERFACE, 'mtu', str(c['Mtu']), 'up'])
        wg_command(['ip', 'route', 'add', c['PeerAddress'] + '/32', 'dev', WG_INTERFACE, 'src', c['LocalAddress']])
        wg_runtime_check(c)
    except BaseException:
        # This function created this specific interface during this invocation.
        wg_command(['ip', 'link', 'delete', 'dev', WG_INTERFACE], check=False)
        raise


def wg_proof_parameters(address, peer, port, nonce):
    wg_inner(address); wg_inner(peer)
    if not 1024 <= int(port) <= 65535 or not re.fullmatch('[a-f0-9]{64}', nonce):
        raise ValueError('Invalid bounded WireGuard path proof.')


def wg_serve(address, peer, port, nonce):
    wg_proof_parameters(address, peer, port, nonce)
    payload = ('may-wireguard:' + nonce).encode()
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp, selectors.DefaultSelector() as selector:
        for listener in (tcp, udp):
            listener.bind((address, int(port))); listener.setblocking(False)
        tcp.listen(2); selector.register(tcp, selectors.EVENT_READ); selector.register(udp, selectors.EVENT_READ)
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            for key, _ in selector.select(min(1, max(0, deadline - time.monotonic()))):
                if key.fileobj is udp:
                    data, source = udp.recvfrom(2048)
                    if source[0] == peer and data == payload:
                        udp.sendto(hashlib.sha256(data).digest(), source)
                else:
                    connection, source = tcp.accept()
                    with connection:
                        connection.settimeout(2)
                        if source[0] != peer:
                            continue
                        data = bytearray()
                        while len(data) < len(payload):
                            part = connection.recv(len(payload) - len(data))
                            if not part: break
                            data.extend(part)
                        if data == payload:
                            connection.sendall(hashlib.sha256(data).digest())


def wg_probe(c, port, nonce):
    wg_proof_parameters(c['LocalAddress'], c['PeerAddress'], port, nonce)
    wg_runtime_check(c)
    payload = ('may-wireguard:' + nonce).encode(); expected = hashlib.sha256(payload).digest()
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(type=kind) as client:
            client.settimeout(4); client.bind((c['LocalAddress'], 0)); client.connect((c['PeerAddress'], int(port)))
            client.sendall(payload)
            response = bytearray()
            while len(response) < len(expected):
                part = client.recv(2048 if kind == socket.SOCK_DGRAM else len(expected) - len(response))
                if not part: break
                response.extend(part)
                if kind == socket.SOCK_DGRAM: break
            if response != expected:
                raise ValueError('WireGuard application challenge did not match.')
    wg_runtime_check(c, handshake=True)
    return {'Status': 'Passed', 'TCP': True, 'UDP': True, 'ResponseMatched': True, 'Scope': 'WireGuardPeerApplication', 'ChallengeDigest': hashlib.sha256(payload).hexdigest()}


def wireguard_runtime_main():
    action = sys.argv[1]
    if action == 'serve':
        wg_serve(*sys.argv[2:]); return
    c = wg_load()
    if action == 'up': wg_up(c)
    elif action == 'down': wg_down(c)
    else: raise ValueError('Unknown WireGuard runtime action.')


if __name__ == '__main__':
    try: wireguard_runtime_main()
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('WireGuard runtime operation failed; inspect the managed task phase.') from None
