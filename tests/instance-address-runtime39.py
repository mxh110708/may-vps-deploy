"""Run only inside a disposable Debian guest with matching DMI and seed ID.
Actual systemd/nftables, fixed sing-box, TLS and application UDP are exercised.
"""
import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import shutil
import struct
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-id', required=True)
    parser.add_argument('--after-reboot', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or Path('/etc/may-address39-fixture').read_text().strip() != args.fixture_id or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.fixture_id:
        raise RuntimeError('Disposable guest identity did not match; no mutations executed.')
    root = Path('/opt/may-address39')
    spec = importlib.util.spec_from_file_location('address39', root / 'scripts/instance-address.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.ADDRESS_SOURCES = {p.stem: p.read_text() for p in (root / 'scripts').glob('*.py')}
    fw = (root / 'assets/remote/firewall-tools.sh').read_text()
    m.ADDRESS_SOURCES['firewall-canonical'] = 'import re, ipaddress, subprocess\n' + fw[fw.index('def table('):fw.index('def identity(')]
    lab = Path('/root/may-address39-lab')
    lab.mkdir(mode=0o700, exist_ok=True)
    binary = '/usr/local/bin/sing-box'
    before, after, ss_port, tcp_port, udp_port, echo_port = '198.18.39.10', '198.18.39.11', 29443, 29444, 29445, 29446

    def command(argv, timeout=30, check=True):
        value = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if check and value.returncode:
            raise RuntimeError('Disposable runtime command failed: ' + str(argv[0]))
        return value

    if args.after_reboot:
        saved = json.loads((lab / 'document.json').read_text())
        host = m.AddressHost(saved)
        if not host.status()['Consistent']:
            raise RuntimeError('Persistent address resources did not survive reboot.')
        if command(['systemctl', 'is-active', '--quiet', 'sing-box.service'], check=False).returncode:
            raise RuntimeError('Protocol did not resume after reboot.')
        if '198.18.39.10' in Path('/etc/nftables.conf').read_text():
            raise RuntimeError('Old whitelist survived finalized reboot.')
        restored = host.rollback()
        if restored['Phase'] != 'RolledBack' or not restored['Consistent']:
            raise RuntimeError('Rebooted address transaction could not restore.')
        print(json.dumps({'stage': 'after-reboot', 'persistentRules': True, 'services': True, 'scopedRestore': True}))
        return

    for ip in (before, after):
        command(['ip', 'address', 'replace', ip + '/32', 'dev', 'lo'])
    # Aliases belong to this disposable fixture and must survive its one reboot.
    alias_unit = '[Unit]\nAfter=network.target\nBefore=sing-box.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/ip address replace ' + before + '/32 dev lo\nExecStart=/usr/sbin/ip address replace ' + after + '/32 dev lo\n[Install]\nWantedBy=multi-user.target\n'
    Path('/etc/systemd/system/may-address39-aliases.service').write_text(alias_unit)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', 'may-address39-aliases.service'])
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    config = {'log': {'level': 'error'}, 'inbounds': [{'type': 'shadowsocks', 'listen': before, 'listen_port': ss_port, 'method': '2022-blake3-aes-128-gcm', 'password': key}],
              'outbounds': [{'type': 'direct', 'inet4_bind_address': before}]}
    config_path = Path('/etc/sing-box/config.json')
    config_path.parent.mkdir(mode=0o700, exist_ok=True)
    config_path.write_text(m.compact(config))
    config_path.chmod(0o600)
    unit = '[Unit]\nAfter=network.target may-address39-aliases.service\n[Service]\nExecStart=' + binary + ' run -c /etc/sing-box/config.json\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n'
    Path('/etc/systemd/system/sing-box.service').write_text(unit)
    command([binary, 'check', '-c', str(config_path)])
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', 'sing-box.service'])
    rules = '#!/usr/sbin/nft -f\n# Managed by May VPS Deploy.\ntable inet filter {}\nflush table inet filter\ndelete table inet filter\ntable inet filter {\n chain input {\n type filter hook input priority 0; policy accept;\n ct state established,related accept\n ip saddr { ' + before + ' } tcp dport ' + str(ss_port) + ' accept\n ip saddr { ' + before + ' } udp dport ' + str(ss_port) + ' accept\n tcp dport ' + str(ss_port) + ' drop\n udp dport ' + str(ss_port) + ' drop\n }\n}\n'
    Path('/etc/nftables.conf').write_text(rules)
    Path('/etc/nftables.conf').chmod(0o600)
    command(['nft', '-f', '/etc/nftables.conf'])
    command(['systemctl', 'enable', 'nftables.service'])

    resources = [{'Kind': 'Firewall', 'Component': 'Firewall', 'ExpectedHash': 'Managed', 'Before': {}, 'After': {}},
                 {'Kind': 'ShadowsocksLanding', 'Component': 'ShadowsocksLanding', 'ExpectedHash': m.sha(config_path.read_bytes()), 'Before': config, 'After': m.rewrite(config, {before: after})}]
    for kind, port, validation in [('TcpForwarding', tcp_port, {'Type': 'Ssh'}), ('UdpForwarding', udp_port, {'Type': 'Echo'})]:
        value = {'Version': 1, 'Rules': [{'Id': secrets.token_hex(16), 'Name': 'address39 lab', 'Enabled': True, 'ListenFamily': 'IPv4', 'ListenPort': port,
                  'TargetAddress': before, 'TargetPort': ss_port if kind == 'TcpForwarding' else echo_port, 'AllowedSources': [before + '/32'], 'Validation': validation}]}
        if kind == 'UdpForwarding':
            value['Rules'][0].update(SessionTimeoutSeconds=60, MaximumSessions=64)
        resource = {'Kind': kind, 'Component': kind, 'ExpectedHash': '0' * 64, 'Before': value, 'After': m.rewrite(value, {before: after})}
        a = m.Adapter(resource, Path('/'), subprocess.run, {before: after})
        value = a.host.normalize(value)
        for name, content in a.host.material(value, a.host.proxy()).items():
            a.host.write(name, content)
        a.host.activate(value)
        resource.update(Before=value, After=m.rewrite(value, {before: after}), ExpectedHash=a.host.read()['Hash'])
        resources.append(resource)
    # Two real independently managed identities; only the first is affected.
    inbound_resource = {'Kind': 'Inbounds', 'Component': 'Inbounds', 'ExpectedHash': '0' * 64}
    inbound = m.Adapter(inbound_resource, Path('/'), subprocess.run, {before: after})
    core = dict(Engine='sing-box', Version='1.14.2', Artifact='sing-box-1.14.2-linux-amd64.tar.gz', Sha256='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6')
    core_file = Path(inbound.ns['core_path'](core))
    core_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    shutil.copyfile(binary, core_file)
    core_file.chmod(0o755)
    (core_file.parent / 'core.json').write_text(m.compact(dict(Managed='MayInboundCore.v1', ArchiveSha256=core['Sha256'], Version=core['Version'], BinarySha256=m.sha(core_file.read_bytes()))))
    payload = dict(Version=1, Model=dict(Version=1, Inbounds=[], Users=[], Certificates=[], Outbounds=[]), Bindings=[], Configurations={}, Core=core)
    for index in range(2):
        identifier = secrets.token_hex(16)
        listener = before if index == 0 else '127.0.0.1'
        native = {'log': {'level': 'error'}, 'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
                  'inbounds': [{'type': 'shadowsocks', 'tag': identifier, 'listen': listener, 'listen_port': 29447 + index, 'method': '2022-blake3-aes-128-gcm', 'password': key}],
                  'outbounds': [{'type': 'direct', 'tag': 'egress', **({'inet4_bind_address': before} if index == 0 else {})}], 'route': {'final': 'egress'}}
        raw = m.compact(native).encode()
        payload['Model']['Inbounds'].append(dict(Id=identifier, Name='address39 identity ' + str(index), Protocol='Shadowsocks2022', Enabled=True))
        payload['Bindings'].append(dict(Id=identifier, Enabled=True, Sha256=m.sha(raw), ClientSha256='e' * 64, Port=29447 + index, Address=listener, Udp=True))
        payload['Configurations'][identifier] = base64.b64encode(raw).decode()
    inbound.ns['normalize'](payload)
    for name, raw in inbound.ns['material'](payload).items():
        inbound.host.write(name, raw)
    command(['systemctl', 'daemon-reload'])
    for binding in payload['Bindings']:
        command(['systemctl', 'enable', '--now', inbound.ns['unit_name'](binding['Id'])])
        inbound.host.wait_ready(binding)
    changed = json.loads(m.compact(payload))
    first_binding = changed['Bindings'][0]
    raw = m.compact(m.rewrite(json.loads(base64.b64decode(changed['Configurations'][first_binding['Id']])), {before: after})).encode()
    changed['Configurations'][first_binding['Id']] = base64.b64encode(raw).decode()
    first_binding.update(Address=after, Sha256=m.sha(raw), ClientSha256='f' * 64)
    inbound_resource.update(Before=payload['Model'], After=changed['Model'], AfterPayload=changed, ExpectedHash=inbound.read()['Hash'])
    resources.append(inbound_resource)
    document = {'Task': secrets.token_hex(16), 'Addresses': {before: after}, 'Resources': resources}
    (lab / 'document.json').write_text(m.compact(document))
    (lab / 'document.json').chmod(0o600)
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(lab / 'tls.key'), '-out', str(lab / 'tls.crt'), '-days', '1', '-subj', '/CN=example.test', '-addext', 'subjectAltName=DNS:example.test'])

    class Https(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = self.client_address[0].encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *ignored):
            pass

    https = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Https)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(lab / 'tls.crt', lab / 'tls.key')
    https.socket = tls.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(('0.0.0.0', echo_port))
    stopped = threading.Event()

    def udp_echo():
        echo.settimeout(.3)
        while not stopped.is_set():
            try:
                data, source = echo.recvfrom(4096)
                echo.sendto(source[0].encode() + b'|' + data, source)
            except socket.timeout:
                continue
            except OSError:
                if stopped.is_set():
                    break
                raise

    threading.Thread(target=udp_echo, daemon=True).start()

    def receive(sock, count):
        result = b''
        while len(result) < count:
            part = sock.recv(count - len(result))
            if not part:
                raise RuntimeError('Unexpected SOCKS EOF.')
            result += part
        return result

    def probe(endpoint, source, expected, via_forward=False, inbound_port=None):
        client = {'log': {'level': 'error'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': 29580}],
                  'outbounds': [{'type': 'shadowsocks', 'server': endpoint, 'server_port': inbound_port or (tcp_port if via_forward else ss_port), 'method': '2022-blake3-aes-128-gcm', 'password': key, 'inet4_bind_address': source}]}
        path = lab / 'client.json'
        path.write_text(m.compact(client))
        process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=(lab / 'client.log').open('w'))
        try:
            for _ in range(60):
                try:
                    raw = socket.create_connection(('127.0.0.1', 29580), .2)
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError('Fixed validation core did not start.')
                    time.sleep(.05)
            else:
                raise RuntimeError('Client startup timeout.')
            with raw:
                raw.settimeout(5)
                raw.sendall(b'\x05\x01\x00')
                if receive(raw, 2) != b'\x05\x00':
                    raise RuntimeError('SOCKS handshake failed.')
                raw.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', https.server_port))
                header = receive(raw, 4)
                if header[1] != 0:
                    raise RuntimeError('Proxy CONNECT failed.')
                receive(raw, (4 if header[3] == 1 else 16) + 2)
                context = ssl.create_default_context(cafile=str(lab / 'tls.crt'))
                with context.wrap_socket(raw, server_hostname='example.test') as secure:
                    secure.sendall(b'GET / HTTP/1.0\r\nHost: example.test\r\n\r\n')
                    data = b''
                    while True:
                        part = secure.recv(4096)
                        if not part:
                            break
                        data += part
                if data.split(b'\r\n\r\n', 1)[1] != expected.encode():
                    raise RuntimeError('HTTPS egress source did not match.')
            if via_forward:
                return
            with socket.create_connection(('127.0.0.1', 29580), 3) as control:
                control.settimeout(5)
                control.sendall(b'\x05\x01\x00')
                receive(control, 2)
                control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
                header = receive(control, 4)
                if header[1] != 0:
                    raise RuntimeError('UDP association failed.')
                relay = socket.inet_ntop(socket.AF_INET if header[3] == 1 else socket.AF_INET6, receive(control, 4 if header[3] == 1 else 16))
                relay_port = struct.unpack('!H', receive(control, 2))[0]
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_sock:
                    data_sock.settimeout(5)
                    nonce = secrets.token_bytes(24)
                    data_sock.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo_port) + nonce, (relay, relay_port))
                    reply = data_sock.recv(4096)
                    if not reply.endswith(expected.encode() + b'|' + nonce):
                        raise RuntimeError('Encrypted UDP egress or response challenge mismatched.')
        finally:
            process.terminate()
            process.wait(timeout=5)

    checks = []
    host = m.AddressHost(document)
    try:
        probe(before, before, before)
        checks.append('original-https-and-encrypted-udp')
        host.inspect()
        host.prepare()
        host.apply('Bridge')
        probe(before, after, before)
        checks.append('transitional-new-source-old-listener')
        host.apply('Apply')
        probe(after, after, after)
        probe(after, after, after, True)
        probe(after, after, after, inbound_port=29447)
        probe('127.0.0.1', '127.0.0.1', '127.0.0.1', inbound_port=29448)
        checks.append('independent-inbound-updated-and-other-identity-preserved')
        checks.append('new-https-egress-encrypted-udp-and-tcp-forward')
        host.apply('Finalize')
        probe(after, after, after)
        with socket.socket() as denied:
            denied.settimeout(.4)
            denied.bind((before, 0))
            try:
                denied.connect((after, ss_port))
            except socket.timeout:
                pass
            else:
                raise RuntimeError('Finalized whitelist accepted an old-source connection.')
        checks.append('old-source-rejected-after-finalize')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forwarded:
            forwarded.settimeout(5)
            forwarded.bind((after, 0))
            nonce = secrets.token_bytes(24)
            forwarded.sendto(nonce, (after, udp_port))
            if not forwarded.recv(4096).endswith(nonce):
                raise RuntimeError('Real UDP forwarding response was not matched.')
        checks.append('udp-forward-real-response')
        if not host.status()['Consistent']:
            raise RuntimeError('Finalized runtime differs from persistent materials.')
        print(json.dumps({'stage': 'before-reboot', 'checks': checks, 'consistent': True, 'production': False}))
    except Exception:
        # Only this disposable guest's synthetic forwarding tables are logged.
        for a in host.adapters:
            if a.kind in ('TcpForwarding', 'UdpForwarding'):
                print(json.dumps({'kind': a.kind, 'persistent': a.host.canonical_table(a.host.path(a.host.ACL).read_text()), 'live': a.host.table()}), file=sys.stderr)
        raise
    finally:
        stopped.set()
        echo.close()
        https.shutdown()


if __name__ == '__main__':
    main()
