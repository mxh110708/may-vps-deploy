"""Actual systemd/nftables PROXY chain acceptance; disposable marked guests only."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time

LAB = Path('/opt/may-proxy42')
ENDPOINTS = [('127.0.0.1', 38100), ('::1', 38101), ('127.0.0.1', 38102)]


def command(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30, **kwargs)
    if result.returncode: raise RuntimeError('Disposable guest command failed: ' + result.stderr[-1200:])
    return result


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), LAB/'scripts'/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def target_daemon(worker):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(LAB/'cert.pem', LAB/'key.pem')
    def target(index):
        address, port = ENDPOINTS[index]
        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); server.bind((address, port)); server.listen()
            def serve(peer, accepted):
                try:
                    with peer:
                        peer.settimeout(10)
                        if accepted[0] not in ('127.0.0.1', '::1'): return
                        data = bytearray(); parsed = None
                        while parsed is None:
                            value = peer.recv(1)
                            if not value: return
                            data.extend(value); parsed = worker.parse_header(data, 'Auto')
                        if str(index) in (LAB/'disabled').read_text().split(): return
                        source, destination, _ = parsed
                        with context.wrap_socket(peer, server_side=True) as tls:
                            stream = tls.makefile('rb')
                            while True:
                                line = stream.readline(4096)
                                if not line: break
                                if not line.startswith(b'GET / HTTP/1.1'): return
                                for _ in range(20):
                                    field = stream.readline(4096)
                                    if field == b'\r\n': break
                                else: return
                                body = json.dumps(dict(Target=index, Source=list(source), Destination=list(destination), Peer=accepted[0], VerifiedTls=True)).encode()
                                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: keep-alive\r\n\r\n' + body)
                except (OSError, ValueError): pass
                finally: peer.close()
            while True:
                peer, accepted = server.accept(); threading.Thread(target=serve, args=(peer, accepted), daemon=True).start()
    for index in range(3): threading.Thread(target=target, args=(index,), daemon=True).start()
    # A separate fixture represents the upstream relay. It is deliberately not
    # another local rule in the managed component, whose loop guard is retained.
    fronts = []
    for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        front = socket.socket(family); front.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6: front.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        front.bind((address, 32140)); front.listen(); fronts.append(front)
    threading.Thread(target=worker.run, args=(fronts, '127.0.0.1', 32141, 'v1'), kwargs=dict(idle=3600), daemon=True).start()
    threading.Event().wait()


def configuration(tcp):
    rules = []
    for index in range(1, 6):
        rule = dict(Id=format(42 + index, '032x'), Name='QA trusted proxy42 ' + str(index), Enabled=True, ListenFamily='DualStack', ListenPort=32140+index,
                    TargetAddress='127.0.0.1', TargetPort=38100, AllowedSources=['127.0.0.0/8', '::1/128'], Validation=dict(Type='Tls', ServerName='target.example.test'), ProxyProtocol='v1' if index in (0, 2, 5) else 'v2')
        if index == 0: rule['TargetPort'] = 32141
        else:
            rule['ProxyReceive'] = dict(Version=1, Protocol='v1' if index == 2 else 'v2' if index == 3 else 'Auto', TrustedSources=['127.0.0.1/32', '::1/128'],
                                        ClientSources=['127.0.0.0/8', '::1/128', '198.51.100.0/24', '2001:db8::/32'], ProbeSource='198.51.100.9', ProbeDestination='203.0.113.8', TimeoutSeconds=1)
        if index in (4, 5):
            rule['TargetGroup'] = dict(Version=2, Strategy='RoundRobin' if index == 4 else 'SourceIpHash',
                                      AdditionalTargets=[dict(Id=format(100+j, '032x'), Address=a, Port=p) for j, (a, p) in enumerate(ENDPOINTS[1:])], Health=copy.deepcopy(rule['Validation']),
                                      IntervalSeconds=5, TimeoutSeconds=1, FailureThreshold=2, RecoveryThreshold=2, RecoveryHoldSeconds=10)
        rules.append(rule)
    return tcp.normalize(dict(Version=1, Rules=rules))


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-id', required=True); parser.add_argument('--after-reboot', action='store_true'); parser.add_argument('--target-daemon', action='store_true'); args = parser.parse_args()
    marker = Path('/etc/may-proxy42-fixture')
    if os.geteuid() != 0 or marker.is_symlink() or marker.read_text().strip() != args.fixture_id or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.fixture_id:
        raise RuntimeError('Disposable guest identity mismatch; refusing all operations.')
    worker = load('tcp-proxy-worker')
    if args.target_daemon: return target_daemon(worker)
    (LAB/'disabled').write_text(''); target_unit = 'may-proxy42-targets.service'
    if not args.after_reboot:
        command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=target.example.test', '-addext', 'subjectAltName=DNS:target.example.test', '-keyout', str(LAB/'key.pem'), '-out', str(LAB/'cert.pem')])
        command(['install', '-m', '0644', str(LAB/'cert.pem'), '/usr/local/share/ca-certificates/may-proxy42-fixture.crt']); command(['update-ca-certificates'])
        Path('/etc/systemd/system/'+target_unit).write_text('[Unit]\nDescription=Disposable PROXY-aware TLS acceptance targets\n[Service]\nExecStart=/usr/bin/python3 ' + str(Path(__file__).resolve()) + ' --fixture-id ' + args.fixture_id + ' --target-daemon\n[Install]\nWantedBy=multi-user.target\n')
        command(['systemctl', 'daemon-reload']); command(['systemctl', 'enable', '--now', target_unit])
    else: assert command(['systemctl', 'is-active', target_unit]).stdout.strip() == 'active'
    tcp = load('tcp-forwarding'); host = tcp.Host(); config = configuration(tcp)
    until = time.monotonic()+8
    while time.monotonic() < until:
        try:
            with socket.create_connection(ENDPOINTS[0], .2): break
        except OSError: time.sleep(.05)
    else: raise RuntimeError('Disposable TLS targets did not start.')
    if args.after_reboot: assert host.read()['Configuration'] == config
    else:
        assert host.read()['Hash'] == 'Absent'
        initial = Path('/root/vps-deploy-backups/20261125-004200/protocol-lifecycle'); initial.mkdir(parents=True, exist_ok=True)
        host.snapshot(initial, 'Absent'); host.apply(config, 'Absent', 'Apply', initial)
    context = ssl.create_default_context()
    def response(tls):
        tls.sendall(b'GET / HTTP/1.1\r\nHost: target.example.test\r\n\r\n')
        headers = bytearray()
        while not headers.endswith(b'\r\n\r\n'):
            data = tls.recv(1)
            if not data or len(headers) > 8192: raise AssertionError('Missing bounded HTTP response')
            headers.extend(data)
        size = int(next(line.split(b':', 1)[1] for line in headers.split(b'\r\n') if line.lower().startswith(b'content-length:')))
        body = bytearray()
        while len(body) < size:
            value = tls.recv(size-len(body))
            if not value: raise AssertionError('Truncated HTTP response')
            body.extend(value)
        return json.loads(body)
    def client(index=1, incoming='v1', source='198.51.100.9', destination='203.0.113.8', ipv6=False, bind=None):
        peer = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET); peer.settimeout(8)
        try:
            if bind: peer.bind((bind, 0))
            peer.connect(('::1' if ipv6 else '127.0.0.1', 32140+index))
            local = peer.getsockname()
            if index: peer.sendall(worker.header(incoming, (source, 45678), (destination, 443)))
            tls = context.wrap_socket(peer, server_hostname='target.example.test')
            return tls, response(tls), local
        except BaseException: peer.close(); raise
    checks = []
    for ipv6 in (False, True):
        peer, proof, local = client(0, ipv6=ipv6, bind='::1' if ipv6 else '127.0.0.2')
        assert proof['Source'] == list(local[:2]) and proof['Destination'] == ['::1' if ipv6 else '127.0.0.1', 32140] and proof['VerifiedTls']; peer.close()
    checks.append('actual-two-hop-https-original-client-and-destination')
    for incoming in ('v1', 'v2'):
        for source, destination in (('198.51.100.9', '203.0.113.8'), ('2001:db8::9', '2001:db8:1::8')):
            for ipv6 in (False, True):
                peer, proof, _ = client(incoming=incoming, source=source, destination=destination, ipv6=ipv6)
                assert proof['Source'] == [source, 45678] and proof['Destination'] == [destination, 443]; peer.close()
    for index, incoming in ((2, 'v1'), (3, 'v2')):
        peer, proof, _ = client(index, incoming); assert proof['Source'][0] == '198.51.100.9'; peer.close()
    checks.append('v1-v2-conversion-dual-transport-and-declared-address-families')
    invalid = [(1, None, b'GET / HTTP/1.1\r\n'), (1, '127.0.0.2', worker.header('v1', ('198.51.100.9', 45678), ('203.0.113.8', 443))),
               (1, None, worker.header('v1', ('192.0.2.9', 45678), ('203.0.113.8', 443))), (2, None, worker.header('v2', ('198.51.100.9', 45678), ('203.0.113.8', 443))),
               (3, None, b'PROXY UNKNOWN\r\n')]
    for index, bind, payload in invalid:
        with socket.socket() as peer:
            peer.settimeout(3)
            if bind: peer.bind((bind, 0))
            peer.connect(('127.0.0.1', 32140+index)); peer.sendall(payload)
            try: assert peer.recv(1) == b''
            except (ConnectionResetError, ConnectionAbortedError): pass
    with socket.create_connection(('127.0.0.1', 32141), timeout=3) as peer:
        start = time.monotonic(); peer.sendall(b'PROX'); assert peer.recv(1) == b''; assert time.monotonic()-start < 2
    checks.append('untrusted-client-spoof-no-header-mode-and-absolute-timeout-rejected')
    for index in (4, 5): peer, _, _ = client(index); peer.close()
    def wait(healthy):
        until = time.monotonic()+35
        while time.monotonic() < until:
            groups = host.read()['TargetGroups']
            if len(groups) == 2 and all(g.get('Fresh') and g.get('Healthy') == healthy for g in groups): return
            for index, group in zip((4, 5), groups):
                if group.get('State') == 'NotRunning':
                    try: peer, _, _ = client(index); peer.close()
                    except OSError: pass
            time.sleep(.2)
        raise AssertionError('PROXY group health did not converge: '+json.dumps(groups))
    wait([True]*3)
    sequence = []
    for _ in range(6): peer, proof, _ = client(4); peer.close(); sequence.append(proof['Target'])
    assert sequence[:3] == sequence[3:] and set(sequence[:3]) == {0, 1, 2}
    mapping = {}
    for i in range(1, 17):
        source = '198.51.100.'+str(i); peer, proof, _ = client(5, source=source); peer.close(); mapping[source] = proof['Target']
        peer, repeated, _ = client(5, 'v2', source=source); peer.close(); assert repeated['Target'] == proof['Target']
    assert len(set(mapping.values())) > 1
    checks.append('multi-target-round-robin-and-verified-claimed-source-hash')
    old, proof, _ = client(4); selected = proof['Target']; (LAB/'disabled').write_text(str(selected))
    wait([i != selected for i in range(3)])
    assert response(old)['Target'] == selected; old.close()
    for _ in range(3): peer, proof, _ = client(4); peer.close(); assert proof['Target'] != selected
    checks.append('health-removal-with-existing-tls-session-pinned')
    (LAB/'disabled').write_text(''); start = time.monotonic(); wait([True]*3); assert time.monotonic()-start >= 9.5
    checks.append('continuous-target-recovery-with-proxy-health')
    before = host.read(); original_worker = host.path(tcp.WORKER).read_bytes(); unrelated = LAB/'unrelated-monitor.conf'; unrelated.write_bytes(b'untouched')
    backup = Path('/root/vps-deploy-backups/20261125-'+('004202' if args.after_reboot else '004201')+'/protocol-lifecycle'); backup.mkdir(parents=True, exist_ok=True)
    host.snapshot(backup, before['Hash'])
    with tarfile.open(backup/'protocol-files.tar.gz', 'w:gz') as archive:
        for name in before['Files']: archive.add(host.path(name), arcname=name.lstrip('/'))
    changed = copy.deepcopy(config); changed['Rules'][0]['ProxyReceive']['ClientSources'] = ['198.51.100.0/24']; host.apply(changed, before['Hash'], 'Apply', backup)
    host.rollback_prepare(backup)
    with tarfile.open(backup/'protocol-files.tar.gz') as archive:
        for member in archive.getmembers():
            path = host.path('/'+member.name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(archive.extractfile(member).read()); path.chmod(member.mode)
    host.rollback_complete(backup)
    assert host.read()['Hash'] == before['Hash'] and host.path(tcp.WORKER).read_bytes() == original_worker and unrelated.read_bytes() == b'untouched'
    peer, proof, local = client(0, bind='127.0.0.2'); assert proof['Source'] == list(local[:2]); peer.close()
    checks.append('exact-trust-policy-worker-and-unrelated-scope-restore')
    if args.after_reboot:
        host.apply(dict(Version=1, Rules=[]), before['Hash'], 'Remove', backup); assert host.read()['Hash'] == 'Absent'
        command(['systemctl', 'disable', '--now', target_unit]); checks.append('owned-component-removal-after-reboot')
    print(json.dumps(dict(passed=True, afterReboot=args.after_reboot, checks=checks, productionChanged=False)))


if __name__ == '__main__': main()
