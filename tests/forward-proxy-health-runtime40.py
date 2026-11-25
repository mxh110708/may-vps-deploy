"""Actual proxy-health failover and reboot. Only in a matching disposable VM."""
import argparse
import base64
import copy
import http.server
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-id', required=True); parser.add_argument('--after-reboot', action='store_true'); args = parser.parse_args()
    if os.geteuid() != 0 or Path('/etc/may-proxy40-fixture').read_text().strip() != args.fixture_id or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.fixture_id:
        raise RuntimeError('Disposable guest identity mismatch; no mutations executed.')
    root, lab = Path('/opt/may-proxy40'), Path('/root/may-proxy40')
    lab.mkdir(mode=0o700, exist_ok=True)
    def load(name):
        spec = importlib.util.spec_from_file_location(name, root / 'scripts' / (name + '.py')); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
    tcp, udp = load('tcp-forwarding'), load('udp-forwarding')
    def cmd(argv, check=True):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        if check and p.returncode: raise RuntimeError('Fixture command failed: ' + argv[0] + ' ' + p.stderr[-250:])
        return p
    core = dict(Engine='sing-box', Version='1.14.2', Artifact='sing-box-1.14.2-linux-amd64.tar.gz', Sha256='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6')
    binary = Path(tcp.proxy_core_path(core))
    if not args.after_reboot:
        binary.parent.mkdir(parents=True, mode=0o755)
        shutil.copyfile('/opt/may-proxy40/sing-box', binary); binary.chmod(0o755)
        core['BinarySha256'] = tcp.proxy_digest(binary.read_bytes())
        (binary.parent / 'core.json').write_text(json.dumps(dict(Managed='MayForwardProbe.v1', Version=core['Version'], ArchiveSha256=core['Sha256'], BinarySha256=core['BinarySha256'])))
        (binary.parent / 'core.json').chmod(0o644)
        alias = '[Unit]\nBefore=may-health40-target-0.service may-health40-target-1.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/ip address replace 198.18.40.10/32 dev lo\nExecStart=/usr/sbin/ip address replace 198.18.40.20/32 dev lo\n[Install]\nWantedBy=multi-user.target\n'
        Path('/etc/systemd/system/may-health40-aliases.service').write_text(alias)
        cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'enable', '--now', 'may-health40-aliases.service'])
        cmd(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(lab / 'tls.key'), '-out', str(lab / 'tls.crt'), '-days', '1', '-subj', '/CN=api4.ipify.org', '-addext', 'subjectAltName=DNS:api4.ipify.org'])
        shutil.copyfile(lab / 'tls.crt', '/usr/local/share/ca-certificates/may-health40.crt'); cmd(['update-ca-certificates'])
        with Path('/etc/hosts').open('a') as file: file.write('\n127.0.0.1 api4.ipify.org\n')
        saved = dict(password=base64.b64encode(secrets.token_bytes(16)).decode(), core=core)
        (lab / 'saved.json').write_text(json.dumps(saved)); (lab / 'saved.json').chmod(0o600)
    else:
        saved = json.loads((lab / 'saved.json').read_text()); core = saved['core']
    password = saved['password']
    def target(index, valid=True):
        config = dict(log=dict(disabled=True), inbounds=[dict(type='shadowsocks', listen='127.0.0.1' if index == 0 else '::1', listen_port=31443 + index, method='2022-blake3-aes-128-gcm', password=password if valid else base64.b64encode(secrets.token_bytes(16)).decode())],
                      outbounds=[dict(type='direct', inet4_bind_address='198.18.40.10' if index == 0 else '198.18.40.20')])
        file = lab / ('target-' + str(index) + '.json'); file.write_text(json.dumps(config)); file.chmod(0o600)
        cmd([str(binary), 'check', '-c', str(file)])
        unit = 'may-health40-target-' + str(index) + '.service'
        if not args.after_reboot:
            Path('/etc/systemd/system/' + unit).write_text('[Unit]\nAfter=may-health40-aliases.service\n[Service]\nExecStart=' + str(binary) + ' run -c ' + str(file) + '\n[Install]\nWantedBy=multi-user.target\n')
        cmd(['systemctl', 'daemon-reload']); cmd(['systemctl', 'enable', '--now', unit]); cmd(['systemctl', 'restart', unit])
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1' if index == 0 else '::1', 31443 + index), .2): return
            except OSError: time.sleep(.05)
        raise RuntimeError('Synthetic target failed to expose its port.')
    for i in range(2): target(i)
    class Https(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = self.client_address[0].encode(); self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self, *args): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Https)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(lab / 'tls.crt', lab / 'tls.key'); server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dns.bind(('127.0.0.1', 31553)); dns.settimeout(.2)
    stopped, denied, wrong, seen = threading.Event(), set(), set(), []
    def dns_server():
        while not stopped.is_set():
            try: data, peer = dns.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            seen.append((peer[0], data[:2].hex()))
            if peer[0] in denied: continue
            answer = data[:2] + b'\x81\x80\x00\x01\x00\x01' + b'\x00' * 4 + data[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04' + socket.inet_aton(peer[0])
            if peer[0] in wrong: answer = bytes([answer[0] ^ 1]) + answer[1:]
            dns.sendto(answer, peer)
    threading.Thread(target=dns_server, daemon=True).start()
    hosts, configs, originals = [], [], []
    for transport, driver in [('TCP', tcp), ('UDP', udp)]:
        host = driver.Host()
        if args.after_reboot:
            observed = host.read(); config = observed['Configuration']
        else:
            rule = dict(Id=secrets.token_hex(16), Name='synthetic protocol health40', Enabled=True, ListenFamily='IPv4', ListenPort=31450,
                        TargetAddress='127.0.0.1', TargetPort=31443, AllowedSources=['127.0.0.1/32'], Validation=dict(Type='Proxy' if transport == 'TCP' else 'Shadowsocks', SchemeId='c' * 32, NodeId='d' * 32, NodeFingerprint='e' * 64),
                        TargetGroup=dict(Version=1, BackupAddress='::1', BackupPort=31444, Health=dict(Type='Proxy', Consent=True, EgressFamily='IPv4', PrimaryExit='198.18.40.10', BackupExit='198.18.40.20'),
                                         IntervalSeconds=5, TimeoutSeconds=2, FailureThreshold=2, RecoveryThreshold=2, RecoveryHoldSeconds=10, AutoReturn=True))
            if transport == 'UDP': rule.update(SessionTimeoutSeconds=10, MaximumSessions=32); rule['Validation'].update(ResolverAddress='127.0.0.1', ResolverPort=31553, QueryName='health.example.test', QueryType='A')
            config = driver.normalize(dict(Version=1, Rules=[rule]))
            doc = dict(Version=1, Core=core, Rules={rule['Id']: dict(RuleFingerprint=driver.group_fingerprint(rule), NodeFingerprint='e' * 64, Outbound=dict(type='shadowsocks', server='127.0.0.1', server_port=31443, method='2022-blake3-aes-128-gcm', password=password))})
            files = host.material(config, host.proxy()); files.update(host.auxiliary(config, payload=doc))
            for path, raw in files.items(): host.write(path, raw)
            host.activate(config)
        observed = host.read(); originals.append(observed['Hash']); hosts.append(host); configs.append(config)
    def client(udp_data=False):
        driver, config = (udp, configs[1]) if udp_data else (tcp, configs[0])
        rule = copy.deepcopy(config['Rules'][0]); rule['TargetPort'] = 31450; rule['TargetGroup']['BackupAddress'] = '127.0.0.1'; rule['TargetGroup']['BackupPort'] = 31451
        rule['TargetGroup']['Health'].update(PrimaryExit='', BackupExit=''); rule['TargetGroup']['TimeoutSeconds'] = 3
        doc = dict(Version=1, Core=core, Rules={rule['Id']: dict(RuleFingerprint=driver.group_fingerprint(rule), NodeFingerprint='e' * 64, Outbound=dict(type='shadowsocks', server='127.0.0.1', server_port=31450, method='2022-blake3-aes-128-gcm', password=password))})
        probe = driver.ProxyProbe(rule, doc, lab)
        try:
            probe.start(); passed = probe.probe(('127.0.0.1', 31450)); return passed, copy.deepcopy(probe.evidence.get(0, {}))
        finally: probe.close()
    def status(index):
        return hosts[index].read()['TargetGroups'][0]
    def wait(index, state, budget=35):
        until = time.monotonic() + budget
        while time.monotonic() < until:
            if status(index).get('State') == state and status(index).get('Fresh'): return
            time.sleep(.3)
        raise RuntimeError('Protocol group did not reach ' + state + ': ' + str(status(index).get('State')))
    checks = []
    try:
        for host, driver in zip(hosts, [tcp, udp]):
            proof = driver.probe_groups(host, 'TCP' if driver is tcp else 'UDP')
            if not all(t['Passed'] for t in proof['Groups'][0]['Targets']): raise RuntimeError('New group lacks both authenticated protocol proofs: ' + json.dumps(proof['Groups'][0]['Targets']))
        checks.append('both-targets-authenticated-https-and-encrypted-udp')
        if not args.after_reboot:
            protocol_results = []
            for protocol in ['ss-aead', 'anytls', 'trojan', 'vless-tls', 'vless-reality']:
                with socket.socket() as reserved: reserved.bind(('127.0.0.1', 0)); port = reserved.getsockname()[1]
                token = secrets.token_hex(16); identifier = __import__('uuid').uuid4().__str__()
                tls = dict(enabled=True, server_name='api4.ipify.org', certificate=(lab / 'tls.crt').read_text().strip().splitlines(), key=(lab / 'tls.key').read_text().strip().splitlines())
                if protocol == 'ss-aead':
                    input = dict(type='shadowsocks', method='aes-128-gcm', password=token)
                    output = dict(type='shadowsocks', method='aes-128-gcm', password=token)
                elif protocol in ('anytls', 'trojan'):
                    input = dict(type=protocol, users=[dict(name='health40', password=token)], tls=tls)
                    output = dict(type=protocol, password=token, tls=dict(enabled=True, server_name='api4.ipify.org'))
                else:
                    input = dict(type='vless', users=[dict(name='health40', uuid=identifier)], tls=tls)
                    output = dict(type='vless', uuid=identifier, tls=dict(enabled=True, server_name='api4.ipify.org'))
                    if protocol == 'vless-reality':
                        generated = cmd([str(binary), 'generate', 'reality-keypair']).stdout
                        keys = dict(line.split(':', 1) for line in generated.splitlines() if ':' in line)
                        short = secrets.token_hex(8)
                        input['tls'] = dict(enabled=True, server_name='api4.ipify.org', reality=dict(enabled=True, handshake=dict(server='127.0.0.1', server_port=443), private_key=keys['PrivateKey'].strip(), short_id=[short]))
                        input['users'][0]['flow'] = 'xtls-rprx-vision'
                        output['flow'] = 'xtls-rprx-vision'
                        output['tls'].update(utls=dict(enabled=True, fingerprint='chrome'), reality=dict(enabled=True, public_key=keys['PublicKey'].strip(), short_id=short))
                input.update(listen='127.0.0.1', listen_port=port); output.update(server='127.0.0.1', server_port=port)
                cfg = dict(log=dict(disabled=True), inbounds=[input], outbounds=[dict(type='direct', inet4_bind_address='198.18.40.10')])
                path = lab / ('protocol-' + protocol + '.json'); path.write_text(json.dumps(cfg)); path.chmod(0o600)
                cmd([str(binary), 'check', '-c', str(path)])
                target_process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                probe = None
                try:
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        try:
                            with socket.create_connection(('127.0.0.1', port), .2): break
                        except OSError: time.sleep(.05)
                    r = copy.deepcopy(configs[0]['Rules'][0]); r['TargetPort'] = port; r['TargetGroup']['BackupAddress'] = '127.0.0.1'; r['TargetGroup']['BackupPort'] = port + 1 if port < 65535 else port - 1
                    r['TargetGroup']['TimeoutSeconds'] = 3; r['TargetGroup']['Health']['PrimaryExit'] = '198.18.40.10'
                    d = dict(Version=1, Core=core, Rules={r['Id']: dict(RuleFingerprint=tcp.group_fingerprint(r), NodeFingerprint='e' * 64, Outbound=output)})
                    probe = tcp.ProxyProbe(r, d, lab); probe.start()
                    if not probe.probe(('127.0.0.1', port)): raise RuntimeError('Protocol health failed for ' + protocol + ': ' + str(probe.evidence.get(0)))
                    probe.close(); probe = None
                    if protocol == 'ss-aead':
                        ur = copy.deepcopy(r); ur['Validation'].update(Type='Shadowsocks', ResolverAddress='127.0.0.1', ResolverPort=31553, QueryName='health.example.test', QueryType='A')
                        ud = copy.deepcopy(d); ud['Rules'][r['Id']]['RuleFingerprint'] = tcp.group_fingerprint(ur)
                        probe = tcp.ProxyProbe(ur, ud, lab); probe.start()
                        if not probe.probe(('127.0.0.1', port)) or not probe.evidence[0]['UdpResponseMatched']: raise RuntimeError('Classic AEAD encrypted UDP health failed.')
                        probe.close(); probe = None
                        protocol_results.append('ss-aead-encrypted-udp')
                    bad = copy.deepcopy(d)
                    if protocol.startswith('vless'): bad['Rules'][r['Id']]['Outbound']['uuid'] = str(__import__('uuid').uuid4())
                    else: bad['Rules'][r['Id']]['Outbound']['password'] = secrets.token_hex(16)
                    probe = tcp.ProxyProbe(r, bad, lab); probe.start()
                    if probe.probe(('127.0.0.1', port)): raise RuntimeError('Wrong credentials passed health for ' + protocol)
                    protocol_results.append(protocol)
                finally:
                    if probe is not None: probe.close()
                    target_process.terminate(); target_process.wait(timeout=4)
            checks.append('tcp-protocol-positive-and-wrong-identity:' + ','.join(protocol_results))
        ok, evidence = client(True)
        if not ok: raise RuntimeError('Actual encrypted forwarding failed: ' + str(evidence))
        wait(0, 'Primary'); wait(1, 'Primary'); checks.append('real-tcp-and-udp-entry-primary')
        if args.after_reboot:
            if any(host.read()['Hash'] != expected for host, expected in zip(hosts, saved['Hashes'])): raise RuntimeError('Persistent private health material differs after reboot.')
            checks.append('reboot-private-material-and-socket-activation')
            import tarfile
            for index, host in enumerate(hosts):
                before = host.read(); backup_name = PurePosixPath('/root/vps-deploy-backups/20261116-04000' + str(index) + '/protocol-lifecycle'); backup = host.path(str(backup_name)); backup.mkdir(parents=True)
                host.snapshot(backup, before['Hash'])
                with tarfile.open(backup / 'protocol-files.tar.gz', 'w:gz') as tar:
                    for name in before['Files']: tar.add(host.path(name), arcname=name.lstrip('/'))
                host.apply(dict(Version=1, Rules=[]), before['Hash'], 'Remove', backup_name)
                if host.read()['Hash'] != 'Absent': raise RuntimeError('Component or private credentials survived removal.')
                host.rollback_prepare(backup_name)
                with tarfile.open(backup / 'protocol-files.tar.gz') as tar:
                    for member in tar.getmembers():
                        path = host.path('/' + member.name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(tar.extractfile(member).read()); path.chmod(member.mode)
                host.rollback_complete(backup_name)
                if host.read()['Hash'] != before['Hash']: raise RuntimeError('Scoped restore changed private material bytes.')
            if not client(True)[0]: raise RuntimeError('Restored protocol groups failed actual business paths.')
            checks.append('live-remove-private-material-and-exact-scoped-restore')
        else:
            target(0, False)
            with socket.create_connection(('127.0.0.1', 31443), 1): pass
            wait(0, 'Standby'); wait(1, 'Standby')
            ok, evidence = client(True)
            if not ok or evidence.get('EgressAddress') != '198.18.40.20': raise RuntimeError('Wrong credentials on an open port did not fail over.')
            checks.append('open-port-wrong-credentials-fails-over')
            target(0, True); wait(0, 'Primary'); wait(1, 'Primary'); checks.append('continuous-stable-recovery')
            denied.add('198.18.40.10'); wait(1, 'Standby'); wait(0, 'Primary')
            count = len(seen); ok, evidence = client(True)
            if not ok or not any(source == '198.18.40.20' for source, nonce in seen[count:]): raise RuntimeError('TCP success concealed failed encrypted UDP.')
            checks.append('udp-failure-independent-of-tcp-health')
            denied.clear(); wait(1, 'Primary')
            wrong.add('198.18.40.10'); wait(1, 'Standby'); checks.append('mismatched-encrypted-dns-is-not-health'); wrong.clear(); wait(1, 'Primary')
            target(0, False); target(1, False); wait(0, 'Unavailable'); wait(1, 'Unavailable')
            if client()[0]: raise RuntimeError('All-failed group used a direct fallback.')
            checks.append('all-failed-closed-no-direct-fallback')
            target(0, True); target(1, True); wait(0, 'Primary'); wait(1, 'Primary')
            saved['Hashes'] = [h.read()['Hash'] for h in hosts]; (lab / 'saved.json').write_text(json.dumps(saved)); (lab / 'saved.json').chmod(0o600)
        for host, config in zip(hosts, configs):
            private = host.path(host.DIRECTORY + '/probe-' + config['Rules'][0]['Id'] + '.json')
            if private.stat().st_mode & 0o777 != 0o600: raise RuntimeError('Probe credential is not private.')
        checks.append('private-per-rule-credential-and-core-scope')
        print(json.dumps(dict(stage='after-reboot' if args.after_reboot else 'before-reboot', checks=checks, production=False)))
    except Exception:
        for config, transport in zip(configs, ['tcp', 'udp']):
            unit = 'may-' + transport + '-forward-' + config['Rules'][0]['Id'] + '.service'
            print(cmd(['journalctl', '-u', unit, '--no-pager', '-n', '14'], False).stdout, flush=True)
        raise
    finally:
        stopped.set(); dns.close(); server.shutdown()


if __name__ == '__main__':
    main()
