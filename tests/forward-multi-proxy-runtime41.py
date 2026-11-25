"""Three-target authenticated SS/SS2022 health in an identity-pinned QA guest."""
import argparse
import base64
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-id', required=True); args = parser.parse_args()
    if os.geteuid() != 0 or Path('/etc/may-multi41-fixture').read_text().strip() != args.fixture_id or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.fixture_id:
        raise RuntimeError('Disposable guest identity mismatch.')
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('group41', root / 'scripts/forward-target-groups.py'); g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
    def command(argv): return subprocess.run(argv, check=True, capture_output=True, timeout=20)
    core = dict(Engine='sing-box', Version='1.14.2', Artifact='sing-box-1.14.2-linux-amd64.tar.gz', Sha256='a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6')
    binary = Path(g.proxy_core_path(core)); binary.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile('/usr/local/bin/sing-box', binary); binary.chmod(0o755)
    core['BinarySha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    (binary.parent / 'core.json').write_text(json.dumps(dict(Managed='MayForwardProbe.v1', Version=core['Version'], ArchiveSha256=core['Sha256'], BinarySha256=core['BinarySha256'])))
    exits = ['198.18.41.' + str(i * 10) for i in range(1, 4)]
    for address in exits: command(['ip', 'address', 'replace', address + '/32', 'dev', 'lo'])
    with tempfile.TemporaryDirectory(prefix='multi41-proxy-') as directory:
        lab = Path(directory); command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(lab / 'tls.key'), '-out', str(lab / 'tls.crt'), '-days', '1', '-subj', '/CN=loopback-qa', '-addext', 'subjectAltName=IP:127.0.0.1'])
        class Https(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                data = self.client_address[0].encode(); self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Https); ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(lab / 'tls.crt', lab / 'tls.key'); server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dns.bind(('127.0.0.1', 0)); dns.settimeout(.1); stop = threading.Event(); denied = set()
        def serve_dns():
            while not stop.is_set():
                try: data, peer = dns.recvfrom(4096)
                except socket.timeout: continue
                except OSError: break
                if peer[0] in denied: continue
                answer = data[:2] + b'\x81\x80\x00\x01\x00\x01' + b'\0' * 4 + data[12:] + b'\xc0\x0c\x00\x01\x00\x01\0\0\0\x01\0\x04' + socket.inet_aton(peer[0])
                try: dns.sendto(answer, peer)
                except OSError: break
        dns_thread = threading.Thread(target=serve_dns, daemon=True); dns_thread.start(); reports = []
        try:
            for method in ('aes-128-gcm', '2022-blake3-aes-128-gcm'):
                password = base64.b64encode(secrets.token_bytes(16)).decode(); processes = []; probes = []
                endpoints = [('127.0.0.1', 32210), ('::1', 32211), ('127.0.0.1', 32212)]
                def start_target(index, valid=True):
                    if len(processes) > index:
                        processes[index].terminate(); processes[index].wait(timeout=5)
                    address, port = endpoints[index]
                    conf = dict(log=dict(disabled=True), inbounds=[dict(type='shadowsocks', listen=address, listen_port=port, method=method, password=password if valid else base64.b64encode(secrets.token_bytes(16)).decode())], outbounds=[dict(type='direct', inet4_bind_address=exits[index])])
                    path = lab / ('ss-' + str(index) + '.json'); path.write_text(json.dumps(conf)); path.chmod(0o600); command([str(binary), 'check', '-c', str(path)])
                    process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if len(processes) > index: processes[index] = process
                    else: processes.append(process)
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        try:
                            with socket.create_connection((address, port), .2): return
                        except OSError: time.sleep(.05)
                    raise AssertionError('QA SS target did not start.')
                try:
                    for i in range(3): start_target(i)
                    rules = []
                    for udp in (False, True):
                        r = dict(Id='a' * 32, TargetAddress=endpoints[0][0], TargetPort=endpoints[0][1], Validation=dict(Type='Shadowsocks' if udp else 'Proxy', NodeFingerprint='e' * 64),
                                 TargetGroup=dict(Version=2, Strategy='RoundRobin', AdditionalTargets=[dict(Id=format(i + 1, '032x'), Address=a, Port=p) for i, (a, p) in enumerate(endpoints[1:])], IntervalSeconds=6, TimeoutSeconds=2, FailureThreshold=2, RecoveryThreshold=2, RecoveryHoldSeconds=10))
                        if udp: r['Validation'].update(ResolverAddress='127.0.0.1', ResolverPort=dns.getsockname()[1], QueryName='example.test', QueryType='A')
                        r['TargetGroup']['Health'] = dict(Type='Proxy', Consent=True, EgressFamily='IPv4', ExpectedExits=dict(zip(g.group_target_ids(r), exits)))
                        document = dict(Version=1, Core=core, Rules={r['Id']: dict(RuleFingerprint=g.group_fingerprint(r), NodeFingerprint='e' * 64, Outbound=dict(type='shadowsocks', server=endpoints[0][0], server_port=endpoints[0][1], method=method, password=password))})
                        probe = g.ProxyProbe(r, document, lab, https_target=server.server_address, context=ssl.create_default_context(cafile=str(lab / 'tls.crt'))); probe.start(); probes.append(probe); rules.append(r)
                        assert all(probe.probe(e) for e in endpoints), 'Three-target HTTPS / encrypted UDP health failed: ' + json.dumps(probe.evidence)
                    start_target(2, False)
                    for probe in probes:
                        assert probe.probe(endpoints[0]) and probe.probe(endpoints[1]) and not probe.probe(endpoints[2])
                        assert probe.evidence[2]['TcpReachable'] and not probe.evidence[2]['ProxyAuthenticated']
                    start_target(2)
                    denied.add(exits[1]); assert probes[0].probe(endpoints[1]) and not probes[1].probe(endpoints[1]); denied.clear()
                    assert probes[1].probe(endpoints[1])
                    rules[0]['TargetGroup']['Health']['ExpectedExits'][g.group_target_ids(rules[0])[2]] = exits[0]
                    assert not probes[0].probe(endpoints[2]) and probes[0].evidence[2]['Stage'] == 'EgressMismatch'
                    assert len(probes[0].ports) == 3 and len(probes[1].ports) == 3
                    reports.append(dict(method=method, threeTargets=True, httpsCertificateVerified=True, encryptedUdpMatched=True, wrongCredentialsOnOpenPortRejected=True, udpFailureIndependent=True, perIdentityExitEnforced=True))
                finally:
                    for probe in probes: probe.close()
                    for process in processes:
                        if process.poll() is None: process.terminate()
                        process.wait(timeout=5)
                    assert not list(lab.glob('probe-*'))
        finally:
            stop.set(); dns.close(); dns_thread.join(2); server.shutdown(); server.server_close()
        print(json.dumps(dict(passed=True, cases=reports, productionChanged=False, ownedChildrenExited=True)))


if __name__ == '__main__': main()
