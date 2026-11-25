"""Private, pinned proxy health. No request replay, shell commands or direct fallback."""
import copy
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request

PROXY_CORE_ROOT = '/usr/local/lib/may-forward-probe-cores'


def proxy_digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def proxy_core_spec(core):
    if set(core) not in ({'Engine', 'Version', 'Artifact', 'Sha256'}, {'Engine', 'Version', 'Artifact', 'Sha256', 'BinarySha256'}) or core['Engine'] != 'sing-box' or not re.fullmatch(r'\d+\.\d+\.\d+', core['Version']) or core['Artifact'] != 'sing-box-' + core['Version'] + '-linux-amd64.tar.gz' or not re.fullmatch('[a-f0-9]{64}', core['Sha256']):
        raise ValueError('Invalid fixed proxy probe core.')
    return core


def proxy_core_path(core):
    proxy_core_spec(core)
    return PROXY_CORE_ROOT + '/' + core['Sha256'] + '/sing-box'


def proxy_regular(path, private=False):
    if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file():
        raise ValueError('Missing or linked proxy health material.')
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & (0o077 if private else 0o022):
        raise ValueError('Proxy health ownership or permissions differ.')
    return path


def proxy_ensure_core(host, core):
    proxy_core_spec(core)
    binary = host.path(proxy_core_path(core))
    if binary.parent.exists():
        metadata = json.loads(proxy_regular(binary.parent / 'core.json').read_text())
        if metadata.get('Managed') != 'MayForwardProbe.v1' or metadata.get('ArchiveSha256') != core['Sha256'] or metadata.get('Version') != core['Version'] or proxy_digest(proxy_regular(binary).read_bytes()) != metadata.get('BinarySha256'):
            raise ValueError('Fixed proxy probe core drift.')
        return dict(core, BinarySha256=metadata['BinarySha256'])
    host.regular(proxy_core_path(core), True)
    binary.parent.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=binary.parent.parent))
    try:
        url = 'https://github.com/SagerNet/sing-box/releases/download/v' + core['Version'] + '/' + core['Artifact']
        with urllib.request.urlopen(url, timeout=60) as response:
            if not response.url.startswith('https://'):
                raise ValueError('Non-HTTPS fixed core redirect.')
            data = response.read(67108865)
        if len(data) > 67108864 or proxy_digest(data) != core['Sha256']:
            raise ValueError('Fixed probe archive digest differs.')
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            matches = [m for m in archive.getmembers() if m.isfile() and Path(m.name).name == 'sing-box']
            if len(matches) != 1 or matches[0].size > 67108864:
                raise ValueError('Ambiguous probe executable.')
            raw = archive.extractfile(matches[0]).read()
        (stage / 'sing-box').write_bytes(raw)
        (stage / 'sing-box').chmod(0o755)
        (stage / 'core.json').write_text(json.dumps(dict(Managed='MayForwardProbe.v1', ArchiveSha256=core['Sha256'], Version=core['Version'], BinarySha256=proxy_digest(raw)), separators=(',', ':')))
        (stage / 'core.json').chmod(0o644)
        stage.chmod(0o755)
        os.rename(stage, binary.parent)
        return dict(core, BinarySha256=proxy_digest(raw))
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def proxy_health_rules(config):
    return [r for r in config['Rules'] if r.get('TargetGroup', {}).get('Health', {}).get('Type') == 'Proxy']


def proxy_material(host, config, candidate=False, payload=None):
    supplied_payload = payload is not None
    rules = proxy_health_rules(config)
    if not rules:
        return {}
    if len(rules) > 4:
        raise ValueError('At most four proxy health groups per component.')
    path = host.DIRECTORY + '/proxy-health.json'
    if payload is None:
        supplied = os.environ.get('VPS_PARAM_PROXY_HEALTH_FILE') if candidate else None
        if supplied:
            source = Path(supplied)
            proxy_regular(source, True)
            if source.stat().st_size > 262144: raise ValueError('Oversized proxy health document.')
            payload = json.loads(source.read_text())
        else:
            source = proxy_regular(host.regular(path), True)
            if source.stat().st_size > 262144: raise ValueError('Oversized proxy health material.')
            payload = json.loads(source.read_text())
    value = copy.deepcopy(payload)
    if set(value) != {'Version', 'Core', 'Rules'} or value['Version'] != 1 or set(value['Rules']) != {r['Id'] for r in rules}:
        raise ValueError('Proxy health source scope differs.')
    for rule in rules:
        entry = value['Rules'][rule['Id']]
        if set(entry) != {'RuleFingerprint', 'NodeFingerprint', 'Outbound'} or entry['RuleFingerprint'] != group_fingerprint(rule) or entry['NodeFingerprint'] != rule['Validation']['NodeFingerprint']:
            raise ValueError('Proxy health source identity differs.')
        native = entry['Outbound']
        if native.get('type') == 'shadowsocks' and native.get('method') not in ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305') or native.get('tls', {}).get('insecure') or native.get('type') in ('vless', 'anytls', 'trojan') and not native.get('tls', {}).get('enabled'):
            raise ValueError('Unsupported authentication or disabled TLS verification.')
        if native.get('type') not in ('shadowsocks', 'anytls', 'vless', 'trojan') or native.get('server') != rule['TargetAddress'] or native.get('server_port') != rule['TargetPort'] or any(k in native for k in ('detour', 'plugin', 'udp_over_tcp')) or native.get('transport', {}).get('type') == 'xhttp' or rule['Validation']['Type'] == 'Shadowsocks' and native['type'] != 'shadowsocks':
            raise ValueError('Unsupported or changed proxy health connection.')
    if candidate:
        value['Core'] = proxy_ensure_core(host, value['Core'])
    else:
        core = value['Core']; proxy_core_spec(core)
        binary = proxy_regular(host.path(proxy_core_path(core)))
        if proxy_digest(binary.read_bytes()) != core.get('BinarySha256'):
            raise ValueError('Installed probe core changed.')
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n'
    if len(text.encode()) > 131072: raise ValueError('Oversized private probe material.')
    files = {path: text}
    for identifier, entry in value['Rules'].items():
        files[host.DIRECTORY + '/probe-' + identifier + '.json'] = json.dumps(dict(Version=1, Core=value['Core'], Rules={identifier: entry}), ensure_ascii=False, separators=(',', ':')) + '\n'
    if not candidate and not supplied_payload:
        for file in files: proxy_regular(host.regular(file), True)
    return files


class ProxyProbe:
    def __init__(self, rule, document, runtime, https_target=None, context=None):
        self.rule, self.document = rule, document
        self.entry = document['Rules'][rule['Id']]
        if self.entry['RuleFingerprint'] != group_fingerprint(rule) or self.entry['NodeFingerprint'] != rule['Validation']['NodeFingerprint']:
            raise ValueError('Runtime proxy credential identity differs.')
        self.core = document['Core']; proxy_core_spec(self.core)
        self.runtime = Path(runtime)
        self.https_target, self.context = https_target, context
        self.process, self.directory = None, None
        self.credentials = (secrets.token_hex(16), secrets.token_hex(32))
        self.ports = []
        self.evidence = {}

    def start(self):
        binary = proxy_regular(Path(proxy_core_path(self.core)))
        if proxy_digest(binary.read_bytes()) != self.core.get('BinarySha256'):
            raise ValueError('Probe binary changed before activation.')
        self.directory = Path(tempfile.mkdtemp(prefix='probe-', dir=self.runtime))
        inputs, outputs, routes = [], [], []
        for index, endpoint in enumerate(group_targets(self.rule)):
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0)); self.ports.append(reserved.getsockname()[1])
            tag = 'proxy-' + str(index)
            inputs.append(dict(type='socks', tag='local-' + str(index), listen='127.0.0.1', listen_port=self.ports[-1], users=[dict(username=self.credentials[0], password=self.credentials[1])]))
            native = copy.deepcopy(self.entry['Outbound']); native.update(tag=tag, server=endpoint[0], server_port=endpoint[1]); native.pop('network', None)
            outputs.append(native)
            routes.append(dict(inbound=['local-' + str(index)], action='route', outbound=tag))
        config = dict(log=dict(disabled=True), inbounds=inputs, outbounds=outputs, route=dict(final='proxy-0', rules=routes))
        path = self.directory / 'core.json'; path.write_text(json.dumps(config, separators=(',', ':'))); path.chmod(0o600)
        subprocess.run([str(binary), 'check', '-c', str(path)], check=True, timeout=8, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = dict(os.environ, GOMEMLIMIT='64MiB', GOMAXPROCS='1')
        self.process = subprocess.Popen([str(binary), 'run', '-c', str(path)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None: raise ValueError('Probe core exited.')
            try:
                for index in range(2):
                    with self.connect(index, time.monotonic() + .3): pass
                return
            except OSError:
                time.sleep(.05)
        raise ValueError('Probe core activation timed out.')

    @staticmethod
    def receive(sock, length, deadline):
        data = b''
        while len(data) < length:
            sock.settimeout(max(.001, deadline - time.monotonic()))
            part = sock.recv(length - len(data))
            if not part: raise OSError('SOCKS EOF.')
            data += part
        return data

    def connect(self, index, deadline):
        if self.process is None or self.process.poll() is not None: raise OSError('Probe core is unavailable.')
        sock = socket.create_connection(('127.0.0.1', self.ports[index]), max(.001, deadline - time.monotonic()))
        try:
            sock.sendall(b'\x05\x01\x02')
            if self.receive(sock, 2, deadline) != b'\x05\x02': raise OSError('SOCKS authentication is required.')
            user, password = (v.encode() for v in self.credentials)
            sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if self.receive(sock, 2, deadline) != b'\x01\x00': raise OSError('SOCKS authentication failed.')
            return sock
        except BaseException:
            sock.close(); raise

    def request(self, sock, command, address, port, deadline):
        try:
            ip = ipaddress.ip_address(address)
            encoded = bytes([1 if ip.version == 4 else 4]) + ip.packed
        except ValueError:
            name = address.encode('ascii'); encoded = b'\x03' + bytes([len(name)]) + name
        sock.settimeout(max(.001, deadline - time.monotonic()))
        sock.sendall(b'\x05' + bytes([command, 0]) + encoded + struct.pack('!H', port))
        header = self.receive(sock, 4, deadline)
        if header[:3] != b'\x05\x00\x00' or header[3] not in (1, 4): raise OSError('Proxy request failed.')
        host = socket.inet_ntop(socket.AF_INET if header[3] == 1 else socket.AF_INET6, self.receive(sock, 4 if header[3] == 1 else 16, deadline))
        return host, struct.unpack('!H', self.receive(sock, 2, deadline))[0]

    def probe(self, endpoint):
        index = group_targets(self.rule).index(endpoint)
        deadline = time.monotonic() + self.rule['TargetGroup']['TimeoutSeconds']
        result = dict(Scope='ProxyHttpsEgress', TcpReachable=False, ProxyAuthenticated=False, HttpsVerified=False, UdpResponseMatched=False, Stage='TargetConnect')
        self.evidence[index] = result
        try:
            with socket.create_connection(endpoint, max(.001, deadline - time.monotonic())): pass
            result['TcpReachable'] = True
            result['Stage'] = 'ProxyHttps'
            family = self.rule['TargetGroup']['Health']['EgressFamily']
            host, port = self.https_target or ('api4.ipify.org' if family == 'IPv4' else 'api6.ipify.org', 443)
            with self.connect(index, deadline) as sock:
                self.request(sock, 1, host, port, deadline)
                context = self.context or ssl.create_default_context()
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED: return False
                sock.settimeout(max(.001, deadline - time.monotonic()))
                with context.wrap_socket(sock, server_hostname=host) as secure:
                    secure.sendall(('GET / HTTP/1.0\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n').encode())
                    response = bytearray()
                    while True:
                        secure.settimeout(max(.001, deadline - time.monotonic()))
                        part = secure.recv(1024)
                        if not part: break
                        response.extend(part)
                        if len(response) > 8256: return False
                        if b'\r\n\r\n' in response:
                            head, body = bytes(response).split(b'\r\n\r\n', 1)
                            if len(head) > 8192 or len(body) > 64: return False
                            length = re.search(br'(?im)^content-length:\s*(\d+)\s*$', head)
                            if length and len(body) == int(length[1]): break
                        if time.monotonic() >= deadline: return False
                    head, raw = bytes(response).split(b'\r\n\r\n', 1)
                    if not re.match(br'^HTTP/1\.[01] 200 ', head) or re.search(br'(?im)^transfer-encoding:', head) or len(raw) > 64: return False
                    observed = ipaddress.ip_address(raw.decode('ascii').strip())
                    if observed.version != (4 if family == 'IPv4' else 6) or observed.is_unspecified or observed.is_multicast or getattr(observed, 'ipv4_mapped', None): return False
                    expected = expected_proxy_exit(self.rule, index)
                    if expected and str(observed) != expected: result['Stage'] = 'EgressMismatch'; return False
                    result.update(ProxyAuthenticated=True, HttpsVerified=True, EgressAddress=str(observed))
            if self.rule['Validation']['Type'] == 'Shadowsocks':
                result['Stage'] = 'EncryptedUdp'
                validation = self.rule['Validation']
                query = dns_query(validation['QueryName'], validation['QueryType'])
                with self.connect(index, deadline) as control:
                    relay = self.request(control, 3, '0.0.0.0', 0, deadline)
                    if relay[0] not in ('127.0.0.1', '::1'): return False
                    with socket.socket(socket.AF_INET6 if ':' in relay[0] else socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.connect(relay); udp.settimeout(max(.001, deadline - time.monotonic()))
                        resolver = ipaddress.ip_address(validation['ResolverAddress'])
                        target = bytes([1 if resolver.version == 4 else 4]) + resolver.packed + struct.pack('!H', validation['ResolverPort'])
                        udp.send(b'\0\0\0' + target + query)
                        answer = udp.recv(8192)
                        if not answer.startswith(b'\0\0\0' + target) or not dns_matches(query, answer[3 + len(target):]): return False
                        result['UdpResponseMatched'] = True
            result['Stage'] = 'Passed'
            return True
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            return False

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try: self.process.wait(timeout=3)
                except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=2)
            self.process = None
        if self.directory is not None and self.directory.exists():
            shutil.rmtree(self.directory)


def proxy_group_probe(host, rule, transport):
    path = proxy_regular(host.regular(host.DIRECTORY + '/proxy-health.json'), True)
    document = json.loads(path.read_text())
    with tempfile.TemporaryDirectory(prefix='may-proxy-probe-') as directory:
        probe = ProxyProbe(rule, document, directory)
        try:
            probe.start()
            return [dict(Index=i, Address=endpoint[0], Port=endpoint[1], Passed=probe.probe(endpoint), Evidence=copy.deepcopy(probe.evidence.get(i, {}))) for i, endpoint in enumerate(group_targets(rule))]
        finally:
            probe.close()
