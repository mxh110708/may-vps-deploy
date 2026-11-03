"""Round30 ownership, bounded PROXY runtime, and two WireGuard namespaces."""
import copy
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
import ssl
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tcp_forwarding as fixture

ROOT = fixture.ROOT
spec = importlib.util.spec_from_file_location('tcp_proxy_worker', ROOT / 'scripts/tcp-proxy-worker.py')
worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)


def listener(family=socket.AF_INET):
    result = socket.socket(family)
    result.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0)); result.listen(); result.settimeout(3)
    return result


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        data = stream.recv(count-len(result))
        if not data: raise ValueError('Early connection close')
        result.extend(data)
    return bytes(result)


def read_header(stream, version):
    if version == 'v1':
        data = bytearray()
        while not data.endswith(b'\r\n') and len(data) < 108: data.extend(exact(stream, 1))
        fields = data.decode().strip().split(' ')
        if len(fields) != 6 or fields[:2] not in (['PROXY', 'TCP4'], ['PROXY', 'TCP6']): raise ValueError('Invalid v1 address header')
        return fields[2], int(fields[4]), fields[3], int(fields[5])
    prefix = exact(stream, 16)
    if prefix[:12] != b'\r\n\r\n\0\r\nQUIT\n' or prefix[12] != 0x21 or prefix[13] not in (0x11, 0x21): raise ValueError('Invalid v2 header')
    length = struct.unpack('!H', prefix[14:])[0]; size = 4 if prefix[13] == 0x11 else 16
    if length != size*2+4: raise ValueError('Unexpected extensions')
    data = exact(stream, length)
    return str(ipaddress.ip_address(data[:size])), struct.unpack('!H', data[size*2:size*2+2])[0], str(ipaddress.ip_address(data[size:size*2])), struct.unpack('!H', data[-2:])[0]


class ProxyRuntime(unittest.TestCase):
    def test_actual_tls_certificate_validation_and_https_with_proxy_target(self):
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            self.skipTest('cryptography is required for TLS fixture generation')
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'proxy.example.test')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('proxy.example.test')]), critical=False).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())
        with tempfile.TemporaryDirectory(dir=ROOT / '.test-output', prefix='proxy30-tls-') as directory:
            directory = Path(directory); certfile, keyfile = directory/'cert.pem', directory/'key.pem'
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            for version in ('v1', 'v2'):
                with self.subTest(version=version):
                    front, target = listener(), listener(); stop = threading.Event(); errors = []
                    def serve():
                        try:
                            peer, _ = target.accept()
                            with peer:
                                peer.settimeout(3); source = read_header(peer, version)
                                if source[0] != '127.0.0.1': raise ValueError('Claimed source is not the accepted socket')
                                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certfile, keyfile)
                                with context.wrap_socket(peer, server_side=True) as tls:
                                    request = tls.recv(1024)
                                    if not request.startswith(b'GET / HTTP/1.1'): raise ValueError('HTTPS request missing')
                                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
                        except BaseException as error: errors.append(error)
                    server = threading.Thread(target=serve, daemon=True); server.start()
                    forward = threading.Thread(target=worker.run, args=([front], '127.0.0.1', target.getsockname()[1], version), kwargs={'idle':0.3,'stop':stop}); forward.start()
                    try:
                        context = ssl.create_default_context(cafile=str(certfile))
                        with socket.create_connection(front.getsockname()[:2], timeout=3) as client:
                            with context.wrap_socket(client, server_hostname='proxy.example.test') as tls:
                                tls.sendall(b'GET / HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n')
                                self.assertTrue(tls.recv(1024).endswith(b'OK'))
                        server.join(3); self.assertFalse(server.is_alive()); self.assertEqual(errors, [])
                    finally:
                        stop.set(); forward.join(2); server.join(3); front.close(); target.close()
                        self.assertFalse(forward.is_alive()); self.assertFalse(server.is_alive())

    def path(self, version, incoming, outgoing):
        front, target = listener(incoming), listener(outgoing)
        self.addCleanup(front.close); self.addCleanup(target.close)
        stop = threading.Event(); errors = []; seen = []; expected = b'PROXY TCP4 1.2.3.4 9.8.7.6 1 2\r\n' + bytes(range(256))*2048
        def serve():
            try:
                peer, _ = target.accept()
                with peer:
                    peer.settimeout(4); seen.append(read_header(peer, version))
                    value = bytearray()
                    while True:
                        data = peer.recv(16384)
                        if not data: break
                        value.extend(data)
                    if bytes(value) != expected: raise ValueError('Payload or half-close changed')
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            except BaseException as error: errors.append(error)
        server = threading.Thread(target=serve, daemon=True); server.start()
        def forward():
            try: worker.run([front], target.getsockname()[0], target.getsockname()[1], version, idle=0.2, stop=stop)
            except BaseException as error: errors.append(error)
        forwarding = threading.Thread(target=forward, daemon=True); forwarding.start()
        try:
            with socket.create_connection(front.getsockname()[:2], timeout=4) as client:
                source = client.getsockname(); client.sendall(expected); client.shutdown(socket.SHUT_WR)
                data = bytearray()
                while True:
                    chunk = client.recv(16384)
                    if not chunk: break
                    data.extend(chunk)
                self.assertTrue(bytes(data).endswith(b'OK'))
            server.join(5); forwarding.join(2)
            self.assertFalse(server.is_alive()); self.assertFalse(forwarding.is_alive()); self.assertEqual(errors, [])
            self.assertEqual(seen, [(source[0], source[1], front.getsockname()[0], front.getsockname()[1])])
        finally:
            stop.set(); forwarding.join(2); server.join(2)
            self.assertFalse(forwarding.is_alive())

    def test_two_versions_dual_families_large_payload_half_close_and_no_input_trust(self):
        for version in ('v1', 'v2'):
            for incoming, outgoing in ((socket.AF_INET, socket.AF_INET), (socket.AF_INET6, socket.AF_INET6), (socket.AF_INET, socket.AF_INET6), (socket.AF_INET6, socket.AF_INET)):
                with self.subTest(version=version, incoming=incoming, outgoing=outgoing): self.path(version, incoming, outgoing)

    def test_multiple_listeners_targets_are_explicitly_isolated(self):
        threads = [threading.Thread(target=self.path, args=(version, socket.AF_INET, family)) for version, family in [('v1', socket.AF_INET), ('v2', socket.AF_INET6)]]
        errors = []
        original = threading.excepthook
        try:
            threading.excepthook = lambda args: errors.append(args.exc_value)
            for thread in threads: thread.start()
            for thread in threads: thread.join(8); self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        finally: threading.excepthook = original

    def test_dead_target_and_idle_worker_exit_without_retry_or_hanging(self):
        front = listener(); dead = listener(); port = dead.getsockname()[1]; dead.close(); self.addCleanup(front.close)
        stop = threading.Event()
        thread = threading.Thread(target=worker.run, args=([front], '127.0.0.1', port, 'v1'), kwargs={'idle': 0.2, 'stop': stop}); thread.start()
        try:
            with socket.create_connection(front.getsockname()[:2], timeout=3) as client:
                try: self.assertEqual(client.recv(32), b'')
                except ConnectionResetError: pass
            thread.join(2); self.assertFalse(thread.is_alive())
        finally:
            stop.set(); thread.join(2); self.assertFalse(thread.is_alive())

    def test_header_does_not_accept_unix_datagrams_or_unreviewed_versions(self):
        for version in ('auto', 'receive-v1', '', 'v3'):
            with self.subTest(version=version), self.assertRaises(ValueError): worker.header(version, ('127.0.0.1', 1), ('127.0.0.1', 2))
        with self.assertRaises(ValueError): worker.header('v1', ('127.0.0.1', 1), ('::1', 2))


class ProxyOwnership(unittest.TestCase):
    setUp = fixture.ForwardingOwnership.setUp
    snapshot = fixture.ForwardingOwnership.snapshot
    apply = fixture.ForwardingOwnership.apply
    restore = fixture.ForwardingOwnership.restore

    def test_mixed_multiple_targets_and_scoped_rollback_pin_worker_bytes(self):
        value = fixture.config(); second = copy.deepcopy(value['Rules'][0]); second['Id'] = 'b'*32; second['ListenPort'] = fixture.port(); second['TargetAddress'] = '192.0.2.21'; second['ProxyProtocol'] = 'v1'; value['Rules'].append(second)
        first = self.apply(value); original = copy.deepcopy(first)
        self.assertIn(fixture.TCP.WORKER, first['Files'])
        self.assertIn('MemoryMax=96M', self.host.path(fixture.TCP.unit_path(fixture.TCP.unit_name(second, 'service'))).read_text())
        self.snapshot(); value['Rules'][1]['ProxyProtocol'] = 'v2'
        self.host.apply(value, first['Hash'], 'Apply', fixture.BACKUP); self.restore()
        self.assertEqual(self.host.read()['Hash'], original['Hash']); self.assertEqual(self.host.read()['Configuration'], original['Configuration'])
        self.host.path(fixture.TCP.WORKER).write_text('unreviewed replacement')
        # The archived resource hash must detect a worker replaced outside the transaction.
        self.assertNotEqual(self.host.read()['Hash'], original['Hash'])

    def test_modes_and_rule_limits_do_not_introduce_implicit_targets(self):
        for version in (None, True, {}, 'auto', 'receive-v2'):
            value = fixture.config(); value['Rules'][0]['ProxyProtocol'] = version
            with self.subTest(version=version), self.assertRaises((ValueError, TypeError)): fixture.TCP.normalize(value)
        value = fixture.config(); value['Rules'][0]['ProxyProtocol'] = 'v1'; value['Rules'][0]['Validation'] = {'Type':'Proxy', 'SchemeId':'a'*32, 'NodeId':'b'*32, 'NodeFingerprint':'c'*64}
        with self.assertRaises(ValueError): fixture.TCP.normalize(value)
        value = fixture.config(); value['Rules'][0]['ProxyProtocol'] = 'v1'; value['Rules'][0]['Validation'] = {'Type':'Ssh'}
        with self.assertRaises(ValueError): fixture.TCP.normalize(value)
        value = fixture.config(); value['Rules'][0]['Targets'] = ['192.0.2.1', '192.0.2.2']
        with self.assertRaises(ValueError): fixture.TCP.normalize(value)

    def test_two_slot_runtime_and_saved_recovery_have_disjoint_owned_paths(self):
        spaces = []
        for slot in (0, 1):
            space = {'__name__': 'isolated_fixture', 'WG_SLOT':slot, 'WIREGUARD_RUNTIME_SOURCE':'synthetic'}
            for file in ('forwarding-host.py', 'wireguard-runtime.py', 'wireguard-host.py'):
                exec(compile((ROOT / 'scripts' / file).read_text(encoding='utf-8'), file, 'exec'), space)
            spaces.append(space)
        for name in ('WG_UNIT', 'WG_PROGRAM', 'WG_DIRECTORY', 'WG_CONFIG', 'WG_KEY', 'WG_INTERFACE'):
            self.assertNotEqual(spaces[0][name], spaces[1][name])
        self.assertEqual(spaces[0]['WG_INTERFACE'], 'maywg0'); self.assertEqual(spaces[1]['WG_INTERFACE'], 'maywg1')
        with self.assertRaises(ValueError): exec(compile((ROOT / 'scripts/wireguard-runtime.py').read_text(encoding='utf-8'), '<bad-slot>', 'exec'), {'WG_SLOT':2})


if __name__ == '__main__': unittest.main()
