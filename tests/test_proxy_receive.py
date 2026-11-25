"""Trusted PROXY input: closed policy, bounded parsing, real sessions and recovery."""
import copy
import datetime
import importlib.util
import ipaddress
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_tcp_forwarding as fixture
from test_chain30 import listener, read_header

spec = importlib.util.spec_from_file_location('receive42_worker', fixture.ROOT / 'scripts/tcp-proxy-worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def policy(**changes):
    value = dict(Version=1, Protocol='Auto', TrustedSources=['127.0.0.1/32', '::1/128'], ClientSources=['198.51.100.0/24', '2001:db8::/32'],
                 ProbeSource='198.51.100.9', ProbeDestination='203.0.113.8', TimeoutSeconds=1)
    value.update(changes)
    return value


def config():
    value = fixture.config()
    value['Rules'][0].update(AllowedSources=['127.0.0.0/8', '::1/128'], ProxyProtocol='v2', ProxyReceive=policy())
    return value


class ReceivePolicy(unittest.TestCase):
    def test_normalization_is_closed_and_requires_explicit_output_trust_and_probe(self):
        value = config(); result = fixture.TCP.normalize(value)
        self.assertEqual(result, fixture.TCP.normalize(result))
        for edit in (
            lambda r: r.pop('ProxyProtocol'), lambda r: r.update(Validation=dict(Type='Ssh')),
            lambda r: r['ProxyReceive'].update(Version=True), lambda r: r['ProxyReceive'].update(Protocol='Optional'),
            lambda r: r['ProxyReceive'].update(TrustedSources=['0.0.0.0/0']), lambda r: r['ProxyReceive'].update(TrustedSources=['::/0']),
            lambda r: r['ProxyReceive'].update(TrustedSources=['192.0.2.1']), lambda r: r['ProxyReceive'].update(TrustedSources=[]),
            lambda r: r['ProxyReceive'].update(ClientSources=[]), lambda r: r['ProxyReceive'].update(ClientSources=['ff00::/8']),
            lambda r: r['ProxyReceive'].update(TimeoutSeconds=True), lambda r: r['ProxyReceive'].update(TimeoutSeconds=11),
            lambda r: r['ProxyReceive'].update(ProbeSource='192.0.2.1'), lambda r: r['ProxyReceive'].update(ProbeSource='::ffff:198.51.100.9'),
            lambda r: r['ProxyReceive'].update(ProbeDestination='::1'), lambda r: r['ProxyReceive'].update(Optional=True),
        ):
            edited = copy.deepcopy(value); edit(edited['Rules'][0])
            with self.subTest(edit=repr(edited['Rules'][0].get('ProxyReceive'))), self.assertRaises(ValueError): fixture.TCP.normalize(edited)
        allowed = copy.deepcopy(value); allowed['Rules'][0]['ProxyReceive']['ClientSources'] = ['0.0.0.0/0', '::/0']
        self.assertEqual(len(fixture.TCP.normalize(allowed)['Rules'][0]['ProxyReceive']['ClientSources']), 2)

    def test_incremental_v1_v2_ipv4_ipv6_and_strict_commands(self):
        for version in ('v1', 'v2'):
            for source, destination in (('198.51.100.9', '203.0.113.8'), ('2001:db8::9', '2001:db8:1::8')):
                header = worker.header(version, (source, 45678), (destination, 443))
                for size in range(len(header)):
                    self.assertIsNone(worker.parse_header(header[:size], version))
                    self.assertIsNone(worker.parse_header(header[:size], 'Auto'))
                self.assertEqual(worker.parse_header(header + b'payload', 'Auto'), ((source, 45678), (destination, 443), len(header)))
        v2 = worker.header('v2', ('198.51.100.9', 45678), ('203.0.113.8', 443))
        invalid = [b'GET / HTTP/1.1\r\n', b'PROXY UNKNOWN\r\n', b'PROXY TCP4 198.51.100.9 203.0.113.8 0 443\r\n',
                   b'PROXY TCP4 198.51.100.9 ::1 123 443\r\n', b'PROXY TCP6 ::ffff:198.51.100.9 ::1 123 443\r\n',
                   b'PROXY TCP6 fe80::1%eth0 ::1 123 443\r\n', b'PROXY TCP4 224.0.0.1 203.0.113.8 123 443\r\n',
                   b'PROXY TCP4 198.51.100.9 203.0.113.8 65536 443\r\n', b'PROXY TCP4 ' + b'x' * 108,
                   b'PROXY TCP4 198.51.100.9 203.0.113.8 123 443\n', v2[:12] + b'\x20' + v2[13:],
                   v2[:13] + b'\x12' + v2[14:], v2[:13] + b'\x31' + v2[14:], v2[:14] + b'\x00\x0d' + v2[16:] + b'X']
        for value in invalid:
            with self.subTest(value=value[:32]), self.assertRaises(ValueError): worker.parse_header(value, 'Auto')


class ReceiveRuntime(unittest.TestCase):
    def relay(self, target, output='v2', receive=None, family=socket.AF_INET, **kwargs):
        front = listener(family); stop = threading.Event(); errors = []
        def run():
            try: worker.run([front], target.getsockname()[0], target.getsockname()[1], output, stop=stop, idle=.2, receive=receive or policy(), **kwargs)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=run); thread.start()
        def cleanup():
            stop.set(); thread.join(3); front.close()
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        self.addCleanup(cleanup)
        return front

    def test_fragmented_headers_conversion_large_payload_and_half_close(self):
        for incoming in ('v1', 'v2'):
            for outgoing in ('v1', 'v2'):
                for family in (socket.AF_INET, socket.AF_INET6):
                    with self.subTest(incoming=incoming, outgoing=outgoing, family=family):
                        target = listener(family); self.addCleanup(target.close)
                        selected = []
                        front = self.relay(target, outgoing, family=family, source_selector=lambda source: selected.append(source) or target.getsockname()[:2])
                        source, destination = ('198.51.100.9', '203.0.113.8') if family == socket.AF_INET else ('2001:db8::9', '2001:db8:1::8')
                        payload = b'PROXY application data\x00' + bytes(range(256)) * 1024
                        seen = []; errors = []
                        def serve():
                            try:
                                peer, _ = target.accept()
                                with peer:
                                    peer.settimeout(5); seen.append(read_header(peer, outgoing)); data = bytearray()
                                    while True:
                                        value = peer.recv(16384)
                                        if not value: break
                                        data.extend(value)
                                    if bytes(data) != payload: raise AssertionError('Stream bytes changed')
                                    peer.sendall(b'after-half-close')
                            except BaseException as error: errors.append(error)
                        server = threading.Thread(target=serve); server.start()
                        try:
                            with socket.create_connection(front.getsockname()[:2], timeout=5) as client:
                                header = worker.header(incoming, (source, 45678), (destination, 443))
                                for part in (header[:1], header[1:5], header[5:]): client.sendall(part)
                                client.sendall(payload); client.shutdown(socket.SHUT_WR)
                                self.assertEqual(client.recv(128), b'after-half-close')
                            server.join(6); self.assertFalse(server.is_alive()); self.assertEqual(errors, [])
                            self.assertEqual(seen, [(source, 45678, destination, 443)]); self.assertEqual(selected, [(source, 45678)])
                        finally: server.join(6)

    def test_untrusted_spoof_missing_wrong_header_and_client_acl_do_not_allocate_target(self):
        valid = worker.header('v1', ('198.51.100.9', 45678), ('203.0.113.8', 443))
        for receive, data in ((policy(TrustedSources=['192.0.2.1/32']), valid), (policy(), b'GET / HTTP/1.1\r\n'),
                              (policy(ClientSources=['192.0.2.0/24'], ProbeSource='192.0.2.5'), valid), (policy(Protocol='v2'), valid)):
            target = listener(); self.addCleanup(target.close); selections = []
            front = self.relay(target, receive=receive, source_selector=lambda source: selections.append(source) or target.getsockname()[:2])
            with socket.create_connection(front.getsockname(), timeout=3) as client:
                try: client.sendall(data); self.assertEqual(client.recv(1), b'')
                except (ConnectionResetError, ConnectionAbortedError): pass
            self.assertEqual(selections, [])
            target.settimeout(.05)
            with self.assertRaises(socket.timeout): target.accept()

    def test_absolute_header_deadline_is_not_extended_by_dripping_bytes(self):
        target = listener(); self.addCleanup(target.close); front = self.relay(target)
        with socket.create_connection(front.getsockname(), timeout=3) as client:
            start = time.monotonic()
            for value in b'PROXY':
                try: client.sendall(bytes([value]))
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError): break
                time.sleep(.24)
            try: self.assertEqual(client.recv(1), b'')
            except (ConnectionResetError, ConnectionAbortedError): pass
            self.assertLess(time.monotonic() - start, 1.8)
        target.settimeout(.05)
        with self.assertRaises(socket.timeout): target.accept()

    def test_completed_header_cannot_cross_deadline_during_parsing(self):
        target = listener(); self.addCleanup(target.close); front = self.relay(target)
        original = worker.parse_header
        def delayed(data, mode):
            # Model CPU contention after the last fragment became readable.
            time.sleep(1.05)
            return original(data, mode)
        worker.parse_header = delayed
        try:
            with socket.create_connection(front.getsockname(), timeout=3) as client:
                client.sendall(worker.header('v1', ('198.51.100.9', 45678), ('203.0.113.8', 443)))
                try: self.assertEqual(client.recv(1), b'')
                except (ConnectionResetError, ConnectionAbortedError): pass
            target.settimeout(.05)
            with self.assertRaises(socket.timeout): target.accept()
        finally: worker.parse_header = original

    def test_incomplete_headers_count_toward_capacity_without_evicting_existing_client(self):
        target = listener(); self.addCleanup(target.close)
        capacity = worker.CAPACITY; worker.CAPACITY = 1
        front = self.relay(target); header = worker.header('v1', ('198.51.100.9', 45678), ('203.0.113.8', 443))
        try:
            with socket.create_connection(front.getsockname(), timeout=3) as first:
                first.sendall(header[:5]); time.sleep(.08)
                with socket.create_connection(front.getsockname(), timeout=3) as extra:
                    try: extra.sendall(header); self.assertEqual(extra.recv(1), b'')
                    except (ConnectionResetError, ConnectionAbortedError): pass
                first.sendall(header[5:]+b'original-client')
                accepted, _ = target.accept()
                with accepted:
                    accepted.settimeout(3); self.assertEqual(read_header(accepted, 'v2')[0], '198.51.100.9')
                    self.assertEqual(accepted.recv(128), b'original-client'); accepted.sendall(b'OK')
                    self.assertEqual(first.recv(2), b'OK')
        finally: worker.CAPACITY = capacity

    def test_valid_slow_header_gets_a_fresh_downstream_connect_budget(self):
        target = listener(); self.addCleanup(target.close)
        front = self.relay(target, receive=policy(TimeoutSeconds=10))
        header = worker.header('v1', ('198.51.100.9', 45678), ('203.0.113.8', 443))
        with socket.create_connection(front.getsockname(), timeout=9) as client:
            client.sendall(header[:5]); time.sleep(5.1); client.sendall(header[5:]+b'after-valid-header')
            peer, _ = target.accept()
            with peer:
                peer.settimeout(3); self.assertEqual(read_header(peer, 'v2')[0], '198.51.100.9')
                self.assertEqual(peer.recv(128), b'after-valid-header'); peer.sendall(b'OK')
                self.assertEqual(client.recv(2), b'OK')

    def test_real_two_hop_verified_https_preserves_original_client_ip_and_destination(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        (fixture.ROOT / '.test-output').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=fixture.ROOT / '.test-output', prefix='receive42-tls-') as temporary:
            path = Path(temporary); key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'target.example.test')]); now = datetime.datetime.now(datetime.timezone.utc)
            certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('target.example.test')]), False).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256())
            (path/'cert.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM)); (path/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(path/'cert.pem', path/'key.pem')
            # Health clients intentionally close immediately after certificate
            # verification. Avoid post-handshake TLS 1.3 ticket writes racing
            # that close on Windows; the fixture does not test resumption.
            context.num_tickets = 0
            target = listener(); self.addCleanup(target.close)
            backend = self.relay(target, receive=policy(ClientSources=['127.0.0.2/32'], ProbeSource='127.0.0.2'))
            entry = listener(); self.addCleanup(entry.close); stop = threading.Event()
            forward = threading.Thread(target=worker.run, args=([entry], '127.0.0.1', backend.getsockname()[1], 'v1'), kwargs=dict(stop=stop, idle=.3)); forward.start()
            seen = []; errors = []
            def serve():
                try:
                    peer, _ = target.accept()
                    with peer:
                        peer.settimeout(4); seen.append(read_header(peer, 'v2'))
                        with context.wrap_socket(peer, server_side=True) as tls:
                            self.assertTrue(tls.recv(4096).startswith(b'GET / HTTP/1.1'))
                            tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
                except BaseException as error: errors.append(error)
            server = threading.Thread(target=serve); server.start()
            try:
                with socket.socket() as client:
                    client.settimeout(5); client.bind(('127.0.0.2', 0)); client.connect(entry.getsockname()); original_source = client.getsockname()
                    with ssl.create_default_context(cafile=str(path/'cert.pem')).wrap_socket(client, server_hostname='target.example.test') as tls:
                        tls.sendall(b'GET / HTTP/1.1\r\nHost: target.example.test\r\n\r\n'); self.assertTrue(tls.recv(4096).endswith(b'OK'))
                server.join(5); self.assertEqual(errors, [])
                self.assertEqual(seen, [(original_source[0], original_source[1], entry.getsockname()[0], entry.getsockname()[1])])
                # Target health must use the same explicitly declared original
                # destination as entry validation, rather than the backend port.
                rule = config()['Rules'][0]
                rule['TargetGroup'] = dict(Health=dict(Type='Tls', ServerName='target.example.test'), TimeoutSeconds=3)
                def health_target():
                    try:
                        peer, _ = target.accept()
                        with peer:
                            peer.settimeout(3); source = read_header(peer, 'v2')
                            self.assertEqual(source[0], rule['ProxyReceive']['ProbeSource'])
                            self.assertEqual(source[2:], (rule['ProxyReceive']['ProbeDestination'], rule['ListenPort']))
                            with context.wrap_socket(peer, server_side=True): pass
                    except BaseException as error: errors.append(error)
                health = threading.Thread(target=health_target); health.start()
                try:
                    self.assertTrue(fixture.TCP.health_probe(rule, target.getsockname()[:2], context=ssl.create_default_context(cafile=str(path/'cert.pem')), proxy_header=worker.header))
                    health.join(4); self.assertFalse(health.is_alive()); self.assertEqual(errors, [])
                finally: health.join(4)
            finally: stop.set(); forward.join(3); server.join(5); self.assertFalse(forward.is_alive())


class ReceiveRecovery(unittest.TestCase):
    setUp = fixture.ForwardingOwnership.setUp
    snapshot = fixture.ForwardingOwnership.snapshot
    apply = fixture.ForwardingOwnership.apply
    restore = fixture.ForwardingOwnership.restore

    def test_scoped_restore_preserves_trust_policy_exact_worker_and_unrelated_files(self):
        before = self.apply(config()); worker_path = self.host.path(fixture.TCP.WORKER); original = worker_path.read_bytes()
        unrelated = self.root/'etc/unrelated-monitor.conf'; unrelated.write_bytes(b'untouched')
        after = config(); after['Rules'][0]['Id'] = before['Configuration']['Rules'][0]['Id']; after['Rules'][0]['ListenPort'] = before['Configuration']['Rules'][0]['ListenPort']; after['Rules'][0]['ProxyReceive']['ClientSources'] = ['0.0.0.0/0', '::/0']
        self.snapshot(); self.host.apply(fixture.TCP.normalize(after), before['Hash'], 'Apply', fixture.BACKUP); self.restore()
        self.assertEqual(self.host.read()['Hash'], before['Hash']); self.assertEqual(worker_path.read_bytes(), original); self.assertEqual(unrelated.read_bytes(), b'untouched')
        self.assertEqual(self.host.read()['Configuration']['Rules'][0]['ProxyReceive'], before['Configuration']['Rules'][0]['ProxyReceive'])
        unit = self.host.path(fixture.TCP.unit_path(fixture.TCP.unit_name(before['Configuration']['Rules'][0], 'service'))).read_text()
        self.assertIn('--receive-policy', unit)


if __name__ == '__main__': unittest.main()
