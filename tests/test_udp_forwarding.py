"""UDP ownership, session isolation, expiry and real socket-activation tests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from test_tcp_forwarding import BACKUP, Kernel, ROOT


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UDP = load('udp_forwarding', 'udp-forwarding.py')
WORKER = load('udp_worker', 'udp-forward-worker.py')


def config():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    return {'Version': 1, 'Rules': [{'Id': 'b' * 32, 'Name': 'Synthetic UDP forward', 'Enabled': True,
            'ListenFamily': 'IPv4', 'ListenPort': port, 'TargetAddress': '192.0.2.20', 'TargetPort': 53,
            'AllowedSources': ['127.0.0.1/32'], 'SessionTimeoutSeconds': 120, 'MaximumSessions': 256,
            'Validation': {'Type': 'Dns', 'QueryName': 'example.test', 'QueryType': 'A'}}]}


class Ownership(unittest.TestCase):
    def setUp(self):
        (ROOT / '.test-output').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='udp-forward-', dir=ROOT / '.test-output')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for item in ('usr/bin/python3', 'usr/sbin/nft'):
            path = self.root / item
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic-tool')
        self.kernel = Kernel(self.root, UDP)
        self.host = UDP.Host(self.root, self.kernel)
        self.backup = self.host.path(str(BACKUP))
        self.backup.mkdir(parents=True)

    def snapshot(self):
        self.host.snapshot(self.backup)
        with tarfile.open(self.backup / 'protocol-files.tar.gz', 'w:gz') as archive:
            for name in self.host.read()['Files']:
                archive.add(self.host.path(name), arcname=name.lstrip('/'))

    def apply(self, value=None):
        value = value or config()
        self.snapshot()
        return self.host.apply(UDP.normalize(value), self.host.read()['Hash'], 'Apply', BACKUP)

    def restore(self):
        self.host.rollback_prepare(BACKUP)
        with tarfile.open(self.backup / 'protocol-files.tar.gz') as archive:
            for member in archive.getmembers():
                path = self.host.path('/' + member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
        self.host.rollback_complete(BACKUP)

    def test_install_modify_target_disable_remove(self):
        before = self.apply()
        self.assertIn('udp dport', self.kernel.table)
        self.assertIn('ListenDatagram=', self.host.path(UDP.unit_path(UDP.unit_name(before['Configuration']['Rules'][0], 'socket'))).read_text())
        value = copy.deepcopy(before['Configuration'])
        value['Rules'][0].update(TargetPort=5353, Enabled=False)
        self.snapshot()
        changed = self.host.apply(value, before['Hash'], 'Apply', BACKUP)
        self.assertNotEqual(changed['Hash'], before['Hash'])
        self.assertFalse(self.kernel.units[UDP.unit_name(value['Rules'][0], 'socket')])
        self.snapshot()
        self.assertEqual(self.host.apply({'Version': 1, 'Rules': []}, changed['Hash'], 'Remove', BACKUP)['Hash'], 'Absent')

    def test_recovery_preserves_original_worker_and_other_components(self):
        before = self.apply()
        sentinel = self.root / 'etc/may-tcp-forward/config.json'
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b'other-component')
        changed = copy.deepcopy(before['Configuration'])
        changed['Rules'][0]['TargetAddress'] = '192.0.2.21'
        self.snapshot()
        self.host.apply(changed, before['Hash'], 'Apply', BACKUP)
        self.host.rollback_prepare(BACKUP)
        self.restore()
        self.assertEqual(self.host.read(), before)
        self.assertEqual(sentinel.read_bytes(), b'other-component')

    def test_worker_drift_and_external_edit_refused(self):
        before = self.apply()
        worker = self.host.path(UDP.WORKER)
        worker.write_bytes(b'external-worker')
        self.assertNotEqual(self.host.read()['Hash'], before['Hash'])
        with self.assertRaises(ValueError):
            self.host.apply(before['Configuration'], before['Hash'], 'Apply', BACKUP)
        with self.assertRaises(ValueError):
            self.host.snapshot(self.backup, before['Hash'])
        with self.assertRaises(ValueError):
            self.host.rollback_prepare(BACKUP)
        self.assertEqual(worker.read_bytes(), b'external-worker')

    def test_reviewed_worker_update_and_restore_use_archived_identity(self):
        before = self.apply()
        old_source = UDP.UDP_WORKER_SOURCE
        try:
            UDP.UDP_WORKER_SOURCE += '\n# newer synthetic app worker\n'
            self.assertEqual(self.host.read()['Hash'], before['Hash'])
            self.snapshot()
            changed = self.host.apply(before['Configuration'], before['Hash'], 'Apply', BACKUP)
            self.assertNotEqual(changed['Hash'], before['Hash'])
            self.restore()
            self.assertEqual(self.host.read(), before)
            self.assertEqual(self.host.path(UDP.WORKER).read_text(), old_source)
        finally:
            UDP.UDP_WORKER_SOURCE = old_source

    def test_recovery_bundle_does_not_depend_on_repository_files(self):
        program = 'UDP_WORKER_SOURCE = ' + json.dumps(UDP.UDP_WORKER_SOURCE) + '\n' + (ROOT / 'scripts/forwarding-host.py').read_text() + '\n' + (ROOT / 'scripts/udp-forwarding.py').read_text()
        namespace = {'__name__': 'synthetic_pinned_program'}
        exec(compile(program, 'pinned-udp-program', 'exec'), namespace)
        self.assertEqual(namespace['material'](config(), '/usr/bin/python3')[UDP.WORKER], UDP.UDP_WORKER_SOURCE)
        self.assertIn('Host', namespace)

    def test_actual_udp_collision_but_same_tcp_port_allowed(self):
        value = config()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(('0.0.0.0', value['Rules'][0]['ListenPort']))
            tcp.listen()
            self.host.preflight(value)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(('0.0.0.0', value['Rules'][0]['ListenPort']))
            with self.assertRaises(OSError):
                self.host.preflight(value)

    def test_limits_and_unknown_options(self):
        for key, bad in [('SessionTimeoutSeconds', 0), ('SessionTimeoutSeconds', 601), ('MaximumSessions', 0), ('MaximumSessions', 1025), ('MaximumSessions', True), ('TargetAddress', '::ffff:127.0.0.1')]:
            value = config()
            value['Rules'][0][key] = bad
            with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                UDP.normalize(value)
        value = config()
        value['Rules'][0]['Validation'] = {'Type': 'Tls'}
        with self.assertRaises(ValueError):
            UDP.normalize(value)

    def test_proxy_validation_references_never_carry_credentials(self):
        value = config()
        validation = {'Type': 'Shadowsocks', 'SchemeId': '1'*32, 'NodeId': '2'*32, 'NodeFingerprint': '3'*64,
                      'ResolverAddress': '2001:db8::53', 'ResolverPort': 53, 'QueryName': 'example.test', 'QueryType': 'AAAA'}
        value['Rules'][0]['Validation'] = validation
        self.assertEqual(UDP.normalize(value), value)
        for name, bad in [('SchemeId', '../source'), ('NodeFingerprint', 'changed'), ('ResolverAddress', '::'), ('ResolverAddress', 'ff02::1'), ('ResolverAddress', 'dns.example'), ('ResolverPort', True), ('ResolverPort', 0), ('QueryType', 'TXT'), ('QueryName', 'bad host'), ('password', 'not allowed')]:
            import copy
            candidate = copy.deepcopy(value)
            candidate['Rules'][0]['Validation'][name] = bad
            with self.subTest(name=name, value=bad), self.assertRaises(ValueError):
                UDP.normalize(candidate)

    def test_ipv6_and_bounded_worker_material(self):
        value = config()
        rule = value['Rules'][0]
        rule.update(ListenFamily='DualStack', TargetAddress='2001:db8::20')
        files = UDP.material(value, '/usr/bin/python3')
        self.assertIn('ListenDatagram=[::]:', files[UDP.unit_path(UDP.unit_name(rule, 'socket'))])
        self.assertIn('--timeout 120 --maximum 256', files[UDP.unit_path(UDP.unit_name(rule, 'service'))])
        self.assertEqual(files[UDP.WORKER], (ROOT / 'scripts/udp-forward-worker.py').read_text())


@unittest.skipUnless(sys.platform == 'linux', 'The deployed UDP worker targets Linux')
class Sessions(unittest.TestCase):
    def start(self, listener_family=socket.AF_INET, backend_family=socket.AF_INET, maximum=256, timeout=.3, idle=.2, wildcard=False, allowed=('127.0.0.0/8', '::1/128')):
        self.errors = []
        listener = socket.socket(listener_family, socket.SOCK_DGRAM)
        backend = socket.socket(backend_family, socket.SOCK_DGRAM)
        for item in (listener, backend):
            if item.family == socket.AF_INET6:
                item.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            address = '127.0.0.1' if item.family == socket.AF_INET else '::1'
            if item is listener and wildcard:
                address = '0.0.0.0' if item.family == socket.AF_INET else '::'
            item.bind((address, 0))
        backend.settimeout(2)
        self.addCleanup(backend.close)
        relay = WORKER.Relay([listener], backend.getsockname()[:2], timeout, maximum, idle, allowed)
        def run():
            try:
                relay.run()
            except BaseException as error:
                self.errors.append(error)
        thread = threading.Thread(target=run, daemon=True)
        self.addCleanup(lambda: self.assertEqual(self.errors, []))
        self.addCleanup(lambda: thread.join(3))
        thread.start()
        return listener.getsockname(), backend, thread

    def peer(self, family=socket.AF_INET):
        client = socket.socket(family, socket.SOCK_DGRAM)
        client.settimeout(2)
        client.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
        self.addCleanup(client.close)
        return client

    def check_route(self, listener_family, target_family):
        address, backend, thread = self.start(listener_family, target_family)
        client = self.peer(listener_family)
        payload = os.urandom(4096)
        client.sendto(payload, address)
        actual, upstream = backend.recvfrom(65535)
        self.assertEqual(actual, payload)
        backend.sendto(actual, upstream)
        self.assertEqual(client.recv(65535), payload)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_ipv4_actual_payload_and_idle_exit(self):
        self.check_route(socket.AF_INET, socket.AF_INET)

    def test_ipv6_actual_payload_and_idle_exit(self):
        self.check_route(socket.AF_INET6, socket.AF_INET6)

    def test_cross_family_v4_to_v6(self):
        self.check_route(socket.AF_INET, socket.AF_INET6)

    def test_cross_family_v6_to_v4(self):
        self.check_route(socket.AF_INET6, socket.AF_INET)

    def test_peers_are_isolated_and_responses_return_to_correct_peer(self):
        address, backend, _ = self.start(timeout=.6)
        first, second = self.peer(), self.peer()
        first.sendto(b'first', address)
        one, source_one = backend.recvfrom(1024)
        second.sendto(b'second', address)
        two, source_two = backend.recvfrom(1024)
        self.assertNotEqual(source_one, source_two)
        backend.sendto(two, source_two)
        backend.sendto(one, source_one)
        self.assertEqual(first.recv(1024), b'first')
        self.assertEqual(second.recv(1024), b'second')

    def test_empty_datagram_is_forwarded(self):
        address, backend, _ = self.start()
        client = self.peer()
        client.sendto(b'', address)
        payload, upstream = backend.recvfrom(1024)
        self.assertEqual(payload, b'')
        backend.sendto(payload, upstream)
        self.assertEqual(client.recv(1024), b'')

    def test_wildcard_listener_preserves_each_local_destination(self):
        address, backend, _ = self.start(wildcard=True, timeout=.6)
        client = self.peer()
        client.sendto(b'one', ('127.0.0.1', address[1]))
        _, source_one = backend.recvfrom(1024)
        client.sendto(b'two', ('127.0.0.2', address[1]))
        _, source_two = backend.recvfrom(1024)
        self.assertNotEqual(source_one, source_two)
        backend.sendto(b'two', source_two)
        backend.sendto(b'one', source_one)
        replies = [client.recvfrom(1024), client.recvfrom(1024)]
        self.assertEqual({payload: peer[0] for payload, peer in replies}, {b'one': '127.0.0.1', b'two': '127.0.0.2'})

    def test_large_datagram_is_not_split_or_truncated(self):
        address, backend, _ = self.start()
        client = self.peer()
        payload = os.urandom(60000)
        client.sendto(payload, address)
        actual, upstream = backend.recvfrom(65535)
        self.assertEqual(actual, payload)
        backend.sendto(actual, upstream)
        self.assertEqual(client.recv(65535), payload)

    def test_worker_rejects_unlisted_source_and_accepts_explicit_source(self):
        interfaces = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show'], text=True))
        sources = [a['local'] for interface in interfaces for a in interface.get('addr_info', []) if a.get('family') == 'inet' and not a['local'].startswith('127.')]
        if not sources:
            self.skipTest('No non-loopback local IPv4 for source-policy fixture')
        source = sources[0]
        for permitted in (False, True):
            allowed = (source + '/32',) if permitted else ('127.0.0.1/32',)
            address, backend, _ = self.start(allowed=allowed)
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.addCleanup(client.close)
            client.bind((source, 0))
            client.settimeout(1)
            client.sendto(b'source-policy', address)
            if permitted:
                payload, upstream = backend.recvfrom(1024)
                backend.sendto(payload, upstream)
                self.assertEqual(client.recv(1024), b'source-policy')
            else:
                backend.settimeout(.12)
                with self.assertRaises(socket.timeout):
                    backend.recvfrom(1024)

    def test_session_limit_preserves_existing_then_expiry_admits_new_peer(self):
        address, backend, _ = self.start(maximum=1, timeout=.3, idle=.8)
        first, second = self.peer(), self.peer()
        first.sendto(b'first', address)
        _, source = backend.recvfrom(1024)
        second.sendto(b'dropped-at-limit', address)
        backend.settimeout(.12)
        with self.assertRaises(socket.timeout):
            backend.recvfrom(1024)
        first.sendto(b'still-first', address)
        self.assertEqual(backend.recvfrom(1024)[1], source)
        time.sleep(.65)  # Expiry is swept at most once per timeout interval here.
        second.sendto(b'new-session', address)
        backend.settimeout(1)
        self.assertEqual(backend.recvfrom(1024)[0], b'new-session')

    def test_other_target_cannot_inject_response(self):
        address, backend, _ = self.start()
        client, attacker = self.peer(), self.peer()
        client.sendto(b'probe', address)
        _, upstream = backend.recvfrom(1024)
        attacker.sendto(b'wrong-target', upstream)
        client.settimeout(.12)
        with self.assertRaises(socket.timeout):
            client.recv(1024)
        backend.sendto(b'correct-target', upstream)
        client.settimeout(1)
        self.assertEqual(client.recv(1024), b'correct-target')


@unittest.skipUnless(sys.platform == 'linux', 'Linux systemd socket activation is unavailable')
class Activation(unittest.TestCase):
    @staticmethod
    def spawn(listener, target):
        script = 'import os,sys; os.dup2(int(sys.argv[1]),3); os.set_inheritable(3,True); os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS="1"); os.execv(sys.executable,[sys.executable,"-I",*sys.argv[2:]])'
        return subprocess.Popen([sys.executable, '-c', script, str(listener.fileno()), str(ROOT / 'scripts/udp-forward-worker.py'), '--target', target[0], '--port', str(target[1]), '--timeout', '10', '--maximum', '16', '--allowed', '127.0.0.0/8,::1/128'], pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_real_inherited_socket_worker(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as backend:
            listener.bind(('127.0.0.1', 0))
            backend.bind(('::1', 0))
            backend.settimeout(3)
            process = self.spawn(listener, backend.getsockname())
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    client.sendto(b'activation-check', listener.getsockname())
                    payload, source = backend.recvfrom(1024)
                    backend.sendto(payload, source)
                    self.assertEqual(client.recv(1024), b'activation-check')
            finally:
                process.terminate()
                process.communicate(timeout=5)

    def test_target_change_restarts_without_reusing_old_session(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as old, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            old.bind(('127.0.0.1', 0))
            new.bind(('127.0.0.1', 0))
            for endpoint in (old, new, client):
                endpoint.settimeout(3)
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.bind(('127.0.0.1', 0))
            address = listener.getsockname()
            process = self.spawn(listener, old.getsockname())
            try:
                client.sendto(b'before', address)
                payload, old_source = old.recvfrom(1024)
                old.sendto(payload, old_source)
                self.assertEqual(client.recv(1024), b'before')
                process.terminate()
                process.communicate(timeout=5)
                listener.close()
                listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                listener.bind(address)
                process = self.spawn(listener, new.getsockname())
                client.sendto(b'after', address)
                payload, new_source = new.recvfrom(1024)
                old.sendto(b'stale-old-target', old_source)
                new.sendto(payload, new_source)
                self.assertEqual(client.recv(1024), b'after')
            finally:
                if process.poll() is None:
                    process.terminate()
                process.communicate(timeout=5)
                listener.close()


if __name__ == '__main__':
    unittest.main()
