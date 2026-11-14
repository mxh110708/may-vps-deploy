"""Explicit main/standby behavior, real bounded loopback and scoped recovery."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


GROUP = module('forward_group_tests', 'scripts/forward-target-groups.py')
TCP = module('forward_tcp_tests', 'scripts/tcp-forwarding.py')
UDP = module('forward_udp_tests', 'scripts/udp-forwarding.py')
WORKER = module('forward_tcp_worker_tests', 'scripts/tcp-proxy-worker.py')
import test_tcp_forwarding as owned_fixture
from test_tcp_forwarding import config


def rule(kind='Ssh'):
    value = config()['Rules'][0]
    value['Validation'] = {'Type': kind} if kind in ('Ssh', 'Echo') else {'Type': 'Tls', 'ServerName': 'target.example.test'}
    if kind == 'Dns': value['Validation'] = {'Type': 'Dns', 'QueryName': 'example.test', 'QueryType': 'A'}
    if kind in ('Dns', 'Echo'):
        value['SessionTimeoutSeconds'] = 10; value['MaximumSessions'] = 16
    value['TargetGroup'] = {'Version': 1, 'BackupAddress': '192.0.2.21', 'BackupPort': 443,
                            'Health': copy.deepcopy(value['Validation']), 'IntervalSeconds': 5, 'TimeoutSeconds': 1,
                            'FailureThreshold': 2, 'RecoveryThreshold': 2, 'RecoveryHoldSeconds': 10, 'AutoReturn': True}
    return value


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
    def advance(self, seconds=5): self.now += seconds


class Target:
    def __init__(self, family=socket.AF_INET, tls=None, banner=None):
        self.listener = socket.socket(family, socket.SOCK_STREAM); self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0)); self.listener.listen(); self.listener.settimeout(.1)
        self.endpoint = self.listener.getsockname()[:2]; self.enabled = True; self.closed = threading.Event(); self.connections = 0; self.clients = []; self.error = None
        self.tls, self.banner = tls, banner
        self.thread = threading.Thread(target=self.run, daemon=True); self.thread.start()

    def run(self):
        while not self.closed.is_set():
            try: client, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            if not self.enabled: client.close(); continue
            self.connections += 1
            def serve(peer):
                try:
                    peer.settimeout(2)
                    if self.tls is not None: peer = self.tls.wrap_socket(peer, server_side=True)
                    if self.banner is not None: peer.sendall(self.banner)
                    while not self.closed.is_set():
                        try: data = peer.recv(4096)
                        except socket.timeout: continue
                        if not data: break
                        peer.sendall(data)
                except (OSError, ssl.SSLError): pass
                finally: peer.close()
            thread = threading.Thread(target=serve, args=(client,), daemon=True); self.clients.append(thread); thread.start()

    def close(self):
        self.closed.set(); self.listener.close(); self.thread.join(2)
        for thread in self.clients: thread.join(2)


class TargetGroups(unittest.TestCase):
    def test_normalization_preserves_single_targets_and_group_order(self):
        plain = config(); self.assertNotIn('TargetGroup', TCP.normalize(plain)['Rules'][0])
        value = rule(); original = copy.deepcopy(value)
        self.assertEqual(TCP.normalize({'Version': 1, 'Rules': [value]})['Rules'][0], original)
        self.assertEqual(value, original)
        self.assertEqual(GROUP.group_targets(value), [('192.0.2.20', 443), ('192.0.2.21', 443)])

    def test_every_group_bound_and_unknown_weight_is_rejected(self):
        for field, invalid in [('Version', 2), ('BackupPort', 0), ('BackupPort', '443'), ('IntervalSeconds', 4),
                               ('TimeoutSeconds', 0), ('TimeoutSeconds', 11), ('FailureThreshold', 1),
                               ('RecoveryThreshold', 11), ('RecoveryHoldSeconds', 0), ('AutoReturn', 'true'), ('Weight', 10)]:
            with self.subTest(field=field, invalid=invalid):
                value = rule(); value['TargetGroup'][field] = invalid
                with self.assertRaises((ValueError, TypeError)): TCP.normalize({'Version': 1, 'Rules': [value]})
        value = rule(); value['TargetGroup']['TimeoutSeconds'] = 3
        with self.assertRaises(ValueError): GROUP.normalize_group(value)

    def test_duplicate_invalid_mapped_and_null_targets_are_rejected(self):
        for address in ['0.0.0.0', '::', '224.0.0.1', '240.0.0.1', '::ffff:192.0.2.21', 'fe80::1%eth0', 'other.example.test', '192.0.2.20']:
            with self.subTest(address=address):
                value = rule(); value['TargetGroup']['BackupAddress'] = address
                with self.assertRaises(ValueError): GROUP.normalize_group(value)
        value = rule(); value['TargetGroup'] = None
        with self.assertRaises(ValueError): GROUP.normalize_group(value)

    def test_health_cannot_be_weakened_or_substituted(self):
        for kind in ['Tls', 'Ssh', 'Dns', 'Echo']:
            value = rule(kind); value['TargetGroup']['Health'] = {'Type': 'Connect'}
            with self.subTest(kind=kind), self.assertRaises(ValueError): GROUP.normalize_group(value, 'UDP' if kind in ['Dns', 'Echo'] else 'TCP')
        value = rule('Tls'); value['TargetGroup']['Health']['Insecure'] = True
        with self.assertRaises(ValueError): GROUP.normalize_group(value)

    def test_udp_groups_only_accept_actual_dns_or_echo_health(self):
        for kind in ['Dns', 'Echo']:
            value = rule(kind)
            self.assertEqual(UDP.normalize({'Version': 1, 'Rules': [value]})['Rules'][0]['TargetGroup'], value['TargetGroup'])
        value = rule('Echo'); value['Validation'] = {'Type': 'TcpChain', 'ChainId': 'b' * 32, 'FrontInstance': 'Example/Front/May-VPS-Deploy'}
        with self.assertRaises(ValueError): GROUP.normalize_group(value, 'UDP')

    def test_initial_choice_is_ordered_and_all_failed_is_closed(self):
        for outcomes, expected in [([True, True], 0), ([False, True], 1), ([True, False], 0), ([False, False], None)]:
            policy = GROUP.FailoverPolicy(rule()['TargetGroup'])
            self.assertEqual(policy.observe(outcomes), expected)

    def test_failures_must_be_consecutive_and_standby_must_be_healthy(self):
        policy = GROUP.FailoverPolicy(rule()['TargetGroup']); policy.observe([True, True])
        self.assertEqual(policy.observe([False, True]), 0)
        self.assertEqual(policy.observe([True, True]), 0)
        self.assertEqual(policy.observe([False, True]), 0)
        self.assertEqual(policy.observe([False, True]), 1)
        self.assertEqual(policy.observe([False, False]), 1)
        self.assertIsNone(policy.observe([False, False]))

    def test_recovery_needs_success_count_and_continuous_monotonic_hold(self):
        clock = Clock(); policy = GROUP.FailoverPolicy(rule()['TargetGroup'], clock); policy.observe([False, True])
        self.assertEqual(policy.observe([True, True]), 1); clock.advance()
        self.assertEqual(policy.observe([True, True]), 1); clock.advance()
        self.assertEqual(policy.observe([False, True]), 1); clock.advance()
        self.assertEqual(policy.observe([True, True]), 1); clock.advance()
        self.assertEqual(policy.observe([True, True]), 1); clock.advance()
        self.assertEqual(policy.observe([True, True]), 0)

    def test_no_automatic_return_keeps_standby_but_allows_emergency_primary(self):
        value = rule()['TargetGroup']; value['AutoReturn'] = False
        clock = Clock(); policy = GROUP.FailoverPolicy(value, clock); policy.observe([False, True]); clock.advance(1000)
        policy.observe([True, True]); self.assertEqual(policy.observe([True, True]), 1)
        policy.observe([True, False]); self.assertEqual(policy.observe([True, False]), 0)

    def test_tls_health_requires_a_valid_certificate_and_hostname(self):
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError: self.skipTest('cryptography is required for the isolated TLS CA')
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'target.example.test')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('target.example.test')]), False).sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); certificate = directory / 'cert.pem'; private = directory / 'key.pem'
            certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM)); private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.load_cert_chain(certificate, private)
            target = Target(tls=server); self.addCleanup(target.close)
            context = ssl.create_default_context(cafile=str(certificate)); value = rule('Tls')
            self.assertTrue(GROUP.health_probe(value, target.endpoint, context=context))
            self.assertFalse(GROUP.health_probe(value, target.endpoint))
            value['TargetGroup']['Health']['ServerName'] = 'wrong.example.test'
            self.assertFalse(GROUP.health_probe(value, target.endpoint, context=context))
            context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
            self.assertFalse(GROUP.health_probe(value, target.endpoint, context=context))

    def test_ssh_banner_and_connect_have_distinct_health_meanings(self):
        target = Target(banner=b'SSH-2.0-Synthetic\r\n'); self.addCleanup(target.close)
        self.assertTrue(GROUP.health_probe(rule(), target.endpoint))
        other = Target(banner=b'HTTP/1.1 200 OK\r\n'); self.addCleanup(other.close)
        self.assertFalse(GROUP.health_probe(rule(), other.endpoint))
        value = rule(); value['TargetGroup']['Health'] = {'Type': 'Connect'}
        self.assertTrue(GROUP.health_probe(value, other.endpoint))

    def test_udp_health_rejects_wrong_transaction_and_empty_service(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); server.bind(('127.0.0.1', 0)); server.settimeout(.1)
        stop = threading.Event(); mode = ['echo']
        def run():
            while not stop.is_set():
                try: data, peer = server.recvfrom(4096)
                except socket.timeout: continue
                except OSError: break
                if mode[0] == 'echo': server.sendto(data, peer)
                elif mode[0] == 'wrong': server.sendto(b'wrong', peer)
                elif mode[0] == 'dns':
                    answer = data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + data[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01'
                    server.sendto(answer, peer)
        worker = threading.Thread(target=run, daemon=True); worker.start()
        try:
            self.assertTrue(GROUP.health_probe(rule('Echo'), server.getsockname(), 'UDP'))
            mode[0] = 'wrong'; self.assertFalse(GROUP.health_probe(rule('Echo'), server.getsockname(), 'UDP'))
            mode[0] = 'dns'; self.assertTrue(GROUP.health_probe(rule('Dns'), server.getsockname(), 'UDP'))
            self.assertFalse(GROUP.health_probe(rule('Echo'), server.getsockname(), 'UDP'))
        finally: stop.set(); server.close(); worker.join(2)

    def test_real_tcp_switch_keeps_existing_stream_and_never_replays(self):
        primary, standby = Target(), Target(); self.addCleanup(primary.close); self.addCleanup(standby.close)
        value = rule(); value['TargetAddress'], value['TargetPort'] = primary.endpoint
        value['TargetGroup']['BackupAddress'], value['TargetGroup']['BackupPort'] = standby.endpoint
        value['TargetGroup']['Health'] = {'Type': 'Connect'}
        monitor = GROUP.TargetMonitor(value); monitor.round()
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); stop = threading.Event()
        errors = []
        def run():
            try: WORKER.run([listener], *primary.endpoint, None, idle=5, stop=stop, target_selector=monitor.selected)
            except Exception as error: errors.append(error)
        worker = threading.Thread(target=run, daemon=True); worker.start()
        old = socket.create_connection(listener.getsockname(), timeout=2)
        try:
            old.sendall(b'first'); self.assertEqual(old.recv(10), b'first')
            with monitor.lock: monitor.policy.observe([False, True]); monitor.policy.observe([False, True])
            with socket.create_connection(listener.getsockname(), timeout=2) as new:
                new.sendall(b'standby'); self.assertEqual(new.recv(10), b'standby')
            old.sendall(b'existing'); self.assertEqual(old.recv(16), b'existing')
            self.assertEqual(primary.connections, 2)  # One health connection and one original stream.
            self.assertEqual(standby.connections, 2)
            with monitor.lock: monitor.policy.observe([False, False]); monitor.policy.observe([False, False])
            with socket.create_connection(listener.getsockname(), timeout=2) as closed:
                try: data = closed.recv(1)
                except ConnectionResetError: data = b''
                self.assertEqual(data, b'')
        finally:
            old.close(); stop.set(); worker.join(3); listener.close(); monitor.close()
        self.assertFalse(worker.is_alive()); self.assertFalse(errors)

    def test_ipv6_standby_uses_its_own_target_family(self):
        if not socket.has_ipv6: self.skipTest('IPv6 is unavailable')
        try: standby = Target(socket.AF_INET6)
        except OSError: self.skipTest('IPv6 loopback is unavailable')
        self.addCleanup(standby.close); value = rule(); value['TargetGroup']['Health'] = {'Type': 'Connect'}
        self.assertTrue(GROUP.health_probe(value, standby.endpoint))

    def test_status_is_configuration_bound_and_stale_status_is_not_healthy(self):
        value = rule(); monitor = GROUP.TargetMonitor(value, probe=lambda target: True)
        with tempfile.TemporaryDirectory() as directory:
            monitor.status = Path(directory) / 'status.json'; snapshot = monitor.round()
            self.assertTrue(GROUP.group_status(value, monitor.status)['Fresh'])
            changed = copy.deepcopy(value); changed['TargetGroup']['BackupPort'] += 1
            self.assertFalse(GROUP.group_status(changed, monitor.status)['Fresh'])
            self.assertFalse(GROUP.group_status(value, monitor.status, snapshot['AtUnix'] + 100)['Fresh'])
            monitor.status.write_text('broken'); self.assertFalse(GROUP.group_status(value, monitor.status)['Fresh'])
        monitor.sampled = time.monotonic() - 1000
        self.assertIsNone(monitor.selected()); self.assertFalse(monitor.healthy(monitor.targets[0]))

    def test_group_program_is_snapshot_embedded_and_bounded(self):
        value = rule('Tls'); rendered = TCP.material({'Version': 1, 'Rules': [value]}, '/usr/lib/systemd/systemd-socket-proxyd')
        self.assertIn(TCP.GROUP_WORKER, rendered)
        compile(rendered[TCP.GROUP_WORKER], 'owned-worker.py', 'exec')
        service = rendered[TCP.unit_path(TCP.unit_name(value, 'service'))]
        for item in ['DynamicUser=yes', 'RuntimeDirectory=', 'MemoryMax=96M', '--transport TCP', '--rule ' + value['Id']]: self.assertIn(item, service)
        self.assertNotIn('Weight', service)

    def test_group_files_follow_existing_component_snapshot_and_recovery(self):
        fixture = owned_fixture.ForwardingOwnership(methodName='runTest'); fixture.setUp()
        try:
            original = fixture.apply(); fixture.snapshot()
            value = copy.deepcopy(original['Configuration']); value['Rules'][0]['TargetGroup'] = rule('Tls')['TargetGroup']
            grouped = fixture.host.apply(TCP.normalize(value), original['Hash'], 'Apply', module_backup())
            self.assertIn(TCP.GROUP_WORKER, grouped['Files'])
            fixture.restore(); self.assertEqual(fixture.host.read()['Hash'], original['Hash'])
            self.assertFalse(fixture.host.path(TCP.GROUP_WORKER).exists())
        finally: fixture.doCleanups()

    def test_backup_self_loop_is_refused_before_component_writes(self):
        fixture = owned_fixture.ForwardingOwnership(methodName='runTest'); fixture.setUp()
        try:
            value = rule('Tls'); value['TargetGroup']['BackupAddress'] = '127.0.0.1'; value['TargetGroup']['BackupPort'] = value['ListenPort']
            with self.assertRaises(ValueError): fixture.host.preflight(TCP.normalize({'Version': 1, 'Rules': [value]}))
            self.assertEqual(fixture.host.read()['Hash'], 'Absent')
        finally: fixture.doCleanups()


def module_backup():
    from test_tcp_forwarding import BACKUP
    return BACKUP


if __name__ == '__main__': unittest.main()
