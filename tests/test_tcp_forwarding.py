"""Owned-resource/recovery tests; optional real Linux socket-proxyd loopback."""
import copy
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('tcp_forwarding', ROOT / 'scripts/tcp-forwarding.py')
TCP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TCP)
BACKUP = PurePosixPath('/root/vps-deploy-backups/20261021-120000/protocol-lifecycle')


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def config():
    return {'Version': 1, 'Rules': [{'Id': 'a' * 32, 'Name': 'Synthetic forward', 'Enabled': True,
            'ListenFamily': 'IPv4', 'ListenPort': port(), 'TargetAddress': '192.0.2.20', 'TargetPort': 443,
            'AllowedSources': ['127.0.0.1/32'], 'Validation': {'Type': 'Tls', 'ServerName': 'target.example.test'}}]}


class Kernel:
    def __init__(self, root, driver=TCP):
        self.root, self.table, self.units, self.commands = root, None, {}, []
        self.driver = driver
        self.dropins = ''

    def __call__(self, args, **kwargs):
        self.commands.append(args)
        code, output = 0, ''
        if args[:4] == ['nft', '-j', 'list', 'tables']:
            output = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': self.driver.TABLE}}] if self.table else []})
        elif args[:3] == ['nft', '-s', '-nn']:
            output = self.table
        elif args[:3] == ['nft', '-c', '-f']:
            pass
        elif args[:2] == ['systemctl', 'show']:
            output = self.dropins if args[4] == 'DropInPaths' else '/etc/systemd/system/' + args[2]
        elif args[:2] == ['systemctl', 'is-enabled']:
            code = 0 if self.units.get(args[-1], False) else 1
        elif args[:2] == ['systemctl', 'is-active']:
            code = 0 if self.units.get(args[-1], False) else 1
        elif args[0] == 'systemctl' and args[1] in ('enable', 'disable'):
            enabled = args[1] == 'enable'
            self.units[args[-1]] = enabled
            if args[-1] == self.driver.ACL_UNIT:
                self.table = (self.root / self.driver.ACL.lstrip('/')).read_text() if enabled else None
        elif args == ['systemctl', 'daemon-reload']:
            pass
        elif args == ['ip', '-j', 'address', 'show']:
            output = json.dumps([{'addr_info': [{'local': '127.0.0.1'}, {'local': '::1'}, {'local': '192.0.2.10'}]}])
        else:
            raise AssertionError('Unexpected fixture command: ' + repr(args))
        return subprocess.CompletedProcess(args, code, output, '')


def check_unit_revision(case, driver):
    before = case.apply()
    unit = case.host.path(driver.unit_path(driver.ACL_UNIT))
    current = unit.read_text()
    case.assertIn('DefaultDependencies=no\n', current)
    case.assertIn('Before=sockets.target shutdown.target\n', current)
    older = current.replace('DefaultDependencies=no\n', '').replace('Before=sockets.target shutdown.target\n', '').replace('Conflicts=shutdown.target\n', '')
    unit.write_bytes(older.encode())
    with case.assertRaises(ValueError):
        case.host.read()
    identity = case.host.identity(before['Files'])
    expected = driver.digest(driver.encoded(dict(identity, Units=before['Units'])))
    case.host = driver.Host(case.root, case.kernel, archived_hash=expected)
    case.assertFalse(case.host.read()['TemplateCurrent'])
    with case.assertRaises(ValueError):
        driver.Host(case.root, case.kernel, archived_hash='f' * 64).read()
    case.snapshot()
    result = case.host.apply(before['Configuration'], expected, 'Apply', BACKUP)
    case.assertTrue(result['TemplateCurrent'])
    case.assertEqual(unit.read_text(), current)
    case.restore()
    case.assertEqual(unit.read_text(), older)
    case.assertFalse(case.host.read()['TemplateCurrent'])
    unit.write_bytes((older + '\n# external edit\n').encode())
    with case.assertRaises(ValueError):
        case.host.read()


class ForwardingOwnership(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'Linux TCP TIME_WAIT binding semantics')
    def test_preflight_allows_closed_tcp_sessions_but_rejects_a_live_listener(self):
        value = config()
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        value['Rules'][0]['ListenPort'] = listener.getsockname()[1]
        with self.assertRaises(OSError): self.host.preflight(TCP.normalize(value))
        peer = socket.create_connection(listener.getsockname())
        accepted, _ = listener.accept()
        accepted.shutdown(socket.SHUT_WR)
        self.assertEqual(peer.recv(1), b'')
        peer.close(); accepted.close(); listener.close()
        with socket.socket() as old_style:
            with self.assertRaises(OSError): old_style.bind(('0.0.0.0', value['Rules'][0]['ListenPort']))
        self.assertEqual(self.host.preflight(TCP.normalize(value))['Hash'], 'Absent')

    def test_chain_owned_rules_keep_strict_identity(self):
        value = config()
        value['Rules'][0]['Validation'] = {'Type': 'TcpChain', 'ChainId': 'b' * 32, 'FrontInstance': 'Example/Front/May-VPS-Deploy'}
        normalized = TCP.normalize(value)
        self.assertEqual(normalized['Rules'][0]['Validation'], value['Rules'][0]['Validation'])
        for field, bad in [('ChainId', '../other'), ('FrontInstance', 'Example/../May-VPS-Deploy')]:
            edited = copy.deepcopy(value)
            edited['Rules'][0]['Validation'][field] = bad
            with self.assertRaises(ValueError): TCP.normalize(edited)
        value['Rules'][0]['Validation']['Unreviewed'] = True
        with self.assertRaises(ValueError): TCP.normalize(value)

    def test_unit_revision_is_pinned_to_the_controller_archive(self):
        check_unit_revision(self, TCP)

    def setUp(self):
        (ROOT / '.test-output').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='tcp-forward-', dir=ROOT / '.test-output')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for item in ('usr/lib/systemd/systemd-socket-proxyd', 'usr/sbin/nft'):
            path = self.root / item
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic-tool')
        self.kernel = Kernel(self.root)
        self.host = TCP.Host(self.root, self.kernel)
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
        return self.host.apply(TCP.normalize(value), self.host.read()['Hash'], 'Apply', BACKUP)

    def restore(self):
        self.host.rollback_prepare(BACKUP)
        with tarfile.open(self.backup / 'protocol-files.tar.gz') as archive:
            for member in archive.getmembers():
                path = self.host.path('/' + member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile(member).read())
        self.host.rollback_complete(BACKUP)

    def test_install_disable_remove_and_scope(self):
        sentinel = self.root / 'etc/sing-box/config.json'
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b'existing-private-config')
        value = config()
        first = self.apply(value)
        self.assertEqual(first['Configuration'], value)
        self.assertIn('--exit-idle-time=60s', self.host.path(TCP.unit_path(TCP.unit_name(value['Rules'][0], 'service'))).read_text())
        self.assertIn('NoNewPrivileges=yes', self.host.path(TCP.unit_path(TCP.unit_name(value['Rules'][0], 'service'))).read_text())
        value['Rules'][0]['Enabled'] = False
        self.snapshot()
        disabled = self.host.apply(value, first['Hash'], 'Apply', BACKUP)
        self.assertNotEqual(first['Hash'], disabled['Hash'])
        self.assertFalse(self.kernel.units[TCP.unit_name(value['Rules'][0], 'socket')])
        self.snapshot()
        self.assertEqual(self.host.apply({'Version': 1, 'Rules': []}, disabled['Hash'], 'Remove', BACKUP)['Hash'], 'Absent')
        self.assertEqual(sentinel.read_bytes(), b'existing-private-config')

    def test_new_install_rollback(self):
        self.apply()
        self.restore()
        self.assertEqual(self.host.read()['Hash'], 'Absent')

    def test_replace_rollback_restores_bytes_and_enablement(self):
        before = self.apply()
        changed = copy.deepcopy(before['Configuration'])
        changed['Rules'][0]['TargetPort'] = 8443
        changed['Rules'][0]['Enabled'] = False
        self.snapshot()
        self.host.apply(changed, before['Hash'], 'Apply', BACKUP)
        self.restore()
        self.assertEqual(self.host.read(), before)

    def test_config_and_unit_drift_refused(self):
        self.apply()
        path = self.host.path(TCP.CONFIG)
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            self.host.read()
        self.assertTrue(path.read_bytes().endswith(b' '))

    def test_interrupted_recovery_can_finish_original_snapshot(self):
        before = self.apply()
        changed = copy.deepcopy(before['Configuration'])
        changed['Rules'][0]['TargetPort'] = 8443
        self.snapshot()
        self.host.apply(changed, before['Hash'], 'Apply', BACKUP)
        self.host.rollback_prepare(BACKUP)
        # A cut connection can leave the original and missing files mixed.
        with tarfile.open(self.backup / 'protocol-files.tar.gz') as archive:
            member = archive.getmembers()[0]
            path = self.host.path('/' + member.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())
        self.restore()
        self.assertEqual(self.host.read(), before)
        self.assertFalse(self.host.journal(BACKUP)['Recovering'])

    def test_interrupted_recovery_still_preserves_external_edit(self):
        self.apply()
        self.host.rollback_prepare(BACKUP)
        path = self.host.path(TCP.CONFIG)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'external-edit-after-recovery-started')
        with self.assertRaises(ValueError):
            self.host.rollback_prepare(BACKUP)
        self.assertEqual(path.read_bytes(), b'external-edit-after-recovery-started')

    def test_runtime_acl_drift_refused(self):
        self.apply()
        self.kernel.table += '\n# harmless formatting\n'
        self.host.read()
        self.kernel.table = self.kernel.table.replace(' drop', ' accept')
        with self.assertRaises(ValueError):
            self.host.read()
        with self.assertRaises(ValueError):
            self.host.rollback_check(BACKUP)

    def test_external_edit_survives_recovery(self):
        value = self.apply()
        path = self.host.path(TCP.CONFIG)
        path.write_bytes(b'external-edit')
        with self.assertRaises(ValueError):
            self.host.rollback_prepare(BACKUP)
        self.assertEqual(path.read_bytes(), b'external-edit')
        self.assertTrue(self.kernel.units[TCP.unit_name(value['Configuration']['Rules'][0], 'socket')])

    def test_dropin_and_unknown_file_refused(self):
        self.apply()
        self.kernel.dropins = '/etc/systemd/system/override.conf'
        with self.assertRaises(ValueError):
            self.host.read()
        self.kernel.dropins = ''
        path = self.host.path('/etc/may-tcp-forward/private.local')
        path.write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            self.host.read()
        self.assertEqual(path.read_bytes(), b'preserve')

    def test_unmanaged_namespace_and_table_refused(self):
        self.kernel.table = 'table inet may_tcp_forward { chain input { policy accept; } }'
        with self.assertRaises(ValueError):
            self.host.read()
        self.kernel.table = None
        path = self.host.path('/etc/systemd/system/may-tcp-forward-foreign.service')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            self.host.read()

    def test_listener_collision_and_local_loop(self):
        value = config()
        with socket.socket() as listener:
            listener.bind(('0.0.0.0', value['Rules'][0]['ListenPort']))
            listener.listen()
            with self.assertRaises(OSError):
                self.host.preflight(value)
        value['Rules'][0].update(TargetAddress='127.0.0.1', TargetPort=value['Rules'][0]['ListenPort'])
        with self.assertRaises(ValueError):
            self.host.preflight(value)

    def test_stale_hash_precedes_mutation(self):
        self.snapshot()
        with self.assertRaises(ValueError):
            self.host.apply(config(), 'a' * 64, 'Apply', BACKUP)
        self.assertFalse(any(c[:2] == ['systemctl', 'disable'] for c in self.kernel.commands))

    def test_invalid_recovery_paths(self):
        self.apply()
        path = self.backup / 'tcp-forward-state.json'
        journal = json.loads(path.read_text())
        journal['Applied']['Files']['/etc/ssh/sshd_config'] = None
        path.write_text(json.dumps(journal))
        with self.assertRaises(ValueError):
            self.host.rollback_check(BACKUP)

    def test_backup_corruption_precedes_stop(self):
        self.apply()
        self.snapshot()
        (self.backup / 'protocol-files.tar.gz').write_bytes(b'broken')
        before = len(self.kernel.commands)
        with self.assertRaises(tarfile.TarError):
            self.host.rollback_check(BACKUP)
        self.assertFalse(any(c[:2] == ['systemctl', 'disable'] for c in self.kernel.commands[before:]))

    def test_strict_rule_boundaries_and_normalized_sources(self):
        value = config()
        value['Rules'][0]['AllowedSources'] = ['192.0.2.99/24', '2001:db8::123/64']
        self.assertEqual(TCP.normalize(value)['Rules'][0]['AllowedSources'], ['192.0.2.0/24', '2001:db8::/64'])
        for key, invalid in [('TargetAddress', '::ffff:127.0.0.1'), ('TargetAddress', '::'), ('ListenPort', True), ('Enabled', 'true'), ('AllowedSources', [])]:
            bad = copy.deepcopy(value)
            bad['Rules'][0][key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                TCP.normalize(bad)

    def test_table_canonicalization_and_ipv6_units(self):
        value = config()
        value['Rules'][0].update(ListenFamily='DualStack', TargetAddress='2001:db8::20')
        files = TCP.material(value, '/usr/lib/systemd/systemd-socket-proxyd')
        text = files[TCP.unit_path(TCP.unit_name(value['Rules'][0], 'socket'))]
        self.assertIn('ListenStream=[::]:', text)
        self.assertIn('ListenStream=0.0.0.0:', text)
        self.assertIn('BindIPv6Only=ipv6-only', text)
        self.assertIn('2001:db8::20:443', files[TCP.unit_path(TCP.unit_name(value['Rules'][0], 'service'))])
        simple = 'table inet may_tcp_forward { chain input { type filter hook input priority -10; policy accept; iifname "lo" accept; tcp dport 1234 ip saddr 127.0.0.1 accept; tcp dport 1234 drop; } }'
        candidate = simple.replace('saddr 127.0.0.1', 'saddr { 127.0.0.1/32 }')
        self.assertEqual(TCP.canonical_table(candidate), TCP.canonical_table(simple))


@unittest.skipUnless(sys.platform == 'linux' and Path('/usr/lib/systemd/systemd-socket-proxyd').is_file(), 'Linux systemd-socket-proxyd is unavailable')
class NativeProxyLoopback(unittest.TestCase):
    def check_family(self, family, address):
        payload = os.urandom(524288)
        errors = []
        with socket.socket(family, socket.SOCK_STREAM) as backend, socket.socket(family, socket.SOCK_STREAM) as listener:
            if family == socket.AF_INET6:
                backend.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            backend.bind((address, 0))
            listener.bind((address, 0))
            backend.listen()
            listener.listen()
            def respond():
                try:
                    with backend.accept()[0] as connection:
                        connection.settimeout(8)
                        received = bytearray()
                        while len(received) < len(payload):
                            chunk = connection.recv(65536)
                            if not chunk:
                                break
                            received.extend(chunk)
                        self.assertEqual(bytes(received), payload)
                        connection.sendall(TCP.digest(bytes(received)).encode())
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=respond, daemon=True)
            thread.start()
            destination = address
            script = 'import os,sys; fd=int(sys.argv[2]); os.dup2(fd,3); os.set_inheritable(3,True); os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS="1"); os.execv(sys.argv[1],[sys.argv[1],"--exit-idle-time=1s",sys.argv[3]])'
            process = subprocess.Popen([sys.executable, '-c', script, '/usr/lib/systemd/systemd-socket-proxyd', str(listener.fileno()), destination + ':' + str(backend.getsockname()[1])], pass_fds=(listener.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                with socket.socket(family, socket.SOCK_STREAM) as client:
                    client.settimeout(10)
                    client.connect(listener.getsockname())
                    client.sendall(payload)
                    response = bytearray()
                    while len(response) < 64:
                        chunk = client.recv(64 - len(response))
                        if not chunk:
                            break
                        response.extend(chunk)
                    self.assertEqual(response.decode(), TCP.digest(payload))
                thread.join(10)
                self.assertFalse(thread.is_alive())
                if errors:
                    raise errors[0]
                self.assertEqual(process.wait(8), 0)
            except BaseException:
                if process.poll() is None:
                    process.kill()
                _, detail = process.communicate(timeout=5)
                print('Native socket-proxyd diagnostic: ' + detail.decode(errors='replace')[:2000], file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_ipv4_actual_data_and_idle_exit(self):
        self.check_family(socket.AF_INET, '127.0.0.1')

    def test_ipv6_actual_data_and_idle_exit(self):
        self.check_family(socket.AF_INET6, '::1')


if __name__ == '__main__':
    unittest.main()
