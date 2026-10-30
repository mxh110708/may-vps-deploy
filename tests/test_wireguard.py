"""WireGuard safety boundaries, runtime ownership and scoped file recovery.
Actual kernel, firewall, reboot and encrypted paths use --wireguard-vm.
"""
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wg_runtime', ROOT / 'scripts/wireguard-runtime.py')
wg = importlib.util.module_from_spec(spec); spec.loader.exec_module(wg)
space = {'__name__': 'component_test', 'WIREGUARD_RUNTIME_SOURCE': (ROOT / 'scripts/wireguard-runtime.py').read_text()}
exec(compile((ROOT / 'scripts/forwarding-host.py').read_text(), '<forward-host>', 'exec'), space)
exec(compile((ROOT / 'scripts/wireguard-runtime.py').read_text(), '<wireguard-runtime>', 'exec'), space)
exec(compile((ROOT / 'scripts/wireguard-host.py').read_text(), '<wireguard-host>', 'exec'), space)


def config():
    return dict(Version=1, Id='a' * 32, Family='IPv4', Endpoint='192.0.2.20', SourceAddress='192.0.2.10', ListenPort=51820, EndpointPort=51821, LocalAddress='10.203.0.1', PeerAddress='10.203.0.2', Mtu=1380, KeepaliveSeconds=0, PublicKey=base64.b64encode(b'1' * 32).decode(), PeerPublicKey=base64.b64encode(b'2' * 32).decode())


class WireGuardTests(unittest.TestCase):
    def test_unknown_mutation_is_refused_before_touching_files(self):
        host = space['WireGuardHost']()
        with self.assertRaises(ValueError): host.apply({}, 'Absent', 'Unknown', Path('/not-a-transaction'))

    def test_no_arbitrary_routes_or_hooks(self):
        for key, value in [('AllowedIPs', '0.0.0.0/0'), ('PostUp', 'sh'), ('DNS', '8.8.8.8'), ('Table', 'main')]:
            with self.subTest(key=key), self.assertRaises(ValueError): wg.wg_normalize(dict(config(), **{key: value}))

    def test_address_types_and_global_scopes_rejected(self):
        for field, values in [('LocalAddress', ['0.0.0.0', '127.0.0.1', '8.8.8.8', '2001:db8::1', 123]), ('Endpoint', ['::ffff:192.0.2.20', 'fe80::1%eth0', '0.0.0.0', '255.255.255.255', '0.1.2.3', 1])]:
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError): wg.wg_normalize(dict(config(), **{field: value}))

    def test_distinct_peer_and_keys(self):
        for key, value in [('PeerAddress', '10.203.0.1'), ('PeerPublicKey', config()['PublicKey']), ('Endpoint', config()['SourceAddress'])]:
            with self.subTest(key=key), self.assertRaises(ValueError): wg.wg_normalize(dict(config(), **{key: value}))

    def test_outer_ipv6_does_not_expand_inner_routes(self):
        c = dict(config(), Family='IPv6', SourceAddress='2001:db8::10', Endpoint='2001:db8::20')
        self.assertEqual(wg.wg_endpoint(wg.wg_normalize(c)), '[2001:db8::20]:51821')
        self.assertEqual(c['PeerAddress'], '10.203.0.2')

    def test_key_and_keepalive_bounds(self):
        for key in ['', 'x' * 44, base64.b64encode(bytes(32)).decode()]:
            with self.assertRaises(ValueError): wg.wg_key(key)
        for value in [True, '25', -1, 1, 121]:
            with self.assertRaises(ValueError): wg.wg_normalize(dict(config(), KeepaliveSeconds=value))
        self.assertEqual(wg.wg_normalize(dict(config(), KeepaliveSeconds=25))['KeepaliveSeconds'], 25)

    def command(self, c, failure=None):
        values = {'public-key': c['PublicKey'], 'listen-port': str(c['ListenPort']), 'peers': c['PeerPublicKey'], 'allowed-ips': c['PeerPublicKey'] + '\t' + c['PeerAddress'] + '/32', 'endpoints': c['PeerPublicKey'] + '\t' + wg.wg_endpoint(c), 'persistent-keepalive': c['PeerPublicKey'] + '\toff'}
        def run(argv, **kwargs):
            if argv[:2] == ['wg', 'show']:
                value = values[argv[-1]]
                if failure == argv[-1]: value = 'external drift'
            elif argv[:4] == ['ip', '-j', '-4', 'address']: value = json.dumps([{'addr_info': [{'family': 'inet', 'local': c['LocalAddress'], 'prefixlen': 32}]}])
            elif argv[:5] == ['ip', '-j', '-4', 'route', 'get']: value = json.dumps([{'dev': 'eth0' if failure == 'route' else 'maywg0'}])
            else: value = json.dumps([{'dst': c['PeerAddress']}, *([{'dst': 'default'}] if failure == 'extra-route' else [])])
            return subprocess.CompletedProcess(argv, 0, value + '\n', '')
        return run

    def test_runtime_rejects_direct_fallback_and_extra_routes(self):
        c = config(); links = [{'ifname': 'maywg0', 'ifalias': wg.wg_alias(c), 'mtu': c['Mtu'], 'flags': ['UP']}]
        for failure in ['route', 'extra-route', 'public-key', 'peers', 'allowed-ips', 'endpoints', 'listen-port', 'persistent-keepalive']:
            with self.subTest(failure=failure), patch.object(wg, 'wg_links', return_value=links), patch.object(wg, 'wg_command', side_effect=self.command(c, failure)), self.assertRaises(ValueError): wg.wg_runtime_check(c)

    def test_valid_runtime(self):
        c = config(); links = [{'ifname': 'maywg0', 'ifalias': wg.wg_alias(c), 'mtu': c['Mtu'], 'flags': ['UP']}]
        with patch.object(wg, 'wg_links', return_value=links), patch.object(wg, 'wg_command', side_effect=self.command(c)): wg.wg_runtime_check(c)

    def test_unowned_interface_never_deleted(self):
        with patch.object(wg, 'wg_links', return_value=[{'ifname': 'maywg0', 'ifalias': 'external owner'}]), patch.object(wg, 'wg_command') as command, self.assertRaises(ValueError): wg.wg_down(config())
        command.assert_not_called()

    def test_replaced_key_never_deleted(self):
        c = config(); links = [{'ifname': 'maywg0', 'ifalias': wg.wg_alias(c)}]
        with patch.object(wg, 'wg_links', return_value=links), patch.object(wg, 'wg_command', return_value=subprocess.CompletedProcess([], 0, 'changed key', '')) as command, self.assertRaises(ValueError): wg.wg_down(c)
        self.assertEqual(command.call_args_list[0].args[0], ['wg', 'show', 'maywg0', 'public-key'])
        self.assertEqual(command.call_count, 1)

    def test_challenge_is_bounded_and_non_executable(self):
        for values in [('10.0.0.1', '10.0.0.2', '0', 'a'*64), ('10.0.0.1', '8.8.8.8', '50000', 'a'*64), ('10.0.0.1', '10.0.0.2', '50000', '; rm -rf')]:
            with self.assertRaises(ValueError): wg.wg_proof_parameters(*values)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux host filesystem semantics required')
    def test_recovery_rejects_unowned_and_altered_files(self):
        with tempfile.TemporaryDirectory() as directory:
            host = space['WireGuardHost'](root=Path(directory)); backup = Path('/root/vps-deploy-backups/20261030-120000/protocol-lifecycle'); local = host.path(str(backup)); local.mkdir(parents=True)
            journal = {'Version': 1, 'Original': {'Files': {}, 'Table': None}, 'OriginalUnits': {}, 'Applied': {'Files': {space['WG_KEY']: 'f'*64}, 'Table': None}}
            host.write_journal(local, journal); key = host.path(space['WG_KEY']); key.parent.mkdir(parents=True); key.write_text('unreviewed edit')
            with patch.dict(space, {'wg_links': lambda: []}), self.assertRaises(ValueError): host.rollback_check(backup)
            journal['Applied']['Files'] = {'/etc/shadow': None}; host.write_journal(local, journal)
            with self.assertRaises(ValueError): host.journal(backup)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux host filesystem semantics required')
    def test_snapshot_tar_cannot_substitute_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            host = space['WireGuardHost'](root=Path(directory)); backup = Path('/root/vps-deploy-backups/20261030-120000/protocol-lifecycle'); local = host.path(str(backup)); local.mkdir(parents=True)
            path = space['WG_KEY']; key = host.path(path); key.parent.mkdir(parents=True); key.write_text('original key')
            journal = {'Version': 1, 'Original': {'Files': {path: space['digest']('original key')}, 'Table': None}, 'OriginalUnits': {}}
            host.write_journal(local, journal)
            with tarfile.open(local/'protocol-files.tar.gz','w:gz') as archive:
                item = tarfile.TarInfo(path.lstrip('/')); payload=b'wrong key'; item.size=len(payload); archive.addfile(item,io.BytesIO(payload))
            with patch.dict(space, {'wg_links': lambda: []}), self.assertRaises(ValueError): host.rollback_check(backup)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux host filesystem semantics required')
    def test_removal_compensation_recreates_private_directory_before_tar(self):
        with tempfile.TemporaryDirectory() as directory:
            host = space['WireGuardHost'](root=Path(directory)); backup = Path('/root/vps-deploy-backups/20261030-120000/protocol-lifecycle'); local = host.path(str(backup)); local.mkdir(parents=True)
            path = space['WG_KEY']; payload = b'original test-only key'
            journal = {'Version': 1, 'Original': {'Files': {path: space['digest'](payload)}, 'Table': None}, 'OriginalUnits': {}, 'Applied': {'Files': {path: None}, 'Table': None}}
            host.write_journal(local, journal)
            with tarfile.open(local/'protocol-files.tar.gz','w:gz') as archive:
                item=tarfile.TarInfo(path.lstrip('/')); item.size=len(payload); archive.addfile(item,io.BytesIO(payload))
            host.stop=lambda paths: None
            with patch.dict(space, {'wg_links': lambda: []}): host.rollback_prepare(backup)
            self.assertEqual(host.path(space['WG_DIRECTORY']).stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux host filesystem semantics required')
    def test_linked_paths_are_refused(self):
        if not hasattr(Path, 'symlink_to'): self.skipTest('No symlink support')
        with tempfile.TemporaryDirectory() as directory:
            host=space['WireGuardHost'](root=Path(directory)); target=host.path(space['WG_KEY']); target.parent.mkdir(parents=True)
            try: target.symlink_to('outside')
            except OSError: self.skipTest('Local symlink permission unavailable')
            with self.assertRaises(ValueError): host.regular(space['WG_KEY'],True)


if __name__ == '__main__': unittest.main()
