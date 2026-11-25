"""Address transaction contracts using disposable files and command fixtures.
Strict ownership/runtime tests run on Linux; they never operate host services.
"""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('address39', REPOSITORY / 'scripts/instance-address.py')
address = importlib.util.module_from_spec(spec)
spec.loader.exec_module(address)
address.ADDRESS_SOURCES = {p.stem: p.read_text(encoding='utf-8-sig') for p in (REPOSITORY / 'scripts').glob('*.py')}
firewall = (REPOSITORY / 'assets/remote/firewall-tools.sh').read_text(encoding='utf-8-sig')
address.ADDRESS_SOURCES['firewall-canonical'] = 'import re, ipaddress, subprocess\n' + firewall[firewall.index('def table('):firewall.index('def identity(')]
launcher_spec = importlib.util.spec_from_file_location('address_launcher39', REPOSITORY / 'scripts/instance-address-launcher.py')
launcher = importlib.util.module_from_spec(launcher_spec)
launcher_spec.loader.exec_module(launcher)


class HostCommands:
    def __init__(self, root):
        self.root, self.states, self.tables, self.acls = root, {}, {}, {}
        self.fail_start = False
        self.commands = []

    def __call__(self, args, **kwargs):
        self.commands.append(list(args))
        result, output = 0, ''
        if args[0] == 'systemctl':
            if args[1] in ('is-enabled', 'is-active'):
                unit = args[-1]
                result = 0 if self.states.get(unit, {'Active': True, 'Enabled': True})['Active' if args[1] == 'is-active' else 'Enabled'] else 1
            elif args[1] == 'show':
                if 'ExecStart' in args:
                    output = '/usr/local/bin/xray run -config /usr/local/etc/xray/config.json'
                elif 'FragmentPath' in args:
                    output = '/etc/systemd/system/' + args[2]
            elif args[1] in ('start', 'stop', 'enable', 'disable'):
                unit = args[-1]
                state = self.states.setdefault(unit, {'Active': True, 'Enabled': True})
                if args[1] in ('enable', 'disable'):
                    state['Enabled'] = args[1] == 'enable'
                if args[1] in ('start', 'stop') or '--now' in args:
                    state['Active'] = args[1] in ('start', 'enable')
                if state['Active'] and self.fail_start:
                    self.fail_start = False
                    return subprocess.CompletedProcess(args, 1, '', 'synthetic restart failure')
                if unit in self.acls:
                    table, name = self.acls[unit]
                    if state['Active']:
                        self.tables[table] = (self.root / name.lstrip('/')).read_text()
                    else:
                        self.tables.pop(table, None)
        elif args[0] == 'nft':
            if args[1:4] == ['-j', 'list', 'tables']:
                output = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': t}} for t in self.tables]})
            elif 'list' in args:
                output = self.tables[args[-1]]
            elif args[1] == '-f':
                self.tables['filter'] = Path(args[-1]).read_text()
        elif args[0] == 'ip':
            output = json.dumps([{'addr_info': [{'local': '192.0.2.10'}, {'local': '192.0.2.11'}, {'local': '127.0.0.1'}]}])
        elif args[0] == '/usr/local/bin/xray':
            json.loads(Path(args[-1]).read_text())
        return subprocess.CompletedProcess(args, result, output, '')


class AddressPureTests(unittest.TestCase):
    def test_nft_adjacent_sources_and_extra_source_have_different_scope(self):
        for kind in ('TcpForwarding', 'UdpForwarding', 'Firewall'):
            a = address.Adapter({'Kind': kind, 'ExpectedHash': '0' * 64}, Path('/unused'), None, {})
            canonical = a.host.canonical_table if a.host else a.ns['canonical']
            table = a.host.TABLE if a.host else 'filter'
            raw = 'table inet ' + table + ' {\n chain input {\n ip saddr %s accept\n }\n}\n'
            self.assertEqual(canonical(raw % '{ 192.0.2.10, 192.0.2.11 }'), canonical(raw % '192.0.2.10/31'))
            self.assertEqual(canonical(raw % '{ 2001:db8::10, 2001:db8::11 }'), canonical(raw % '2001:db8::10/127'))
            self.assertNotEqual(canonical(raw % '{ 192.0.2.10, 192.0.2.11 }'), canonical(raw % '192.0.2.8/30'))
    def test_only_connections_and_host_sources_change(self):
        value = {'server': '192.0.2.10', 'servername': '192.0.2.10', 'Name': '192.0.2.10',
                 'AllowedSources': ['192.0.2.10/32', '192.0.2.0/24'], 'Endpoint': '[2001:db8::1]:443'}
        result = address.rewrite(value, {'192.0.2.10': '192.0.2.11', '2001:db8::1': '2001:db8::2'})
        self.assertEqual(result['server'], '192.0.2.11')
        self.assertEqual(result['servername'], value['servername'])
        self.assertEqual(result['Name'], value['Name'])
        self.assertEqual(result['AllowedSources'], ['192.0.2.11/32', '192.0.2.0/24'])
        self.assertEqual(result['Endpoint'], '[2001:db8::2]:443')
        self.assertEqual(value['server'], '192.0.2.10')

    def test_bridge_preserves_old_and_new_until_finalize(self):
        before = {'Rules': [{'TargetAddress': '192.0.2.10', 'AllowedSources': ['192.0.2.10/32']}]}
        mapping = {'192.0.2.10': '192.0.2.11'}
        bridge = address.rewrite(before, mapping, True, True)
        during = address.merge_sources(address.rewrite(before, mapping), bridge)
        self.assertEqual(bridge['Rules'][0]['TargetAddress'], '192.0.2.10')
        self.assertEqual(during['Rules'][0]['TargetAddress'], '192.0.2.11')
        self.assertEqual(during['Rules'][0]['AllowedSources'], ['192.0.2.10/32', '192.0.2.11/32'])


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires isolated Linux root fixture')
class AddressResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='may-address39-')
        self.root = Path(self.temp.name)
        self.run = HostCommands(self.root)
        self.mapping = {'192.0.2.10': '192.0.2.11'}
        self.original = {'inbounds': [], 'outbounds': [{'protocol': 'freedom', 'settings': {}, 'address': '192.0.2.10'}], 'tls': {'server_name': '192.0.2.10'}}
        self.protocol = '/usr/local/etc/xray/config.json'
        self.write(self.protocol, address.compact(self.original).encode())
        self.write('/usr/local/bin/xray', b'fixture core')
        self.resource = {'Kind': 'RealityEntry', 'Component': 'RealityEntry', 'ExpectedHash': address.sha(address.compact(self.original)),
                         'Before': self.original, 'After': address.rewrite(self.original, self.mapping)}
        self.document = {'Task': 'a' * 32, 'Addresses': self.mapping, 'Resources': [self.resource]}

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data):
        target = self.root / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o600)
        return target

    def host(self):
        return address.AddressHost(copy.deepcopy(self.document), self.root, self.run)

    def test_fresh_process_stages_and_exact_restore(self):
        before = (self.root / self.protocol.lstrip('/')).read_bytes()
        self.assertEqual(self.host().inspect()['Phase'], 'Inspected')
        self.assertFalse(self.host().directory.exists())
        self.host().prepare()
        self.host().apply('Bridge')
        self.assertEqual((self.root / self.protocol.lstrip('/')).read_bytes(), before)
        self.host().apply('Apply')
        self.assertEqual(json.loads((self.root / self.protocol.lstrip('/')).read_text())['outbounds'][0]['address'], '192.0.2.11')
        self.assertTrue(self.host().status()['Consistent'])
        self.host().apply('Finalize')
        restored = self.host().rollback()
        self.assertEqual(restored['Phase'], 'RolledBack')
        self.assertTrue(restored['Consistent'])
        self.assertEqual((self.root / self.protocol.lstrip('/')).read_bytes(), before)
        self.assertEqual(self.host().file.stat().st_mode & 0o777, 0o600)

    def test_recovery_uses_reviewed_program_after_application_update(self):
        original = b'# pinned synthetic program\n'
        current = self.write('/tmp/current.py', original)
        doc = dict(self.document, ProgramSha256=address.sha(original))
        host = address.AddressHost(doc, self.root, self.run, program=original)
        self.assertEqual(launcher.select(doc, 'Prepare', current, self.root), current)
        host.prepare()
        saved = host.directory / 'recovery.py'
        current.write_bytes(b'# upgraded application\n')
        self.assertEqual(launcher.select(doc, 'Rollback', current, self.root), saved)
        with self.assertRaises(ValueError):
            launcher.select(doc, 'Inspect', current, self.root)
        saved.chmod(0o644)
        with self.assertRaises(ValueError):
            launcher.select(doc, 'Rollback', current, self.root)
        saved.chmod(0o600)
        saved.write_bytes(b'# foreign recovery\n')
        with self.assertRaises(ValueError):
            launcher.select(doc, 'Rollback', current, self.root)

    def test_incomplete_snapshot_is_absent_only_while_resources_match_original(self):
        self.host().directory.mkdir(parents=True)
        self.write('/' + (self.host().directory / 'recovery.py').relative_to(self.root).as_posix(), b'fixture pinned program')
        self.assertEqual(self.host().status()['Phase'], 'Absent')
        self.write(self.protocol, address.compact(self.resource['After']).encode())
        with self.assertRaises(ValueError):
            self.host().status()

    def test_stage_replay_and_skip_are_rejected(self):
        self.host().prepare()
        with self.assertRaises(ValueError):
            self.host().prepare()
        with self.assertRaises(ValueError):
            self.host().apply('Apply')
        self.host().apply('Bridge')
        with self.assertRaises(ValueError):
            self.host().apply('Bridge')

    def test_external_edit_blocks_apply_and_restore(self):
        self.host().prepare()
        path = self.root / self.protocol.lstrip('/')
        path.write_text('{"external":true}')
        self.assertFalse(self.host().status()['Consistent'])
        with self.assertRaises(ValueError):
            self.host().apply('Bridge')
        with self.assertRaises(ValueError):
            self.host().rollback()
        self.assertEqual(path.read_text(), '{"external":true}')

    def test_restart_failure_keeps_intent_and_can_restore(self):
        self.host().prepare()
        self.host().apply('Bridge')
        self.run.fail_start = True
        with self.assertRaises(ValueError):
            self.host().apply('Apply')
        self.assertEqual(self.host().status()['Phase'], 'ApplyIntent')
        self.assertEqual(self.host().rollback()['Phase'], 'RolledBack')

    def test_links_metadata_and_unknown_journals_are_rejected(self):
        path = self.root / self.protocol.lstrip('/')
        original = path.read_bytes()
        self.host().prepare()
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.host().rollback()
        path.chmod(0o600)
        external = self.write('/external', original)
        path.unlink()
        path.symlink_to(external)
        with self.assertRaises(ValueError):
            self.host().rollback()
        path.unlink()
        self.write(self.protocol, original)
        journal = json.loads(self.host().file.read_text())
        journal['Version'] = 999
        self.host().save(journal)
        with self.assertRaises(ValueError):
            self.host().status()

    def test_forged_component_file_scope_is_rejected(self):
        self.host().prepare()
        j = self.host().load()
        for values in j['Components']['RealityEntry']['Files']:
            values['/etc/shadow'] = base64.b64encode(b'not owned').decode()
        self.host().save(j)
        self.write('/etc/shadow', b'not owned')
        with self.assertRaises(ValueError):
            self.host().rollback()
        self.assertEqual((self.root / 'etc/shadow').read_bytes(), b'not owned')

    def test_whitelist_file_and_runtime_change_together(self):
        content = '#!/usr/sbin/nft -f\n# Managed by May VPS Deploy.\ntable inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n ip saddr { 192.0.2.10, 192.0.2.199 } tcp dport 443 accept\n }\n}\n'
        self.write('/etc/nftables.conf', content.encode())
        self.run.tables['filter'] = content
        self.document['Resources'] = [{'Kind': 'Firewall', 'Component': 'Firewall', 'Before': {}, 'After': {}, 'ExpectedHash': 'Managed'}]
        self.host().prepare()
        self.host().apply('Bridge')
        bridge = (self.root / 'etc/nftables.conf').read_text()
        self.assertIn('192.0.2.10', bridge)
        self.assertIn('192.0.2.11', bridge)
        self.host().apply('Apply')
        self.host().apply('Finalize')
        final = (self.root / 'etc/nftables.conf').read_text()
        self.assertNotIn('192.0.2.10', final)
        self.assertIn('192.0.2.199', final)
        self.assertTrue(self.host().status()['Consistent'])
        self.host().rollback()
        self.assertEqual((self.root / 'etc/nftables.conf').read_text(), content)

    def test_forward_targets_and_acl_transition(self):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        config = {'Version': 1, 'Rules': [{'Id': 'b' * 32, 'Name': 'address forwarding', 'Enabled': True, 'ListenFamily': 'IPv4',
                  'ListenPort': port, 'TargetAddress': '192.0.2.10', 'TargetPort': 443, 'AllowedSources': ['192.0.2.10/32'], 'Validation': {'Type': 'Ssh'}}]}
        self.write('/lib/systemd/systemd-socket-proxyd', b'fixture proxy').chmod(0o755)
        self.write('/usr/sbin/nft', b'fixture nft').chmod(0o755)
        resource = {'Kind': 'TcpForwarding', 'Component': 'TcpForwarding', 'Before': config, 'After': address.rewrite(config, self.mapping), 'ExpectedHash': '0' * 64}
        adapter = address.Adapter(resource, self.root, self.run, self.mapping)
        native = adapter.host.normalize(config)
        for name, value in adapter.host.material(native, adapter.host.proxy()).items():
            adapter.host.write(name, value)
        self.run.acls[adapter.host.ACL_UNIT] = (adapter.host.TABLE, adapter.host.ACL)
        self.run.tables[adapter.host.TABLE] = adapter.host.path(adapter.host.ACL).read_text()
        resource['Before'] = native
        resource['After'] = address.rewrite(native, self.mapping)
        resource['ExpectedHash'] = adapter.host.read()['Hash']
        self.document['Resources'] = [resource]
        self.host().prepare()
        self.host().apply('Bridge')
        read_config = lambda: json.loads(adapter.host.path(adapter.host.CONFIG).read_text())['Rules'][0]
        self.assertEqual(read_config()['TargetAddress'], '192.0.2.10')
        self.assertEqual(read_config()['AllowedSources'], ['192.0.2.10/32', '192.0.2.11/32'])
        self.host().apply('Apply')
        self.assertEqual(read_config()['TargetAddress'], '192.0.2.11')
        self.assertEqual(read_config()['AllowedSources'], ['192.0.2.10/32', '192.0.2.11/32'])
        self.host().apply('Finalize')
        self.assertEqual(read_config()['AllowedSources'], ['192.0.2.11/32'])
        self.assertTrue(self.host().status()['Consistent'])
        self.assertEqual(self.host().rollback()['Phase'], 'RolledBack')

    def test_independent_inbound_refresh_preserves_other_identity_and_runtime(self):
        from test_inbound_host import payload, A, B
        resource = {'Kind': 'Inbounds', 'Component': 'Inbounds', 'ExpectedHash': '0' * 64}
        adapter = address.Adapter(resource, self.root, self.run, self.mapping)
        value = payload()
        for binding in value['Bindings']:
            if binding['Id'] != A:
                continue
            data = json.loads(base64.b64decode(value['Configurations'][A]))
            data['outbounds'][0]['inet4_bind_address'] = '192.0.2.10'
            raw = address.compact(data).encode()
            value['Configurations'][A] = base64.b64encode(raw).decode()
            binding['Sha256'] = address.sha(raw)
        for name, content in adapter.ns['material'](value).items():
            adapter.host.write(name, content)
        after = copy.deepcopy(value)
        for binding in after['Bindings']:
            if binding['Id'] != A:
                continue
            raw = address.compact(address.rewrite(json.loads(base64.b64decode(after['Configurations'][A])), self.mapping)).encode()
            after['Configurations'][A] = base64.b64encode(raw).decode()
            binding.update(Sha256=address.sha(raw), ClientSha256='f' * 64)
        resource.update(Before=value['Model'], After=after['Model'], AfterPayload=after)
        original_adapter = address.Adapter
        class FixtureAdapter(original_adapter):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                if self.kind == 'Inbounds':
                    self.host.verify_core = lambda core: self.ns['core_spec'](core)
                    self.host.wait_ready = lambda binding: None
        with patch.object(address, 'Adapter', FixtureAdapter):
            resource['ExpectedHash'] = FixtureAdapter(resource, self.root, self.run, self.mapping).read()['Hash']
            self.document['Resources'] = [resource]
            unrelated = adapter.host.path(adapter.ns['config_path'](B)).read_bytes()
            self.host().prepare()
            self.host().apply('Bridge')
            self.host().apply('Apply')
            self.assertEqual(json.loads(adapter.host.path(adapter.ns['config_path'](A)).read_text())['outbounds'][0]['inet4_bind_address'], '192.0.2.11')
            self.host().apply('Finalize')
            self.assertTrue(self.host().status()['Consistent'])
            self.run.commands.clear()
            self.assertTrue(self.host().rollback()['Consistent'])
            self.assertFalse(any(c[:2] == ['systemctl', 'stop'] and c[-1] == adapter.ns['unit_name'](B) for c in self.run.commands))
            self.assertEqual(adapter.host.path(adapter.ns['config_path'](B)).read_bytes(), unrelated)


if __name__ == '__main__':
    unittest.main(verbosity=2)
