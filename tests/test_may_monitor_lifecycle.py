"""Disposable filesystem + inert systemd/account runner; never host services."""
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


if sys.platform != 'linux':
    raise unittest.SkipTest('May Monitor host lifecycle requires Linux; run in the isolated WSL test entry.')
if os.geteuid() != 0:
    raise SystemExit('Run this isolated temporary-filesystem test as root inside a disposable Linux environment; all account/service commands are fake.')
spec = importlib.util.spec_from_file_location('may_lifecycle', Path(__file__).parents[1] / 'scripts/may-monitor-lifecycle.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeHost(module.Host):
    def __init__(self, root):
        self.accounts, self.groups, self.services = {}, {}, {}
        self.calls, self.version = [], '0.1.0-rc.2'
        self.agent_uuid, self.server_uuid = str(uuid.uuid4()), str(uuid.uuid4())
        super().__init__(root, self.execute)

    def account(self, name):
        if name not in self.accounts:
            raise KeyError(name)
        return self.accounts[name]

    def group(self, name):
        if name not in self.groups:
            raise KeyError(name)
        return self.groups[name]

    def verify_process(self, unit, binary):
        if not self.services.get(unit, {}).get('active') or not self.path(binary).is_file():
            raise ValueError('Missing inert process.')

    def execute(self, args, **kwargs):
        self.calls.append(tuple(args)); code, text = 0, ''
        if args[0] == 'systemctl':
            operation, unit = args[1], args[-1]
            state = self.services.setdefault(unit, {'active': False, 'enabled': False})
            if operation == 'cat':
                code = 0 if self.path('/etc/systemd/system/' + unit).exists() else 1
            elif operation == 'is-active': code = 0 if state['active'] else 3
            elif operation == 'is-enabled': code = 0 if state['enabled'] else 1
            elif operation in ('start', 'stop'): state['active'] = operation == 'start'
            elif operation in ('enable', 'disable'): state['enabled'] = operation == 'enable'
        elif args[0] == 'groupadd':
            self.groups[args[-1]] = SimpleNamespace(gr_gid=1900 + len(self.groups), gr_mem=[])
        elif args[0] == 'useradd':
            name = args[-1]; gid = self.groups[name].gr_gid
            self.accounts[name] = SimpleNamespace(pw_uid=gid, pw_gid=gid, pw_dir='/var/lib/' + name, pw_shell='/usr/sbin/nologin')
        elif args[0] == 'userdel': del self.accounts[args[-1]]
        elif args[0] == 'groupdel': del self.groups[args[-1]]
        elif args[-1] == '--version': text = 'may-monitor-server version ' + self.version
        return subprocess.CompletedProcess(args, code, text, '')


class FixtureLifecycle(module.Lifecycle):
    def initialize(self, configuration, secrets):
        pass

    def verify_agent_credential(self, configuration, secrets):
        configuration['ClientUUID'] = self.host.agent_uuid
        configuration['ServerInstanceId'] = self.host.server_uuid


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='codex-may-monitor-')
        self.host = FakeHost(Path(self.temp.name))
        self.host.path('/etc').mkdir(); self.host.path('/etc/machine-id').write_text('synthetic-machine')
        self.host.path('/var/lib/may-vps-deploy').mkdir(parents=True)
        self.life = FixtureLifecycle(self.host, 'Server')
        self.patches = [patch.object(module.pwd, 'getpwnam', self.host.account), patch.object(module.grp, 'getgrnam', self.host.group), patch.object(module.time, 'sleep', lambda _: None)]
        for item in self.patches: item.start()
        self.source = Path(spec.origin).read_text()
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0)); self.port = port.getsockname()[1]
        self.configuration = {'Port': self.port, 'Username': 'admin'}
        self.secrets = {'SetupToken': 'synthetic-operator-initialization-token-123', 'AdminPassword': 'Synthetic-Password1'}

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def begin(self):
        task = uuid.uuid4().hex
        result = self.life.begin(task, self.life.inspect()['Hash'], self.source)
        self.assertEqual(result['Phase'], 'Armed')
        return task, self.life.backup_path(task)

    def asset(self, backup, selected='0.1.0-rc.2', role='Server'):
        artifact = backup / 'artifact'
        payload = b'synthetic owned binary ' + selected.encode()
        if role == 'Server':
            with tarfile.open(artifact, 'w:gz') as archive:
                entry = tarfile.TarInfo('may-monitor-server'); entry.size = len(payload)
                archive.addfile(entry, io.BytesIO(payload))
            name = 'may-monitor-server-linux-amd64.tar.gz'
        else:
            artifact.write_bytes(payload); name = 'may-monitor-agent-linux-amd64'
        artifact.chmod(0o600)
        self.host.version = selected
        return {'Version': selected, 'Bytes': artifact.stat().st_size, 'Sha256': module.digest(artifact), 'Name': name, 'Url': 'https://github.com/mxh110708/may-monitor-' + role.lower() + '/releases/download/v' + selected + '/' + name}

    def install(self, selected='0.1.0-rc.2'):
        task, backup = self.begin(); asset = self.asset(backup, selected)
        result = self.life.apply(task, 'Install', dict(self.configuration), self.secrets, asset)
        self.assertTrue(result['Installed']); self.assertTrue(result['Active'])
        self.life.finish(task)
        return task

    def test_empty_check_is_read_only(self):
        before = list(Path(self.temp.name).rglob('*'))
        self.assertEqual(self.life.inspect()['Hash'], 'Absent')
        self.assertEqual(before, list(Path(self.temp.name).rglob('*')))

    def test_unmanaged_resources_and_accounts_refused(self):
        self.host.path(self.life.binary).parent.mkdir(parents=True)
        self.host.path(self.life.binary).write_text('operator-owned')
        with self.assertRaises(ValueError): self.life.inspect()
        self.host.path(self.life.binary).unlink()
        self.host.accounts[self.life.leaf] = SimpleNamespace()
        with self.assertRaises(ValueError): self.life.inspect()

    def test_unknown_role_and_versions_refused(self):
        with self.assertRaises(ValueError): FixtureLifecycle(self.host, 'KomariController')
        for value in ('latest', 'main', '1.0', '1.0.0-foo', '../escape'):
            with self.assertRaises(ValueError): module.version(value)
        self.assertLess(module.version('0.1.0-rc.1'), module.version('0.1.0-rc.2'))
        self.assertLess(module.version('0.1.0-rc.2'), module.version('0.1.0'))

    def test_install_upgrade_and_legacy_preservation(self):
        legacy = self.host.path('/etc/komari/untouched'); legacy.parent.mkdir(parents=True); legacy.write_bytes(b'legacy')
        self.install('0.1.0-rc.1')
        data = self.host.path(self.life.data) / 'state'; data.write_bytes(b'synthetic-current-data')
        task, backup = self.begin(); asset = self.asset(backup)
        result = self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, asset)
        self.assertEqual(result['Version'], '0.1.0-rc.2'); self.life.finish(task)
        self.assertEqual(data.read_bytes(), b'synthetic-current-data'); self.assertEqual(legacy.read_bytes(), b'legacy')
        self.assertTrue(all('komari.service' not in args for args in self.host.calls))

    def test_failed_download_keeps_current_data(self):
        self.install(); task, backup = self.begin(); data = self.host.path(self.life.data) / 'fresh'; data.write_bytes(b'new-after-snapshot')
        asset = self.asset(backup); asset['Sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, asset)
        self.assertEqual(self.life.finish(task, True)['Phase'], 'RolledBack')
        self.assertEqual(data.read_bytes(), b'new-after-snapshot')

    def test_backup_does_not_rewrite_state(self):
        self.install(); before = self.life.inspect()['Hash']; task, _ = self.begin()
        self.assertEqual(self.life.finish(task)['State']['Hash'], before)

    def test_cancelled_install_restores_absence(self):
        task, backup = self.begin(); asset = self.asset(backup)
        self.life.apply(task, 'Install', dict(self.configuration), self.secrets, asset)
        self.assertEqual(self.life.finish(task, True)['Phase'], 'RolledBack')
        self.assertEqual(self.life.inspect()['Hash'], 'Absent'); self.assertNotIn(self.life.leaf, self.host.accounts)

    def test_disabled_upgrade_preserves_disabled_state(self):
        self.install('0.1.0-rc.1')
        task, _ = self.begin(); self.life.apply(task, 'Disable', {}, {}); self.life.finish(task)
        task, backup = self.begin(); asset = self.asset(backup)
        result = self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, asset); self.life.finish(task)
        self.assertFalse(result['Active']); self.assertFalse(result['Enabled'])

    def test_selected_restore_is_scope_limited(self):
        self.install('0.1.0-rc.1')
        data = self.host.path(self.life.data) / 'state'; data.write_bytes(b'before-upgrade')
        old_task, backup = self.begin(); old_hash = self.life.transaction(old_task)[1]['BackupSha256']
        self.life.apply(old_task, 'Upgrade', dict(self.configuration), self.secrets, self.asset(backup)); self.life.finish(old_task)
        data.write_bytes(b'after-upgrade')
        task, _ = self.begin()
        restored = self.life.apply(task, 'Restore', {'RestoreTask': old_task, 'RestoreSha256': old_hash}, {})
        self.life.finish(task)
        self.assertEqual(restored['Version'], '0.1.0-rc.1'); self.assertEqual(data.read_bytes(), b'before-upgrade')

    def test_drift_and_readable_credentials_refused(self):
        self.install(); path = self.host.path(self.life.config + '/runtime.env')
        path.chmod(0o644)
        with self.assertRaises(ValueError): self.life.inspect()
        path.chmod(0o600); path.write_bytes(b'external edit')
        with self.assertRaises(ValueError): self.life.inspect()

    def test_active_service_must_run_owned_binary(self):
        self.install()
        with patch.object(self.host, 'verify_process', side_effect=ValueError('synthetic different process')):
            with self.assertRaises(ValueError): self.life.inspect()

    def test_dropin_added_during_transaction_blocks_recovery(self):
        self.install(); task, _ = self.begin(); self.life.apply(task, 'Disable', {}, {})
        override = self.host.path('/etc/systemd/system/' + self.life.unit + '.d'); override.mkdir()
        with self.assertRaises(ValueError): self.life.finish(task, True)
        self.assertTrue(override.is_dir()); override.rmdir(); self.life.finish(task, True)

    def test_recovery_does_not_stop_unowned_running_process(self):
        self.install('0.1.0-rc.1'); task, backup = self.begin()
        self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, self.asset(backup))
        before_calls = len(self.host.calls)
        with patch.object(self.host, 'verify_process', side_effect=ValueError('synthetic different process')):
            with self.assertRaises(ValueError): self.life.finish(task, True)
        self.assertNotIn(('systemctl', 'stop', self.life.unit), self.host.calls[before_calls:])

    def test_external_edit_blocks_rollback(self):
        self.install('0.1.0-rc.1'); task, backup = self.begin()
        self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, self.asset(backup))
        self.host.path(self.life.binary).write_bytes(b'operator edit')
        with self.assertRaises(ValueError): self.life.finish(task, True)
        self.assertEqual(self.host.path(self.life.binary).read_bytes(), b'operator edit')

    def test_external_permissions_and_extra_file_block_recovery(self):
        self.install(); task, _ = self.begin(); self.life.apply(task, 'Disable', {}, {})
        path = self.host.path(self.life.config + '/runtime.env'); path.chmod(0o644)
        with self.assertRaises(ValueError): self.life.finish(task, True)
        self.assertEqual(stat_mode(path), 0o644)
        path.chmod(0o600); extra = self.host.path(self.life.config + '/operator-note'); extra.write_text('retained')
        with self.assertRaises(ValueError): self.life.finish(task, True)
        self.assertEqual(extra.read_text(), 'retained'); extra.unlink(); self.life.finish(task, True)

    def test_account_creation_acknowledgement_unknown_is_not_deleted(self):
        task, backup = self.begin(); record = self.life.transaction(task)[1]
        record['Phase'] = 'Applying'; record['CreatingAccount'] = True; self.life.save_transaction(backup, record)
        self.host.groups[self.life.leaf] = SimpleNamespace(gr_gid=1900, gr_mem=[])
        with self.assertRaises(ValueError): self.life.finish(task, True)
        self.assertIn(self.life.leaf, self.host.groups); self.assertTrue(self.host.path(module.OWNER).exists())

    def test_live_listener_collision_is_refused_and_scope_restored(self):
        task, backup = self.begin(); asset = self.asset(backup)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', self.port)); listener.listen(1)
            with self.assertRaises(OSError): self.life.apply(task, 'Install', dict(self.configuration), self.secrets, asset)
        self.life.finish(task, True); self.assertEqual(self.life.inspect()['Hash'], 'Absent')

    def test_archive_duplicates_refused_before_service_files_change(self):
        task, backup = self.begin(); asset = self.asset(backup)
        with tarfile.open(backup / 'artifact', 'w:gz') as archive:
            for _ in range(2):
                entry = tarfile.TarInfo('may-monitor-server'); entry.size = 3; archive.addfile(entry, io.BytesIO(b'bad'))
        asset['Sha256'] = module.digest(backup / 'artifact'); asset['Bytes'] = (backup / 'artifact').stat().st_size
        with self.assertRaises(ValueError): self.life.apply(task, 'Install', dict(self.configuration), self.secrets, asset)
        self.assertFalse((backup / 'candidate-binary').exists())
        self.life.finish(task, True); self.assertEqual(self.life.inspect()['Hash'], 'Absent')

    def test_published_server_layout_with_versioned_release_notes(self):
        task, backup = self.begin(); asset = self.asset(backup, '0.1.0-rc.9')
        payload = b'synthetic owned binary 0.1.0-rc.9'
        with tarfile.open(backup / 'artifact', 'w:gz') as archive:
            for name in ('may-monitor-server', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'RELEASE-0.1.0-rc.9.md'):
                raw = payload if name == 'may-monitor-server' else b'reviewed release metadata'
                entry = tarfile.TarInfo(name); entry.size = len(raw); archive.addfile(entry, io.BytesIO(raw))
        asset['Sha256'] = module.digest(backup / 'artifact'); asset['Bytes'] = (backup / 'artifact').stat().st_size
        result = self.life.apply(task, 'Install', dict(self.configuration), self.secrets, asset)
        self.assertEqual(result['Version'], '0.1.0-rc.9'); self.assertTrue(result['Active'])
        self.life.finish(task)

    def test_missing_upgrade_credential_does_not_stop_original_service(self):
        self.install(); task, backup = self.begin(); asset = self.asset(backup, '0.1.0-rc.9')
        before = self.life.inspect(); calls = len(self.host.calls)
        with self.assertRaisesRegex(ValueError, 'Missing private initialization token'):
            self.life.apply(task, 'Upgrade', dict(before['Configuration']), {}, asset)
        self.assertEqual(self.life.inspect()['Hash'], before['Hash'])
        self.assertNotIn(('systemctl', 'stop', self.life.unit), self.host.calls[calls:])
        self.assertEqual(self.life.transaction(task)[1]['Phase'], 'Armed')
        self.life.finish(task, True)

    def test_missing_agent_upgrade_credential_does_not_stop_original_service(self):
        self.life = FixtureLifecycle(self.host, 'Agent')
        task, backup = self.begin(); asset = self.asset(backup, role='Agent')
        self.life.apply(task, 'Install', {'Endpoint': 'https://monitor.example/'}, {'AgentToken': 'synthetic-agent-token'}, asset); self.life.finish(task)
        task, backup = self.begin(); before = self.life.inspect(); asset = self.asset(backup, '0.1.0-rc.4', role='Agent'); calls = len(self.host.calls)
        with self.assertRaisesRegex(ValueError, 'Invalid May agent credential'):
            self.life.apply(task, 'Upgrade', dict(before['Configuration']), {}, asset)
        self.assertEqual(self.life.inspect()['Hash'], before['Hash'])
        self.assertNotIn(('systemctl', 'stop', self.life.unit), self.host.calls[calls:])
        self.life.finish(task, True)

    def test_unwritten_upgrade_recovery_retains_metrics_since_snapshot(self):
        self.install(); task, _ = self.begin(); before = self.life.inspect()
        metric = self.host.path(self.life.data) / 'new-telemetry'; metric.write_bytes(b'created after snapshot')
        backup, record = self.life.transaction(task); record['Phase'] = 'Applying'; record['Operation'] = 'Upgrade'; self.life.save_transaction(backup, record)
        self.life.system('stop', self.life.unit)
        result = self.life.finish(task, True)
        self.assertEqual(result['Phase'], 'RolledBack'); self.assertEqual(result['State']['Hash'], before['Hash'])
        self.assertEqual(metric.read_bytes(), b'created after snapshot')

    def test_archive_unknown_notes_paths_and_links_refused_before_extraction(self):
        for name, link in [('RELEASE-0.1.0-rc.1.md', False), ('docs/RELEASE-0.1.0-rc.9.md', False), ('../CHANGELOG.md', False), ('CHANGELOG.md', True)]:
            with self.subTest(name=name, link=link):
                task, backup = self.begin(); asset = self.asset(backup, '0.1.0-rc.9')
                with tarfile.open(backup / 'artifact', 'w:gz') as archive:
                    entry = tarfile.TarInfo('may-monitor-server'); entry.size = 3; archive.addfile(entry, io.BytesIO(b'bin'))
                    entry = tarfile.TarInfo(name)
                    if link:
                        entry.type = tarfile.SYMTYPE; entry.linkname = 'may-monitor-server'; archive.addfile(entry)
                    else:
                        entry.size = 3; archive.addfile(entry, io.BytesIO(b'doc'))
                asset['Sha256'] = module.digest(backup / 'artifact'); asset['Bytes'] = (backup / 'artifact').stat().st_size
                with self.assertRaises(ValueError): self.life.asset(backup, asset)
                self.assertFalse((backup / 'candidate-binary').exists())
                self.assertFalse(self.host.path(self.life.binary).exists())
                self.life.finish(task, True)

    def test_snapshot_scope_and_identity_rejected(self):
        self.install(); task, backup = self.begin()
        record = self.host.read_json(backup / 'transaction.json'); record['MachineId'] = 'another-machine'
        self.host.atomic(backup / 'transaction.json', module.canonical(record))
        with self.assertRaises(ValueError): self.life.finish(task, True)

    def test_rollback_is_idempotent_and_does_not_release_next_owner(self):
        self.install(); first, _ = self.begin(); self.life.finish(first, True)
        second, _ = self.begin(); owner = self.host.path(module.OWNER).read_bytes()
        self.assertEqual(self.life.finish(first, True)['Phase'], 'RolledBack')
        self.assertEqual(self.host.path(module.OWNER).read_bytes(), owner)
        self.life.finish(second, True)

    def test_remove_retains_private_data_for_gradual_migration(self):
        self.install(); data = self.host.path(self.life.data) / 'state'; data.write_bytes(b'retained')
        task, _ = self.begin(); result = self.life.apply(task, 'Remove', {}, {}); self.life.finish(task)
        self.assertFalse(result['Installed']); self.assertEqual(data.read_bytes(), b'retained')
        self.assertIn(self.life.leaf, self.host.accounts)

    def test_agent_config_and_remote_capabilities(self):
        self.life = FixtureLifecycle(self.host, 'Agent')
        task, backup = self.begin(); asset = self.asset(backup, role='Agent')
        result = self.life.apply(task, 'Install', {'Endpoint': 'https://monitor.example/'}, {'AgentToken': 'synthetic-agent-token'}, asset)
        self.life.finish(task)
        config = json.loads(self.host.path(self.life.config + '/config.json').read_text())
        self.assertTrue(config['disable_auto_update']); self.assertTrue(config['disable_web_ssh']); self.assertFalse(config['ignore_unsafe_cert'])
        self.assertNotIn('token', result['Configuration']); self.assertEqual(stat_mode(self.host.path(self.life.config + '/config.json')), 0o640)

    def test_reviewed_static_theme_disable_upgrade_and_restore(self):
        import hashlib
        self.install()
        members = {'komari-theme.json': b'{"short":"GlassmorphismEnhanced"}', 'dist/index.html': b'<html>reviewed fixture</html>'}
        lock = module.canonical({'schema': 1, 'short': 'GlassmorphismEnhanced', 'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}})
        pin = hashlib.sha256(lock).hexdigest()
        root = self.host.path('/usr/local/share/may-monitor/themes/' + pin)
        root.mkdir(parents=True, mode=0o755)
        for name, raw in {**members, 'may-theme.lock.json': lock}.items():
            p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw); p.chmod(0o644)
        task, _ = self.begin()
        selected = self.life.apply(task, 'ConfigureTheme', {'ThemeLockSha256': pin}, {})
        self.life.finish(task)
        self.assertEqual(selected['Configuration']['ThemeLockSha256'], pin)
        self.assertNotIn('MAY_MONITOR_ALLOW_EXTENSIONS', self.host.path(self.life.config+'/runtime.env').read_text())
        task, backup = self.begin()
        self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, self.asset(backup, '0.1.0-rc.3')); self.life.finish(task)
        self.assertIn('MAY_MONITOR_REVIEWED_THEME='+pin, self.host.path(self.life.config+'/runtime.env').read_text())
        task, _ = self.begin(); self.life.apply(task, 'DisableTheme', {}, {}); self.life.finish(task, True)
        self.assertEqual(self.life.inspect()['Configuration']['ThemeLockSha256'], pin)
        (root/'dist/index.html').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.life.inspect()

    def test_server_identity_is_stable_across_upgrade_and_rollback(self):
        self.install('0.1.0-rc.2'); before = self.life.inspect()['Configuration']['InstanceId']
        self.assertEqual(str(uuid.UUID(before)), before)
        self.assertIn('MAY_MONITOR_INSTANCE_ID=' + before, self.host.path(self.life.config + '/runtime.env').read_text())
        task, backup = self.begin(); self.life.apply(task, 'Upgrade', dict(self.configuration), self.secrets, self.asset(backup, '0.1.0-rc.3'))
        self.assertEqual(self.life.inspect()['Configuration']['InstanceId'], before)
        self.life.finish(task, True); self.assertEqual(self.life.inspect()['Configuration']['InstanceId'], before)

    def test_agent_identity_check_is_read_only_and_does_not_return_token(self):
        self.life = FixtureLifecycle(self.host, 'Agent'); task, backup = self.begin()
        self.life.apply(task, 'Install', {'Endpoint': 'https://monitor.example/'}, {'AgentToken': 'synthetic-agent-token'}, self.asset(backup, role='Agent')); self.life.finish(task)
        hashes = {str(p): module.digest(p) for p in self.host.root.rglob('*') if p.is_file()}
        confirmed = self.life.verify_agent(self.life.inspect()['Hash'])
        self.assertEqual(confirmed['ClientUUID'], self.host.agent_uuid); self.assertEqual(confirmed['ServerInstanceId'], self.host.server_uuid)
        self.assertNotIn('synthetic-agent-token', json.dumps(confirmed))
        self.assertEqual(hashes, {str(p): module.digest(p) for p in self.host.root.rglob('*') if p.is_file()})


def stat_mode(path):
    return path.stat().st_mode & 0o777


if __name__ == '__main__':
    unittest.main()
