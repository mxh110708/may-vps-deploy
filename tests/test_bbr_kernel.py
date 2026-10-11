"""Kernel lifecycle refusal contracts; real reboot proof remains a separate test."""
import base64
import copy
import json
import pathlib
import tempfile
import sys
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMP_ROOT = ROOT/'.test-output/kernel-python'
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(TEMP_ROOT)
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *args: None))
CODE = (ROOT/'scripts/bbr-runtime.py').read_text(encoding='utf8')+'\n'+(ROOT/'scripts/kernel-engine.py').read_text(encoding='utf8')
NS = {'__name__': 'kernel_contract'}
exec(compile(CODE, 'kernel_contract', 'exec'), NS)


class KernelContract(unittest.TestCase):
    def probe(self, data, module=''):
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream
        stream.accept.return_value = (stream, ('127.0.0.1', 1))
        stream.getsockopt.return_value = data
        with mock.patch.object(NS['socket'], 'TCP_CONGESTION', 13, create=True), mock.patch.object(NS['socket'], 'socket', return_value=stream), mock.patch.object(NS['Path'], 'read_text', return_value=module):
            return NS['bbr_runtime']()

    def test_running_builtin_v3_requires_version_at_exact_offset(self):
        data = bytearray(52); data[39] = 3
        self.assertEqual(self.probe(bytes(data))['BbrVersionEvidence'], 'TcpCcInfo')
        data[39] = 0; data[38] = 3
        self.assertEqual(self.probe(bytes(data))['BbrVersion'], 'VersionUnverified')

    def test_legacy_shape_or_conflict_is_not_v3(self):
        self.assertEqual(self.probe(b'\x03'*20)['BbrVersion'], 'VersionUnverified')
        data = bytearray(52); data[39] = 3
        self.assertEqual(self.probe(bytes(data), '1')['BbrVersionEvidence'], 'ConflictingRuntime')
        self.assertEqual(self.probe(b'', '1')['BbrVersion'], 'v1')

    def test_catalog_refuses_untrusted_source_arch_and_expired_snapshot(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        NS['catalog_validate'](cat)
        for field, value in [('Repository', 'http://example.com/'), ('Kernel', '6.18.55-x64v3-xanmod1'), ('Architecture', 'arm64'), ('Filename', '../../kernel.deb'), ('SignedAt', '2025-01-01T00:00:00Z')]:
            bad = copy.deepcopy(cat); bad[field] = value
            with self.assertRaises(RuntimeError): NS['catalog_validate'](bad)

    def test_one_shot_entry_refuses_ambiguous_boot_layout(self):
        text = "submenu 'Debian' $menuentry_id_option 'gnulinux-advanced-identity' {\n\tmenuentry 'Debian kernel' $menuentry_id_option 'gnulinux-test-advanced-identity' {\n"
        with mock.patch.object(NS['Path'], 'read_text', return_value=text):
            self.assertEqual(NS['entry']('test'), 'gnulinux-advanced-identity>gnulinux-test-advanced-identity')
        with mock.patch.object(NS['Path'], 'read_text', return_value=text+text):
            with self.assertRaises(RuntimeError): NS['entry']('test')

    def test_latest_reads_only_signed_compatible_lts_and_pins_its_hash(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        data = {name: (ROOT/'assets/kernel'/name).read_bytes() for name in ('xanmod.gpg', 'InRelease', 'Packages.gz')}
        entries = [dict(l.split(': ', 1) for l in p.splitlines() if ': ' in l and not l.startswith(' ')) for p in NS['gzip'].decompress(data['Packages.gz']).decode().split('\n\n')]
        calls = []
        def download(request, timeout):
            calls.append(request.full_url)
            response = mock.MagicMock(); response.__enter__.return_value = response
            response.geturl.return_value = request.full_url; response.read.return_value = data[request.full_url.rsplit('/', 1)[1]]
            return response
        env = {'VPS_PARAM_CATALOG': json.dumps(cat), 'VPS_PARAM_KEY': base64.b64encode(data['xanmod.gpg']).decode()}
        with mock.patch.dict(NS['os'].environ, env), mock.patch.object(NS['Path'], 'read_text', return_value='ID=debian\nVERSION_ID="12"'), mock.patch.object(NS['urllib'].request, 'urlopen', side_effect=download), mock.patch.dict(NS, {'signed_index': lambda *args: (entries, cat['SignedAt'], 'bookworm'), 'run': mock.Mock(side_effect=AssertionError('persistent system mutation'))}):
            result = NS['latest_candidate']()
        self.assertEqual(result['Catalog']['Kernel'], cat['Kernel'])
        self.assertEqual(result['Catalog']['Sha256'], cat['Sha256'])
        self.assertEqual(result['Catalog']['Selection'], 'Latest')
        self.assertTrue(all(url.startswith('https://deb.xanmod.org/dists/bookworm/') for url in calls))
        self.assertEqual(len(calls), 2)

    def test_signed_date_cannot_be_forged_to_refresh_an_old_index(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); identity = 'a'*32; target = root/identity; target.mkdir()
            for name in ('xanmod.gpg', 'InRelease', 'Packages.gz'): (target/name).write_bytes((ROOT/'assets/kernel'/name).read_bytes())
            cat['SignedAt'] = NS['datetime'].datetime.now(NS['datetime'].timezone.utc).isoformat()
            with mock.patch.dict(NS, {'BASE': root, 'run': lambda *args: '[GNUPG:] VALIDSIG '+cat['SigningFingerprint']+' '}):
                with self.assertRaisesRegex(RuntimeError, 'Signed date'): NS['sources_verify']({'Id': identity, 'Catalog': cat})

    def test_latest_refuses_an_arbitrary_signing_key(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        env = {'VPS_PARAM_CATALOG': json.dumps(cat), 'VPS_PARAM_KEY': base64.b64encode(b'unknown key').decode()}
        with mock.patch.dict(NS['os'].environ, env), mock.patch.object(NS['urllib'].request, 'urlopen', side_effect=AssertionError('network call')):
            with self.assertRaisesRegex(RuntimeError, 'trust anchor'): NS['latest_candidate']()

    def test_absent_remote_record_can_end_preparation_without_replaying_it(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); identity = 'a'*32; original_stat = NS['Path'].stat
            def root_owner(path, *args, **kwargs):
                return types.SimpleNamespace(st_uid=0, st_mode=0o40700) if path == root else original_stat(path, *args, **kwargs)
            env = {'VPS_PARAM_CATALOG': json.dumps(cat)}
            with mock.patch.dict(NS, {'BASE': root, 'runtime': lambda: {'Kernel': 'stock'}, 'run': mock.Mock(side_effect=AssertionError('mutation'))}), mock.patch.object(NS['os'], 'geteuid', return_value=0, create=True), mock.patch.object(NS['Path'], 'stat', root_owner), mock.patch.object(NS['sys'], 'argv', ['engine', 'Status', identity]), mock.patch.dict(NS['os'].environ, env), mock.patch('builtins.print') as output:
                NS['main']()
            result = json.loads(base64.b64decode(output.call_args.args[0].split('=', 1)[1]))
            self.assertEqual(result['Phase'], 'Aborted')
            self.assertTrue(result['NoMutationConfirmed'])
            self.assertFalse((root/identity).exists())

    def test_install_replay_is_refused_before_commands(self):
        for phase, count in [('Installing', 1), ('Prepared', 0), ('Committed', 1)]:
            with mock.patch.dict(NS, {'run': mock.Mock(side_effect=AssertionError('mutation'))}):
                with self.assertRaises(RuntimeError): NS['install_worker']({'Phase': phase, 'InstallInvocations': count})

    def test_commit_requires_real_v3_and_old_services(self):
        for phase, version, healthy in [('Prepared', 'v3', True), ('Booted', 'VersionUnverified', True), ('Booted', 'v3', False)]:
            s = {'Phase': phase, 'Runtime': {'BbrVersion': version}, 'ServicesHealthy': healthy}
            with mock.patch.dict(NS, {'status': lambda _: s, 'set_default': mock.Mock(side_effect=AssertionError('mutation'))}):
                with self.assertRaises(RuntimeError): NS['confirm'](s)

    def test_linked_kernel_path_refused(self):
        fake = mock.Mock(); fake.parents = []; fake.lstat.return_value = types.SimpleNamespace(st_mode=0o120777, st_nlink=1)
        with self.assertRaises(RuntimeError): NS['regular'](fake)

    def test_boot_drift_refused_before_write(self):
        s = {'BootConfigFingerprint': 'a', 'OwnedDefaultSha256': 'b', 'SavedEntry': 'old'}
        with mock.patch.dict(NS, {'config_fingerprint': lambda: 'changed', 'digest': lambda _: 'b'}):
            with self.assertRaises(RuntimeError): NS['owned_boot'](s)
        with mock.patch.dict(NS, {'config_fingerprint': lambda: 'a', 'digest': lambda _: 'b', 'boot_environment': lambda: {'saved_entry': 'foreign'}}):
            with self.assertRaises(RuntimeError): NS['owned_boot'](s)


if __name__ == '__main__':
    unittest.main()
