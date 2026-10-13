"""Kernel lifecycle refusal contracts; real reboot proof remains a separate test."""
import base64
import copy
import json
import hashlib
import io
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

    def test_debian13_kernel_plus_is_accepted_but_shell_characters_are_refused(self):
        kernel = '6.12.38+deb13-amd64'
        text = "submenu 'Debian' $menuentry_id_option 'gnulinux-advanced-identity' {\n\tmenuentry 'Debian kernel' $menuentry_id_option 'gnulinux-"+kernel+"-advanced-identity' {\n"
        with mock.patch.object(NS['Path'], 'read_text', return_value=text):
            self.assertEqual(NS['entry'](kernel), 'gnulinux-advanced-identity>gnulinux-'+kernel+'-advanced-identity')
        with mock.patch.object(NS['Path'], 'read_text', return_value=text.replace('identity', 'identity;bad')):
            with self.assertRaises(RuntimeError): NS['entry'](kernel)

    def test_verifier_selection_does_not_require_installing_gpgv_on_debian13(self):
        for tools, expected in [({'sqv'}, 'sqv'), ({'gpgv'}, 'gpgv'), ({'sqv', 'gpgv'}, 'gpgv')]:
            with mock.patch.object(NS['shutil'], 'which', side_effect=lambda tool: '/usr/bin/'+tool if tool in tools else None), mock.patch.dict(NS, {'run': lambda *args, **kwargs: '--cleartext --output'}):
                self.assertEqual(NS['signature_verifier'](), expected)
        with mock.patch.object(NS['shutil'], 'which', side_effect=lambda tool: '/usr/bin/sqv' if tool == 'sqv' else None), mock.patch.dict(NS, {'run': lambda *args, **kwargs: 'legacy detached signatures only'}):
            with self.assertRaisesRegex(NS['KernelFailure'], 'KernelVerifierMissing'): NS['signature_verifier']()
        with mock.patch.object(NS['shutil'], 'which', return_value=None):
            with self.assertRaisesRegex(NS['KernelFailure'], 'KernelVerifierMissing'): NS['signature_verifier']()

    def test_both_verifiers_require_pinned_fingerprint_and_authenticated_index(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in ('xanmod.gpg', 'InRelease', 'Packages.gz'): (root/name).write_bytes((ROOT/'assets/kernel'/name).read_bytes())
            for verifier in ('sqv', 'gpgv'):
                def verify(args, fingerprint=cat['SigningFingerprint']):
                    self.assertEqual(args[0], verifier)
                    self.assertNotIn('--policy-as-of', args)
                    NS['Path'](args[args.index('--output')+1]).write_text((root/'InRelease').read_text())
                    return fingerprint if verifier == 'sqv' else '[GNUPG:] VALIDSIG '+fingerprint+' '
                with mock.patch.dict(NS, {'signature_verifier': lambda: verifier, 'run': verify}):
                    entries, signed_at, _ = NS['signed_index'](root, cat['SigningFingerprint'])
                    self.assertTrue(any(p.get('Package') == cat['Package'] for p in entries))
                    self.assertEqual(signed_at, cat['SignedAt'])
                with mock.patch.dict(NS, {'signature_verifier': lambda: verifier, 'run': lambda args: verify(args, 'F'*40)}):
                    with self.assertRaisesRegex(NS['KernelFailure'], 'KernelSigningKeyMismatch'): NS['signed_index'](root, cat['SigningFingerprint'])
                failing = mock.Mock(side_effect=RuntimeError('synthetic-secret'))
                with mock.patch.dict(NS, {'signature_verifier': lambda: verifier, 'run': failing}):
                    with self.assertRaisesRegex(NS['KernelFailure'], 'KernelSignatureRejected') as error: NS['signed_index'](root, cat['SigningFingerprint'])
                    self.assertNotIn('synthetic-secret', str(error.exception))
                    self.assertEqual(failing.call_count, 1)
            (root/'Packages.gz').write_bytes(b'tampered index')
            with mock.patch.dict(NS, {'signature_verifier': lambda: 'gpgv', 'run': verify}):
                with self.assertRaisesRegex(NS['KernelFailure'], 'KernelIndexHashMismatch'): NS['signed_index'](root, cat['SigningFingerprint'])

    def test_real_available_verifiers_accept_signed_fixture_and_refuse_tampering(self):
        if sys.platform == 'win32': self.skipTest('VPS verification uses Linux tools; real cryptographic checks run in Debian CI and native VPS tests')
        tools = [tool for tool in ('sqv', 'gpgv') if NS['shutil'].which(tool)]
        if not tools: self.skipTest('OpenPGP verifier not installed on this runner; Debian CI and native VPS checks cover it')
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in ('xanmod.gpg', 'InRelease', 'Packages.gz'): (root/name).write_bytes((ROOT/'assets/kernel'/name).read_bytes())
            original = (root/'InRelease').read_bytes()
            self.assertIn(b'Codename: bookworm', original)
            for verifier in tools:
                with mock.patch.dict(NS, {'signature_verifier': lambda: verifier}):
                    (root/'InRelease').write_bytes(original)
                    _, signed_at, _ = NS['signed_index'](root, cat['SigningFingerprint'])
                    self.assertEqual(signed_at, cat['SignedAt'])
                    (root/'InRelease').write_bytes(original.replace(b'Codename: bookworm', b'Codename: tampered', 1))
                    with self.assertRaisesRegex(NS['KernelFailure'], 'KernelSignatureRejected'): NS['signed_index'](root, cat['SigningFingerprint'])

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
        with mock.patch.dict(NS['os'].environ, env), mock.patch.object(NS['Path'], 'read_text', return_value='ID=debian\nVERSION_ID="12"'), mock.patch.object(NS['urllib'].request, 'urlopen', side_effect=download), mock.patch.dict(NS, {'signature_verifier': lambda: 'gpgv', 'signed_index': lambda *args: (entries, cat['SignedAt'], 'bookworm'), 'run': mock.Mock(side_effect=AssertionError('persistent system mutation'))}):
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
            def verify(args):
                NS['Path'](args[args.index('--output')+1]).write_text((target/'InRelease').read_text())
                return '[GNUPG:] VALIDSIG '+cat['SigningFingerprint']+' '
            with mock.patch.dict(NS, {'BASE': root, 'signature_verifier': lambda: 'gpgv', 'run': verify}):
                with self.assertRaisesRegex(RuntimeError, 'Signed date'): NS['sources_verify']({'Id': identity, 'Catalog': cat})

    def test_latest_missing_verifier_and_network_errors_report_safe_distinct_causes(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        env = {'VPS_PARAM_CATALOG': json.dumps(cat), 'VPS_PARAM_KEY': base64.b64encode((ROOT/'assets/kernel/xanmod.gpg').read_bytes()).decode()}
        with mock.patch.dict(NS['os'].environ, env), mock.patch.object(NS['shutil'], 'which', return_value=None), mock.patch.object(NS['urllib'].request, 'urlopen', side_effect=AssertionError('network call')):
            with self.assertRaisesRegex(NS['KernelFailure'], 'KernelVerifierMissing'): NS['latest_candidate']()
        errors = [(NS['urllib'].error.HTTPError('synthetic-secret', 403, 'synthetic-secret', {}, None), 'KernelRepositoryForbidden'), (NS['urllib'].error.URLError(NS['socket'].gaierror('synthetic-secret')), 'KernelRepositoryDnsFailed'), (NS['urllib'].error.URLError(TimeoutError('synthetic-secret')), 'KernelRepositoryTimeout')]
        for failure, code in errors:
            with mock.patch.dict(NS['os'].environ, env), mock.patch.dict(NS, {'signature_verifier': lambda: 'sqv'}), mock.patch.object(NS['Path'], 'read_text', return_value='ID=debian\nVERSION_ID="13"'), mock.patch.object(NS['urllib'].request, 'urlopen', side_effect=failure):
                with self.assertRaisesRegex(NS['KernelFailure'], code) as error: NS['latest_candidate']()
                self.assertNotIn('synthetic-secret', str(error.exception))
                self.assertEqual(NS['failure_code'](error.exception, 'Latest'), code)
        self.assertEqual(NS['failure_code'](RuntimeError('synthetic-secret'), 'Latest'), 'KernelMetadataRejected')

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

    def test_previously_owned_installed_target_is_reused_without_package_mutation(self):
        for owned in (True, False):
            with self.subTest(owned=owned), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory); identity = 'a'*32; (root/identity).mkdir()
                package_bytes = b'synthetic-checked-package'; cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
                cat['Bytes'] = len(package_bytes); cat['Sha256'] = hashlib.sha256(package_bytes).hexdigest()
                state = {'Id': identity, 'Phase': 'Installing', 'InstallInvocations': 0, 'Catalog': cat, 'PreviousTransaction': 'b'*32, 'OldKernel': 'stock', 'OldImageSha256': 'image'}
                prior = {'Id': 'b'*32, 'Phase': 'RolledBack', 'Catalog': cat, 'NewImageSha256': 'image', 'NewInitrdSha256': 'initrd'} if owned else {'Id': 'b'*32, 'Phase': 'Aborted', 'Catalog': {'Kernel': 'foreign'}}
                calls = []
                def run(args, *unused, **kwargs):
                    calls.append(args)
                    if args[0] == 'dpkg-deb': return 'Package: '+cat['Package']+'\nVersion: '+cat['PackageVersion']+'\nArchitecture: amd64'
                    if args[0] == 'apt-get': return '0 upgraded, 0 newly installed, 0 to remove'
                    if args[0] == 'dpkg-query': return 'installed '+cat['PackageVersion']
                    raise AssertionError(args)
                response = io.BytesIO(package_bytes); response.geturl = lambda: cat['Repository']+cat['Filename']
                with mock.patch.dict(NS, {'BASE': root, 'owned_boot': lambda _: None, 'sources_verify': lambda _: None, 'save': lambda _: None, 'run': run, 'load': lambda _: prior, 'digest': lambda p: 'initrd' if 'initrd' in str(p) else 'image', 'entry': lambda _: 'retained-entry'}), mock.patch.object(NS['urllib'].request, 'urlopen', return_value=response):
                    if owned:
                        NS['install_worker'](state); self.assertEqual(state['Phase'], 'Prepared'); self.assertTrue(state['ReusedRetainedPackage'])
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'managed artifact history'): NS['install_worker'](state)
                        self.assertEqual(state['Phase'], 'InstallFailed')
                self.assertFalse(any(args[:2] == ['apt-get', '-y'] for args in calls))

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

    def test_upgrade_only_accepts_current_committed_identity_and_newer_kernel(self):
        cat=json.loads((ROOT/'config/kernel-catalog.json').read_text())
        old=cat['Kernel'];new='6.19.1-x64v1-xanmod1';cat['Kernel']=new;cat['Package']='linux-image-'+new
        prior={'Id':'a'*32,'Phase':'Committed','Catalog':{'Kernel':old},'OwnedDefaultSha256':'hash','NewImageSha256':'image','NewInitrdSha256':'initrd'}
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'current.json').write_text('{"Id":"'+'a'*32+'"}')
            def digest(p):return 'initrd' if 'initrd' in str(p) else 'image'
            defaults={'BASE':root,'DEFAULT':root/'default','UNIT':root/'unit','audit':lambda:{'Compatible':True,'BbrVersion':'v3','Kernel':old},
                      'load':lambda _:prior,'owned_boot':mock.Mock(),'catalog_validate':lambda _:None,'digest':digest}
            env={'VPS_PARAM_CATALOG':json.dumps(cat),'VPS_PARAM_PREVIOUS_TRANSACTION':'b'*32}
            with mock.patch.dict(NS,defaults),mock.patch.dict(NS['os'].environ,env):
                with self.assertRaisesRegex(RuntimeError,'identity mismatch'):NS['prepare']('c'*32)
                self.assertFalse((root/('c'*32)).exists())
            env['VPS_PARAM_PREVIOUS_TRANSACTION']='a'*32
            for changed in [('Phase','RolledBack'),('NewImageSha256','drift')]:
                invalid=copy.deepcopy(prior);invalid[changed[0]]=changed[1]
                with mock.patch.dict(NS,{**defaults,'load':lambda _:invalid}),mock.patch.dict(NS['os'].environ,env):
                    with self.assertRaises(RuntimeError):NS['prepare']('c'*32)
                    self.assertFalse((root/('c'*32)).exists())
            cat['Kernel']='6.1.1-x64v1-xanmod1';env['VPS_PARAM_CATALOG']=json.dumps(cat)
            with mock.patch.dict(NS,defaults),mock.patch.dict(NS['os'].environ,env):
                with self.assertRaisesRegex(RuntimeError,'downgrade'):NS['prepare']('c'*32)
                self.assertFalse((root/('c'*32)).exists())

    def test_original_rollback_and_previous_rollback_have_distinct_targets(self):
        original='6.12.74+deb13+1-cloud-amd64';previous='6.18.55-x64v1-xanmod1';current='6.18.56-x64v1-xanmod1'
        base={'Id':'a'*32,'Phase':'Committed','Catalog':{'Kernel':current},'OldKernel':previous,'OldEntry':'previous',
              'OldImageSha256':'hash','OldInitrdSha256':'hash','OriginalKernel':original,'OriginalEntry':'original',
              'OriginalImageSha256':'hash','OriginalInitrdSha256':'hash','OwnedDefaultSha256':'owned','Runtime':{'Kernel':current}}
        for original_target,expected,expected_entry in [(False,previous,'previous'),(True,original,'original')]:
            state=copy.deepcopy(base);writes=mock.Mock();commands=mock.Mock()
            with mock.patch.dict(NS,{'status':lambda _:state,'digest':lambda _:'hash','owned_boot':lambda _:None,'set_default':writes,
                                   'run':commands,'save':lambda _:None,'remove_guard':lambda _:None,'runtime':lambda:{'BootId':'new'}}),mock.patch.object(NS['platform'],'release',return_value=current):
                result=NS['rollback'](state,original_target)
            self.assertEqual(result['RollbackKernel'],expected);self.assertEqual(result['Phase'],'RollbackRequested')
            writes.assert_called_once_with(state,expected_entry)
            self.assertEqual(sum(call.args[0][0]=='systemd-run' for call in commands.call_args_list),1)
            state['Runtime']={'Kernel':expected,'BootId':'rebooted'};state['OldBootId']='old';state['Services']=[]
            with mock.patch.dict(NS,{'runtime':lambda:state['Runtime'],'run':lambda *a,**k:'','save':lambda _:None}):
                self.assertEqual(NS['status'](state)['Phase'],'RolledBack')

    def test_upgrade_after_abort_or_rollback_requires_committed_running_history(self):
        committed={'Id':'a'*32,'Phase':'Committed','Catalog':{'Kernel':'6.18.55-x64v1-xanmod1'}}
        for phase in ('Aborted','RolledBack'):
            latest={'Id':'b'*32,'Phase':phase,'Catalog':{'Kernel':'6.18.56-x64v1-xanmod1'},'PreviousTransaction':committed['Id']}
            with mock.patch.dict(NS,{'load':lambda _:committed}):
                self.assertEqual(NS['committed_running_kernel'](latest,committed['Catalog']['Kernel'])['Id'],committed['Id'])
            with mock.patch.dict(NS,{'load':lambda _:latest}):
                with self.assertRaises(RuntimeError):NS['committed_running_kernel'](latest,committed['Catalog']['Kernel'])


if __name__ == '__main__':
    unittest.main()
