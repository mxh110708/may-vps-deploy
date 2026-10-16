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
CODE = (ROOT/'scripts/bbr-runtime.py').read_text(encoding='utf8')+'\n'+(ROOT/'scripts/kernel-runtime.py').read_text(encoding='utf8')+'\n'+(ROOT/'scripts/kernel-engine.py').read_text(encoding='utf8')
NS = {'__name__': 'kernel_contract'}
exec(compile(CODE, 'kernel_contract', 'exec'), NS)


class KernelContract(unittest.TestCase):
    def test_vps_runtime_contains_no_compiler_or_version_query_client(self):
        for name in ('official_read','latest_candidate','build_dependencies','build_package','build_google_kernel'):
            self.assertNotIn(name, NS)

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

    def test_catalog_refuses_non_google_source_and_identity_drift(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        NS['catalog_validate'](cat)
        for field, value in [('Repository', 'https://deb.xanmod.org/'), ('Branch', 'master'), ('Architecture', 'arm64'), ('Kernel', '../../kernel'), ('Commit', '0'*40), ('Sha256', 'f'*64), ('SchemaVersion', 1)]:
            bad = copy.deepcopy(cat); bad[field] = value
            with self.assertRaises(RuntimeError): NS['catalog_validate'](bad)
        materials = {name: (ROOT/'assets/kernel'/name).read_bytes() for name in NS['SOURCE_NAMES']}
        NS['verify_materials'](cat, materials)
        materials['Makefile'] += b'\nSUBLEVEL = 999\n'
        with self.assertRaises(RuntimeError): NS['verify_materials'](cat, materials)

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

    def materials(self):
        return {name: (ROOT/'assets/kernel'/name).read_bytes() for name in NS['SOURCE_NAMES']}

    def test_source_version_and_bbr_are_read_from_the_actual_materials(self):
        materials = self.materials(); cat = NS['source_catalog'](materials)
        self.assertEqual(cat['BaseKernel'], '6.13.7')
        for value in (b'EXTRAVERSION = -rc1', b'EXTRAVERSION = arbitrary'):
            bad = dict(materials); bad['Makefile'] = materials['Makefile'].replace(b'EXTRAVERSION =', value, 1)
            with self.assertRaisesRegex(RuntimeError, 'KernelSourcePrerelease'): NS['source_catalog'](bad)
        bad = dict(materials); bad['tcp_bbr.c'] = NS['re'].sub(rb'(#define[ \t]+BBR_VERSION[ \t]+)3', rb'\g<1>1', materials['tcp_bbr.c'])
        with self.assertRaisesRegex(RuntimeError, 'KernelSourceNotV3'): NS['source_catalog'](bad)




    def test_current_kernel_version_parse_accepts_debian_suffixes(self):
        self.assertEqual(NS['kernel_version']('6.12.38+deb13-amd64'), (6,12,38))
        with self.assertRaises(RuntimeError): NS['kernel_version']('unknown')


    def test_prebuilt_manifest_rejects_paths_sizes_and_hash_drift(self):
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        NS['prebuilt_validate'](cat)
        for field, value in [('File','../../kernel.deb'), ('Bytes',True), ('Bytes',0), ('Bytes',1073741825), ('Sha256','bad'), ('ManifestSha256','bad')]:
            bad = copy.deepcopy(cat); bad['Prebuilt'][field] = value
            with self.assertRaisesRegex(RuntimeError, 'KernelPrebuiltRejected'): NS['prebuilt_validate'](bad)

    def test_small_vps_prebuilt_preflight_does_not_require_source_build_resources(self):
        contents={'/etc/os-release':'ID=debian\nVERSION_ID="12"\n','/proc/meminfo':'MemTotal: 440000 kB\nMemAvailable: 307200 kB\n'}
        def run(args,*a,**kw):
            if args[0]=='systemd-detect-virt':return 'kvm'
            if args[0]=='findmnt':return 'ext4' if 'FSTYPE' in args else '/dev/vda1'
            raise AssertionError(args)
        with mock.patch.dict(NS,{'runtime':lambda:{'Kernel':'6.1.1-stock'},'run':run,'regular':lambda _:None,'entry':lambda _:'old','boot_environment':lambda:{},'digest':lambda _:'f'*64}), mock.patch.object(NS['shutil'],'which',return_value='/tool'), mock.patch.object(NS['shutil'],'disk_usage',return_value=types.SimpleNamespace(free=4*1024**3)), mock.patch.object(NS['platform'],'machine',return_value='x86_64'), mock.patch.object(NS['platform'],'release',return_value='6.1.1-stock'), mock.patch.object(NS['Path'],'exists',return_value=False), mock.patch.object(NS['Path'],'stat',return_value=types.SimpleNamespace(st_size=100)), mock.patch.object(NS['Path'],'read_text',lambda p:contents[str(p).replace('\\','/')]):
            self.assertTrue(NS['audit']()['Compatible'])
            self.assertEqual(NS['audit']()['Delivery'],'Prebuilt')
            contents['/proc/meminfo']='MemTotal: 440000 kB\nMemAvailable: 250000 kB\n'
            self.assertFalse(NS['audit']()['Compatible'])

    def test_prebuilt_install_has_no_compiler_or_dependency_mutations(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory); identity = 'a'*32; target = root/identity; target.mkdir()
                payload = b'embedded kernel bytes'; (target/'kernel.deb').write_bytes(payload+(b'changed' if corrupt else b''))
                cat = json.loads((ROOT/'config/kernel-catalog.json').read_text()); cat['Prebuilt']['Sha256'] = hashlib.sha256(payload).hexdigest(); cat['Prebuilt']['Bytes'] = len(payload)
                state = {'Id':identity,'Catalog':cat,'Delivery':'Prebuilt','BuiltPackageSha256':cat['Prebuilt']['Sha256'],'Phase':'Installing','InstallInvocations':0,'OldKernel':'6.12.1-stock','OldImageSha256':'image'}
                commands = []
                def run(args,*a,**kw):
                    commands.append(args)
                    if args[:2] == ['dpkg-deb','-f']: return 'Package: '+cat['Package']+'\nVersion: '+cat['PackageVersion']+'\nArchitecture: amd64'
                    if args[:2] == ['apt-get','-s']: return 'Inst '+cat['Package']+' (test Debian [amd64])'
                    if args[0] == 'apt-get': return ''
                    if args[0] == 'dpkg-query': return 'installed '+cat['PackageVersion']
                    raise AssertionError(args)
                original_digest = NS['digest']
                def digest(path): return original_digest(path) if path == target/'kernel.deb' else 'image'
                with mock.patch.dict(NS, {'BASE':root,'run':run,'save':lambda _:None,'owned_boot':lambda _:None,'sources_verify':lambda _:None,'retained_package':lambda _:None,'digest':digest,'entry':lambda _:'new-entry','build_dependencies':mock.Mock(side_effect=AssertionError('compiler dependencies')),'build_package':mock.Mock(side_effect=AssertionError('compiler'))}), mock.patch.object(NS['Path'],'exists', return_value=False):
                    if corrupt:
                        with self.assertRaisesRegex(RuntimeError,'KernelPrebuiltRejected'): NS['install_worker'](state)
                        self.assertEqual(state['Phase'],'InstallFailed'); self.assertFalse(commands)
                    else:
                        NS['install_worker'](state); self.assertEqual(state['Phase'],'Prepared')
                        self.assertEqual(sum(c[0]=='apt-get' and '-s' not in c for c in commands),1)

    def test_uploaded_prebuilt_is_verified_before_copy_and_staging_cleanup(self):
        payload = b'prebuilt copy contract'; cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        cat['Prebuilt']['Sha256'] = hashlib.sha256(payload).hexdigest(); cat['Prebuilt']['Bytes'] = len(payload)
        upload = mock.MagicMock(); upload.__str__.return_value='/tmp/mxh-vps.ABCDEF1234/kernel.deb'
        upload.stat.return_value=types.SimpleNamespace(st_uid=0,st_mode=0o100600,st_size=len(payload))
        upload.parent.stat.return_value=types.SimpleNamespace(st_uid=0,st_mode=0o40700)
        upload.open.side_effect=lambda *a:io.BytesIO(payload)
        with tempfile.TemporaryDirectory() as folder:
            target=pathlib.Path(folder); original_digest=NS['digest']
            with mock.patch.dict(NS, {'Path':lambda _:upload,'regular':lambda *a:None,'digest':lambda p:cat['Prebuilt']['Sha256'] if p is upload else original_digest(p)}), mock.patch.dict(NS['os'].environ,{'VPS_PARAM_PACKAGE_PATH':'ignored by fake path'}):
                package=NS['take_prebuilt'](cat,target)
            self.assertEqual(package.read_bytes(),payload); upload.unlink.assert_called_once(); upload.parent.rmdir.assert_called_once()
        upload.stat.return_value.st_size += 1
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(NS,{'Path':lambda _:upload,'regular':lambda *a:None}), mock.patch.dict(NS['os'].environ,{'VPS_PARAM_PACKAGE_PATH':'ignored by fake path'}):
            with self.assertRaisesRegex(RuntimeError,'KernelPrebuiltRejected'): NS['take_prebuilt'](cat,pathlib.Path(folder))
            self.assertFalse(list(pathlib.Path(folder).iterdir()))






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

    def test_previously_owned_installed_target_is_reused_without_compiling_or_installing(self):
        for owned in (True, False):
            with self.subTest(owned=owned), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory); identity = 'a'*32; (root/identity).mkdir()
                cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
                state = {'Id':identity,'Phase':'Installing','InstallInvocations':0,'Catalog':cat,'PreviousTransaction':'b'*32,'OldKernel':'6.12.1-amd64','OldImageSha256':'image'}
                prior = {'Id':'b'*32,'Phase':'RolledBack','Catalog':cat,'NewImageSha256':'image','NewInitrdSha256':'initrd'} if owned else {'Id':'b'*32,'Phase':'Aborted','Catalog':{'Kernel':'foreign'}}
                def run(args,*a,**kw):
                    if args[0]=='dpkg-query': return 'installed '+cat['PackageVersion']
                    raise AssertionError(args)
                with mock.patch.dict(NS, {'BASE':root,'owned_boot':lambda _:None,'sources_verify':lambda _:None,'save':lambda _:None,'run':run,'load':lambda _:prior,'digest':lambda p:'initrd' if 'initrd' in str(p) else 'image','entry':lambda _:'retained-entry','build_dependencies':mock.Mock(side_effect=AssertionError('dependency mutation')),'build_package':mock.Mock(side_effect=AssertionError('unnecessary build'))}):
                    if owned:
                        NS['install_worker'](state); self.assertEqual(state['Phase'],'Prepared'); self.assertTrue(state['ReusedRetainedPackage'])
                    else:
                        with self.assertRaisesRegex(RuntimeError,'managed artifact history'): NS['install_worker'](state)
                        self.assertEqual(state['Phase'],'InstallFailed')

    def test_same_source_with_different_prebuilt_binary_is_not_retained_as_the_new_artifact(self):
        cat=json.loads((ROOT/'config/kernel-catalog.json').read_text()); prior=copy.deepcopy(cat);prior['Prebuilt']['Sha256']='f'*64
        state={'Catalog':cat,'PreviousTransaction':'b'*32}
        previous={'Id':'b'*32,'Phase':'RolledBack','Catalog':prior,'NewImageSha256':'image','NewInitrdSha256':'initrd'}
        with mock.patch.dict(NS,{'run':lambda *a,**k:'installed '+cat['PackageVersion'],'load':lambda _:previous,'digest':lambda _:'image'}):
            with self.assertRaisesRegex(RuntimeError,'matching managed artifact history'):NS['retained_package'](state)

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
        old=cat['Kernel'];new='6.14.1-mxh-bbr3-111111111111';cat['Kernel']=new;cat['Package']='linux-image-'+new
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
            cat['Kernel']='6.1.1-mxh-bbr3-222222222222';env['VPS_PARAM_CATALOG']=json.dumps(cat)
            with mock.patch.dict(NS,defaults),mock.patch.dict(NS['os'].environ,env):
                with self.assertRaisesRegex(RuntimeError,'downgrade'):NS['prepare']('c'*32)
                self.assertFalse((root/('c'*32)).exists())

    def test_original_rollback_and_previous_rollback_have_distinct_targets(self):
        original='6.12.74+deb13+1-cloud-amd64';previous='6.13.6-mxh-bbr3-111111111111';current='6.13.7-mxh-bbr3-222222222222'
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
        committed={'Id':'a'*32,'Phase':'Committed','Catalog':{'Kernel':'6.13.6-mxh-bbr3-111111111111'}}
        for phase in ('Aborted','RolledBack'):
            latest={'Id':'b'*32,'Phase':phase,'Catalog':{'Kernel':'6.13.7-mxh-bbr3-222222222222'},'PreviousTransaction':committed['Id']}
            with mock.patch.dict(NS,{'load':lambda _:committed}):
                self.assertEqual(NS['committed_running_kernel'](latest,committed['Catalog']['Kernel'])['Id'],committed['Id'])
            with mock.patch.dict(NS,{'load':lambda _:latest}):
                with self.assertRaises(RuntimeError):NS['committed_running_kernel'](latest,committed['Catalog']['Kernel'])


if __name__ == '__main__':
    unittest.main()
