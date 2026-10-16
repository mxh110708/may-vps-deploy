"""Maintainer build isolation contracts; never executed on the VPS being tuned."""
import base64
import io
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock
ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMP_ROOT = ROOT/'.test-output/kernel-prebuild-python'
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(TEMP_ROOT)
class MaintainerBuildContract(unittest.TestCase):
    def test_non_root_build_refuses_root_replay_and_config_drift(self):
        builder = {'__name__':'builder_contract'}
        exec(compile((ROOT/'scripts/kernel-source.py').read_text()+'\n'+(ROOT/'scripts/kernel-build.py').read_text(), 'builder_contract', 'exec'), builder)
        with mock.patch.object(builder['os'], 'geteuid', return_value=0, create=True):
            with self.assertRaisesRegex(RuntimeError, 'as root'): builder['build_google_kernel']()
        cat = json.loads((ROOT/'config/kernel-catalog.json').read_text())
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)/('mxh-google-bbr-build-'+'a'*32); root.mkdir()
            credentials = pathlib.Path(folder)/'credentials'; credentials.mkdir(); (credentials/'kernel.config').write_bytes(b'config')
            env = {'VPS_BUILD_CATALOG':base64.b64encode(json.dumps(cat).encode()).decode(),'VPS_BUILD_ID':'a'*32,'STATE_DIRECTORY':str(root),'CREDENTIALS_DIRECTORY':str(credentials),'VPS_BUILD_CONFIG_SHA256':'f'*64}
            with mock.patch.dict(builder['os'].environ, env), mock.patch.object(builder['os'], 'geteuid', return_value=1234, create=True), mock.patch.object(builder['subprocess'], 'run', side_effect=AssertionError('compiler')):
                with self.assertRaisesRegex(RuntimeError, 'configuration drift'): builder['build_google_kernel']()
                (root/'already-running').write_text('exists')
                with self.assertRaisesRegex(RuntimeError, 'replay'): builder['build_google_kernel']()

    def test_build_stops_its_process_group_when_disk_margin_is_exhausted(self):
        builder = {'__name__':'builder_contract'}
        exec(compile((ROOT/'scripts/kernel-source.py').read_text()+'\n'+(ROOT/'scripts/kernel-build.py').read_text(), 'builder_contract', 'exec'), builder)
        process = mock.Mock(pid=1234); process.poll.return_value = None
        process.communicate.side_effect = builder['subprocess'].TimeoutExpired('make', 5)
        disk = [types.SimpleNamespace(free=3*1024**3), types.SimpleNamespace(free=1024**3)]
        with mock.patch.object(builder['subprocess'], 'Popen', return_value=process), mock.patch.object(builder['shutil'], 'disk_usage', side_effect=disk), mock.patch.object(builder['os'], 'killpg', create=True) as kill:
            with self.assertRaisesRegex(RuntimeError, 'KernelBuildDiskLow'):
                builder['build_execute'](['make'], '.', {}, io.BytesIO())
        kill.assert_called_once_with(1234, builder['signal'].SIGTERM); process.wait.assert_called_once_with(timeout=5)

    def test_build_deadline_and_disk_preflight_refuse_unbounded_work(self):
        builder = {'__name__':'builder_contract'}
        exec(compile((ROOT/'scripts/kernel-source.py').read_text()+'\n'+(ROOT/'scripts/kernel-build.py').read_text(), 'builder_contract', 'exec'), builder)
        with mock.patch.object(builder['shutil'], 'disk_usage', return_value=types.SimpleNamespace(free=0)), mock.patch.object(builder['subprocess'], 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'KernelBuildDiskLow'): builder['build_execute'](['make'], '.', {}, io.BytesIO())
            spawn.assert_not_called()
        process = mock.Mock(pid=1234); process.poll.return_value = None
        with mock.patch.object(builder['shutil'], 'disk_usage', return_value=types.SimpleNamespace(free=4*1024**3)), mock.patch.object(builder['subprocess'], 'Popen', return_value=process), mock.patch.object(builder['time'], 'monotonic', side_effect=[0, 11]), mock.patch.object(builder['os'], 'killpg', create=True) as kill:
            with self.assertRaisesRegex(RuntimeError, 'KernelBuildTimeout'): builder['build_execute'](['make'], '.', {}, io.BytesIO(), timeout=10)
        kill.assert_called_once(); process.wait.assert_called_once()

if __name__ == '__main__': unittest.main()
