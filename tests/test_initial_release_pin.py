"""Initial Xray package pinning with isolated commands; no real installations."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt' or not shutil.which('bash'), 'Unix command fixtures run in Debian CI')
class InitialReleasePinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='initial-core-pin-')
        self.root = Path(self.temp.name)
        self.bin = self.root/'bin'; self.bin.mkdir()
        self.package = self.root/'package.zip'; self.package.write_bytes(b'isolated-package-identity')
        self.marker = self.root/'installer-called'
        installer = self.root/'installer.sh'
        installer.write_text('#!/usr/bin/env bash\nset -eu\n[[ "$1" == install && "$2" == --local && "$#" == 3 ]]\nread -r\nprintf local > "$VPS_TEST_INSTALL_MARKER"\n', encoding='utf-8')
        self.write('curl', '''#!/usr/bin/env python3
import os, pathlib, sys
args=sys.argv[1:]; target=args[args.index('--output')+1]
url=next(x for x in args if x.startswith('https://'))
source=os.environ['VPS_TEST_INSTALLER'] if url.endswith('/installer') else os.environ['VPS_TEST_PACKAGE']
pathlib.Path(target).write_bytes(pathlib.Path(source).read_bytes())
''')
        self.write('systemctl', '#!/usr/bin/env bash\nexit 0\n')
        binary = self.root/'xray'; binary.write_text('#!/usr/bin/env bash\nprintf "Xray 1.2.3\\n"\n', encoding='utf-8'); binary.chmod(0o755)
        source = (ROOT/'assets/remote/xray-install.sh').read_text(encoding='utf-8-sig').replace('/usr/local/bin/xray', str(binary))
        self.script = self.root/'operation.sh'; self.script.write_text(source, encoding='utf-8')
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'], VPS_PARAM_VERSION='1.2.3', VPS_PARAM_INSTALLER_URL='https://fixtures.invalid/installer', VPS_PARAM_INSTALLER_SHA256=hashlib.sha256(installer.read_bytes()).hexdigest(), VPS_PARAM_ASSET_NAME='Xray-linux-64.zip', VPS_PARAM_SHA256=hashlib.sha256(self.package.read_bytes()).hexdigest(), VPS_PARAM_DOWNLOAD_URL='https://github.com/XTLS/Xray-core/releases/download/1.2.3/Xray-linux-64.zip', VPS_TEST_INSTALLER=str(installer), VPS_TEST_PACKAGE=str(self.package), VPS_TEST_INSTALL_MARKER=str(self.marker))

    def write(self, name, text):
        path = self.bin/name; path.write_text(text, encoding='utf-8'); path.chmod(0o755)

    def tearDown(self): self.temp.cleanup()

    def run_operation(self): return subprocess.run([shutil.which('bash'), str(self.script)], env=self.env, capture_output=True, text=True, timeout=10)

    def test_verified_release_is_passed_as_local_package(self):
        result = self.run_operation()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text(), 'local')
        self.assertIn('VPSDEPLOY_XRAY_VERSION_B64=', result.stdout)

    def test_package_hash_failure_never_invokes_installer(self):
        self.env['VPS_PARAM_SHA256'] = 'a'*64
        self.assertNotEqual(self.run_operation().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_foreign_asset_url_never_invokes_installer(self):
        self.env['VPS_PARAM_DOWNLOAD_URL'] = 'https://fixtures.invalid/package.zip'
        self.assertNotEqual(self.run_operation().returncode, 0)
        self.assertFalse(self.marker.exists())


if __name__ == '__main__': unittest.main()
