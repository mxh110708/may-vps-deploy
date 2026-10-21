"""Real Bash file/guard branches, using only a temporary root and fake service/core."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = None


def shell_path(path):
    value = Path(path).as_posix()
    return '/' + value[0].lower() + value[2:] if re.match(r'^[A-Za-z]:/', value) else value


class ServerOutboundScripts(unittest.TestCase):
    role = 'AnyTlsEntry'
    def setUp(self):
        if not BASH:
            self.skipTest('Bash unavailable')
        (ROOT / '.test-output').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='server-outbound-', dir=ROOT / '.test-output')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        is_reality = self.role == 'RealityEntry'
        self.service = 'xray.service' if is_reality else 'sing-box-anytls.service'
        self.config = self.root / ('usr/local/etc/xray/config.json' if is_reality else 'etc/sing-box-anytls/config.json')
        self.config.parent.mkdir(parents=True)
        self.original = b'{"inbounds":[],"synthetic":"original"}\n'
        self.config.write_bytes(self.original)
        binary = self.root / ('usr/local/bin/xray' if is_reality else 'usr/local/bin/sing-box-anytls')
        binary.parent.mkdir(parents=True)
        binary.write_bytes('''#!/usr/bin/env bash
set -euo pipefail
touch "$TEST_ROOT/core-checked"
if [[ "${TEST_INVALID:-false}" == true ]]; then echo 'sensitive-native-output' >&2; exit 1; fi
python3 -m json.tool "${@: -1}" >/dev/null
if [[ "${TEST_DRIFT:-false}" == true ]]; then printf 'external edit' > "$TEST_CONFIG"; fi
'''.encode('utf-8'))
        binary.chmod(0o755)
        self.env = dict(os.environ, TEST_ROOT=shell_path(self.root), TEST_NATIVE_ROOT=self.root.as_posix(), TEST_CONFIG=shell_path(self.config), TEST_CORE=shell_path(binary), TEST_SERVICE=self.service,
                        VPS_PARAM_ROLE=self.role, TEST_CONFIG_FLAG='-config' if is_reality else '-c',
                        TEST_PYTHON=shell_path(sys.executable), VPS_PARAM_CONFIG_JSON='{"synthetic":"candidate"}',
                        VPS_PARAM_EXPECTED_CONFIG_SHA256=hashlib.sha256(self.original).hexdigest())

    def run_asset(self, name, **extra):
        source = (ROOT / 'assets/remote' / name).read_text(encoding='utf-8')
        source = re.sub(r'(?<![\w/])/(?:usr/local|etc)(?=/|[\'"\s])', lambda m: shell_path(self.root) + m[0], source)
        preamble = '''python3(){ local args=(); for value in "$@"; do args+=("${value//$TEST_ROOT/$TEST_NATIVE_ROOT}"); done; "$TEST_PYTHON" "${args[@]}"; }
export -f python3
chown(){ printf '%s\\n' "$*" >> "$TEST_ROOT/ownership-calls"; }
id(){ [[ "$*" == "-gn ${TEST_USER:-root}" ]] || return 1; printf 'fixture-group'; }
systemctl(){
  printf '%s\\n' "$*" >> "$TEST_ROOT/service-calls"
  case "$1" in
    is-active|is-enabled) [[ "${TEST_INACTIVE:-false}" != true ]];;
    show) if [[ " $* " == *' -p User '* ]]; then printf '%s' "${TEST_USER:-root}"; elif [[ "${TEST_WRONG_UNIT:-false}" == true ]]; then printf 'foreign binary'; else printf '%s run %s %s' "$TEST_CORE" "$TEST_CONFIG_FLAG" "$TEST_CONFIG"; fi;;
    restart) [[ "${@: -1}" == "$TEST_SERVICE" ]];;
    *) return 1;;
  esac
}
'''
        return subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble + source, text=True,
                              encoding='utf-8', errors='replace', capture_output=True, env=dict(self.env, **extra), timeout=15)

    def no_restart(self):
        path = self.root / 'service-calls'
        self.assertNotIn('restart', path.read_text() if path.exists() else '')

    def test_apply_validates_and_replaces_only_owned_config(self):
        other = self.root / 'etc/untouched'; other.parent.mkdir(parents=True, exist_ok=True); other.write_text('keep')
        result = self.run_asset('server-outbound-apply.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.config.read_bytes()), {'synthetic': 'candidate'})
        self.assertEqual(other.read_text(), 'keep')
        self.assertTrue((self.root / 'core-checked').exists())
        calls = (self.root / 'service-calls').read_text()
        self.assertEqual(calls.count('restart ' + self.service), 1)
        self.assertIn('VPSDEPLOY_SERVER_OUTBOUND_APPLIED', result.stdout)
        self.assertFalse(list(self.config.parent.glob('.may-outbound-*')))

    def test_stale_hash_never_validates_or_restarts(self):
        result = self.run_asset('server-outbound-apply.sh', VPS_PARAM_EXPECTED_CONFIG_SHA256='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse((self.root / 'core-checked').exists())
        self.no_restart()

    def test_core_rejection_keeps_original_and_hides_native_errors(self):
        result = self.run_asset('server-outbound-apply.sh', TEST_INVALID='true')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertNotIn('sensitive-native-output', result.stderr)
        self.assertFalse(list(self.config.parent.glob('.may-outbound-*')))
        self.no_restart()

    def test_drift_during_validation_is_not_overwritten(self):
        result = self.run_asset('server-outbound-apply.sh', TEST_DRIFT='true')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), 'external edit')
        self.no_restart()

    def test_stopped_service_is_not_enabled_as_side_effect(self):
        result = self.run_asset('server-outbound-apply.sh', TEST_INACTIVE='true')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.no_restart()

    def test_wrong_unit_command_is_not_restarted(self):
        result = self.run_asset('server-outbound-apply.sh', TEST_WRONG_UNIT='true')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.no_restart()

    def test_unknown_role_does_not_choose_a_default_service(self):
        result = self.run_asset('server-outbound-apply.sh', VPS_PARAM_ROLE='Other')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.no_restart()

    def test_read_marks_exact_raw_hash_without_mutation(self):
        result = self.run_asset('server-outbound-read.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        marker = re.search(r'^VPSDEPLOY_SERVER_CONFIG_SHA256_B64=(.*)$', result.stdout, re.M)
        self.assertEqual(base64.b64decode(marker[1]).decode(), hashlib.sha256(self.original).hexdigest())
        self.assertEqual(self.config.read_bytes(), self.original)
        self.no_restart()

    def test_linked_file_is_rejected(self):
        target = self.config.with_name('foreign.json'); self.config.rename(target)
        try:
            self.config.symlink_to(target)
        except OSError:
            self.skipTest('Symlink creation not permitted')
        for name in ['server-outbound-read.sh', 'server-outbound-apply.sh']:
            self.assertNotEqual(self.run_asset(name).returncode, 0)
        self.assertEqual(target.read_bytes(), self.original)
        self.no_restart()


class RealityOutboundScripts(ServerOutboundScripts):
    role = 'RealityEntry'

    def test_config_group_follows_service_user(self):
        result = self.run_asset('server-outbound-apply.sh', TEST_USER='nobody')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('root:fixture-group', (self.root / 'ownership-calls').read_text())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--bash')
    options, remaining = parser.parse_known_args()
    BASH = options.bash or ('/bin/bash' if os.name != 'nt' else None)
    unittest.main(argv=[sys.argv[0], *remaining])
