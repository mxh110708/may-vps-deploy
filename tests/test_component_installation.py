"""Installation boundaries and protocol coexistence in isolated fixtures; no VPS."""
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
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' and value[1:2] == ':' else value

class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='component-install-', dir=ROOT / '.tmp')
        self.root = Path(self.folder.name)
        self.env = dict(os.environ, VPS_PARAM_COMPONENT='ShadowsocksLanding', VPS_PARAM_PORTS='45001')

    def tearDown(self):
        self.folder.cleanup()

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding='utf-8')
        path.chmod(0o755)
        return path

    def preflight(self):
        source = (ROOT / 'assets/remote/component-install-preflight.sh').read_text().split("python3 <<'PY'\n", 1)[1].split('\nPY', 1)[0]
        source = re.sub(r'(?<![\w/])/(?:usr/local|usr/bin|etc|var/lib|opt|root|nonexistent)(?=/|[\'"\s])', lambda m: self.root.as_posix() + m[0], source)
        preamble = '''import subprocess, os, pathlib
def fixture_run(*args, **kwargs):
    command = args[0]
    if command[0] == 'ss': return subprocess.CompletedProcess(command, 0, 'occupied' if os.environ.get('BUSY_PORT') else '', '')
    unit = command[-1]
    exists = pathlib.Path(os.environ['FIXTURE_ROOT'], 'etc/systemd/system', unit).is_file()
    return subprocess.CompletedProcess(command, 0 if exists else 1, '', '')
subprocess.run = fixture_run
'''
        result = subprocess.run([sys.executable, '-c', preamble + source], env=dict(self.env, FIXTURE_ROOT=str(self.root)), capture_output=True, text=True, timeout=20)
        marker = next(line.split('=', 1)[1] for line in result.stdout.splitlines() if line.startswith('VPSDEPLOY_INSTALLATION_CHECK_B64='))
        return json.loads(base64.b64decode(marker)), result.returncode

    def test_absent_component_and_free_port_allowed_without_mutation(self):
        self.write('usr/local/bin/xray', 'existing-binary')
        self.write('etc/systemd/system/xray.service', 'existing-unit')
        self.write('usr/local/etc/xray/config.json', 'existing-config')
        before = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}
        result, code = self.preflight()
        self.assertEqual(code, 0)
        self.assertTrue(result['Allowed'])
        self.assertEqual(before, {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()})

    def test_partial_files_and_busy_tcp_or_udp_port_rejected(self):
        path = self.write('etc/sing-box/unmanaged.txt', 'keep')
        result, _ = self.preflight(); self.assertEqual(result['Code'], 'ComponentExists')
        self.assertEqual(path.read_text(), 'keep')
        path.unlink(); path.parent.rmdir(); self.env['BUSY_PORT'] = '45001'
        result, _ = self.preflight(); self.assertEqual(result['Code'], 'PortBusy')
        self.env['VPS_PARAM_REQUIRE_ABSENT'] = 'true'
        _, code = self.preflight(); self.assertNotEqual(code, 0)

    def test_preservation_gate_detects_existing_config_change(self):
        old = self.write('usr/local/etc/xray/config.json', 'old-reality')
        result, _ = self.preflight()
        self.env.update(VPS_PARAM_VERIFY_ONLY='true', VPS_PARAM_BEFORE_JSON=json.dumps(result))
        self.write('usr/local/bin/sing-box', 'new-binary')
        self.write('etc/systemd/system/sing-box.service', 'new-unit')
        result, _ = self.preflight(); self.assertTrue(result['Allowed'])
        old.write_text('changed-existing')
        result, _ = self.preflight(); self.assertFalse(result['Allowed']); self.assertEqual(result['Code'], 'ExistingComponentChanged')

    def test_symlinked_parent_is_not_overwritten(self):
        if os.name == 'nt': self.skipTest('Windows symlink privilege; Linux CI covers this case')
        actual = self.root / 'outside'; actual.mkdir()
        (self.root / 'etc').mkdir(); (self.root / 'etc/sing-box').symlink_to(actual, target_is_directory=True)
        result, _ = self.preflight(); self.assertFalse(result['Allowed'])
        self.assertEqual(list(actual.iterdir()), [])

    def test_batch_preserves_existing_service_and_requires_every_selected_service(self):
        self.write('usr/local/bin/xray', 'existing-binary')
        old = self.write('usr/local/etc/xray/config.json', 'old-reality')
        self.write('etc/systemd/system/xray.service', 'old-unit')
        self.env.update(VPS_PARAM_COMPONENTS='ShadowsocksLanding,KomariController', VPS_PARAM_PORTS='45001,25774')
        before, _ = self.preflight(); self.assertTrue(before['Allowed'])
        self.env.update(VPS_PARAM_VERIFY_ONLY='true', VPS_PARAM_BEFORE_JSON=json.dumps(before))
        self.write('usr/local/bin/sing-box', 'new-ss')
        self.write('etc/systemd/system/sing-box.service', 'new-ss-unit')
        result, _ = self.preflight(); self.assertFalse(result['Allowed']); self.assertEqual(result['Code'], 'ComponentNotRunning')
        self.write('usr/local/bin/komari', 'new-controller')
        self.write('etc/systemd/system/komari.service', 'new-controller-unit')
        result, _ = self.preflight(); self.assertTrue(result['Allowed'])
        old.write_text('changed-existing')
        result, _ = self.preflight(); self.assertFalse(result['Allowed']); self.assertEqual(result['Code'], 'ExistingComponentChanged')

    def test_batch_rejects_one_collision_before_mutation_and_duplicate_ports(self):
        keep = self.write('var/lib/komari/private.db', 'keep-controller')
        self.env.update(VPS_PARAM_COMPONENTS='ShadowsocksLanding,KomariController', VPS_PARAM_PORTS='45001,25774')
        result, _ = self.preflight(); self.assertFalse(result['Allowed']); self.assertEqual(result['Code'], 'ComponentExists')
        self.assertEqual(keep.read_text(), 'keep-controller')
        keep.unlink(); keep.parent.rmdir(); self.env['VPS_PARAM_PORTS'] = '45001,45001'
        result, _ = self.preflight(); self.assertFalse(result['Allowed'])

    def test_batch_firewall_builds_one_increment_and_refuses_unreviewed_content(self):
        source = (ROOT / 'assets/remote/component-firewall-add.sh').read_text().split('python3 - "$temporary" <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]
        source = source.replace("'/etc/nftables.conf'", repr((self.root / 'nftables.conf').as_posix()))
        baseline = 'table inet filter {\n  chain input {\n    ct state established,related accept\n    tcp dport { 22,443 } accept\n  }\n}\n'
        original = self.write('nftables.conf', baseline); original.write_bytes(baseline.encode()); destination = self.root / 'proposed-nftables.conf'
        env = dict(self.env, VPS_PARAM_COMPONENTS_JSON=json.dumps([{'Component': 'AnyTlsEntry', 'Ports': [8443]}, {'Component': 'ShadowsocksLanding', 'Ports': [45001]}]), VPS_PARAM_EXPECTED_SHA256=hashlib.sha256(original.read_bytes()).hexdigest(), VPS_PARAM_ALLOWED_IPV4S='192.0.2.30')
        result = subprocess.run([sys.executable, '-c', source, str(destination)], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        proposed = destination.read_text(); self.assertIn('tcp dport { 8443 } accept', proposed)
        self.assertIn('ip saddr { 192.0.2.30 } tcp dport 45001 accept', proposed)
        self.assertIn('ip saddr { 192.0.2.30 } udp dport 45001 accept', proposed)
        self.assertIn('tcp dport { 22,443 } accept', proposed); self.assertEqual(original.read_text(), baseline)
        destination.unlink(); original.write_text(baseline + '# changed\n')
        result = subprocess.run([sys.executable, '-c', source, str(destination)], env=env, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(destination.exists())

    def coexistence(self, port):
        self.write('usr/local/bin/xray', '#!/usr/bin/env bash\nexit 0\n')
        self.write('usr/local/bin/sing-box-anytls', '#!/usr/bin/env bash\nexit 0\n')
        self.write('usr/local/etc/xray/config.json', json.dumps({'inbounds': [{'port': 443}]}))
        self.write('etc/sing-box-anytls/config.json', json.dumps({'inbounds': [{'listen_port': port}]}))
        self.write('etc/systemd/system/xray.service', '[Unit]\nDescription=Existing Reality\n')
        installer = (ROOT / 'assets/remote/sing-box-anytls-install.sh').read_text()
        unit = installer.split("sing-box-anytls.service <<'EOF'\n", 1)[1].split('\nEOF', 1)[0]
        self.write('etc/systemd/system/sing-box-anytls.service', unit)
        self.write('active-xray.service', 'true')
        source = (ROOT / 'assets/remote/protocol-lifecycle-apply-state.sh').read_text()
        source = re.sub(r'(?<![\w/])/(?:usr/local|etc)(?=/|[\'"\s])', lambda m: shell_path(self.root) + m[0], source)
        source = re.sub(r"(<<'PY'\n)(.*?)(\nPY)", lambda m: m[1] + m[2].replace(shell_path(self.root), self.root.as_posix()) + m[3], source, flags=re.S)
        preamble = '''python3(){ "$TEST_PYTHON" "$@"; }
systemctl(){
  echo "$*" >> "$TEST_ROOT/calls"
  local unit="${@: -1}"
  case "$1" in
    cat) [[ -f "$TEST_ROOT/etc/systemd/system/$unit" ]];;
    is-active|is-enabled) [[ -f "$TEST_ROOT/active-$unit" ]];;
    enable|start)
      for conflict in $(awk -F= '$1=="Conflicts" {print $2}' "$TEST_ROOT/etc/systemd/system/$unit"); do
        rm -f "$TEST_ROOT/active-$conflict"
      done
      touch "$TEST_ROOT/active-$unit";;
    disable|stop) rm -f "$TEST_ROOT/active-$unit"; return 0;;
    *) return 0;;
  esac
}
'''
        env = dict(self.env, TEST_ROOT=shell_path(self.root), TEST_PYTHON=shell_path(sys.executable), VPS_PARAM_REALITY_ENABLED='true', VPS_PARAM_ANYTLS_ENABLED='true', VPS_PARAM_SHADOWSOCKS_ENABLED='false')
        return subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble + source, text=True, capture_output=True, env=env, timeout=20)

    def test_distinct_ports_coexist_without_stopping_existing_reality(self):
        if not BASH: self.skipTest('Bash unavailable')
        result = self.coexistence(8443)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / 'calls').read_text()
        self.assertNotIn('disable --now xray.service', calls)
        self.assertTrue((self.root / 'active-xray.service').is_file())
        self.assertTrue((self.root / 'active-sing-box-anytls.service').is_file())

    def test_shared_ports_rejected_before_any_service_mutation(self):
        if not BASH: self.skipTest('Bash unavailable')
        result = self.coexistence(443)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())
        self.assertTrue((self.root / 'active-xray.service').is_file())

    def test_disabled_reality_backup_port_is_skipped_during_apply_and_final_validation(self):
        if not BASH:self.skipTest('Bash unavailable')
        binary=self.write('usr/local/bin/xray','#!/usr/bin/env bash\nexit 0\n')
        self.write('usr/local/etc/xray/config.json','{}')
        (self.root/'tmp').mkdir()
        preamble=r'''
systemctl(){ case "$1" in show) echo fixture;; is-active|is-enabled) [[ "${@: -1}" == xray.service ]];; *) return 0;; esac; }
id(){ echo fixture; }
chown(){ return 0; }
sleep(){ return 0; }
timeout(){ return 0; }
timedatectl(){ echo yes; }
sshd(){ if [[ "$1" == -T ]];then printf 'port 45003\nport 45004\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\n';fi; }
ss(){ echo "$*" >> "$TEST_ROOT/listener-calls";[[ "$*" != *'sport = :0' ]] && echo xray; }
install(){ if [[ " $* " == *' -d '* ]];then mkdir -p "${@: -1}";return;fi;local args=();while (($#));do case "$1" in -o|-g) shift 2;; *) args+=("$1");shift;; esac;done;command install "${args[@]}"; }
python3(){ local args=();for value in "$@";do args+=("${value//$TEST_ROOT/$TEST_NATIVE_ROOT}");done;"$TEST_PYTHON" "${args[@]}"; }
'''
        for name in ('xray-apply-config.sh','final-validate.sh'):
            for backup in ('','0','45002'):
                with self.subTest(script=name,backup=backup):
                    source=(ROOT/'assets/remote'/name).read_text()
                    source=re.sub(r'(?<![\w/])/(?:usr/local|etc|root|var/log)(?=/|[\'"\s])',lambda match:shell_path(self.root)+match[0],source)
                    calls=self.root/'listener-calls'
                    if calls.exists():calls.unlink()
                    env=dict(self.env,TEST_ROOT=shell_path(self.root),TEST_NATIVE_ROOT=self.root.as_posix(),TEST_PYTHON=shell_path(sys.executable),TMPDIR=shell_path(self.root/'tmp'),
                             VPS_PARAM_CONFIG_JSON='{}',VPS_PARAM_PRIMARY_PORT='45001',VPS_PARAM_BACKUP_PORT=backup,VPS_PARAM_TARGET='example.invalid:443',
                             VPS_PARAM_ROLE='RealityEntry',VPS_PARAM_SSH_PRIMARY='45003',VPS_PARAM_SSH_RESCUE='45004',VPS_PARAM_XRAY_PRIMARY='45001',VPS_PARAM_XRAY_BACKUP=backup,
                             VPS_PARAM_REALITY_ENABLED='true',VPS_PARAM_ANYTLS_ENABLED='false',VPS_PARAM_SHADOWSOCKS_ENABLED='false',VPS_PARAM_KOMARI_ENABLED='false',VPS_PARAM_FIREWALL_MODE='PreserveExisting')
                    result=subprocess.run([BASH,'--noprofile','--norc','-s'],input=preamble+source,text=True,encoding='utf-8',errors='replace',capture_output=True,env=env,timeout=20)
                    self.assertEqual(result.returncode,0,result.stderr+result.stdout)
                    observed=calls.read_text()
                    self.assertNotIn('sport = :0',observed)
                    self.assertEqual(observed.count('sport = :45001'),1)
                    self.assertEqual('sport = :45002' in observed,backup=='45002')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--bash'); options, remaining = parser.parse_known_args()
    BASH = options.bash or ('/bin/bash' if os.name != 'nt' else None)
    (ROOT / '.tmp').mkdir(exist_ok=True)
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
