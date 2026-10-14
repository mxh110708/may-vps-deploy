"""Cross-feature review regressions on disposable files; no production network."""
import argparse
import contextlib
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tarfile
import unittest
import types
from unittest import mock

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from build_client_authority import replace_named, update_node_references, validate_rendered_references, apply_sing_groups

BASH = None
FIREWALL = (ROOT/'assets/remote/firewall-tools.sh').read_text(encoding='utf-8').split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]

def shell_path(path):
    value = Path(path).as_posix()
    return '/'+value[0].lower()+value[2:] if os.name == 'nt' and value[1:2] == ':' else value

class ReviewRepairs(unittest.TestCase):
    def test_bootstrap_key_keeps_an_existing_key_without_trailing_newline_valid(self):
        if not BASH: self.skipTest('Bash fixture unavailable')
        for old in ('', 'ssh-ed25519 synthetic-old'):
            with self.subTest(old=old), tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
                root = Path(folder); file = root/'root/.ssh/authorized_keys'; file.parent.mkdir(parents=True); file.write_text(old)
                source = (ROOT/'assets/remote/bootstrap-access.sh').read_text().replace('/root/.ssh', shell_path(root/'root/.ssh'))
                preamble = '''sshd(){ printf 'pubkeyauthentication yes\\nauthorizedkeysfile .ssh/authorized_keys\\nauthenticationmethods any\\n'; }\n'''
                if os.name == 'nt': preamble += 'chmod(){ return 0; }\ninstall(){ mkdir -p "${@: -1}"; }\n'
                env = dict(os.environ, VPS_PARAM_PUBLIC_KEY='ssh-ed25519 synthetic-new')
                result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+source, env=env, text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(file.read_text().splitlines(), ([old] if old else [])+['ssh-ed25519 synthetic-new'])
                original = file.read_bytes()
                result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+source, env=env, text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(file.read_bytes(), original)

    def test_generated_selector_replaces_matching_urltest_once(self):
        custom = {'tag': 'Custom', 'type': 'urltest', 'outbounds': ['A'], 'url': 'https://example.com', 'interval': '10m'}
        document = {'outbounds': [{'tag': 'A', 'type': 'direct'}, {'tag': 'Region', 'type': 'urltest', 'outbounds': ['A'], 'tolerance': 50}, custom, {'tag': 'Unused', 'type': 'urltest', 'outbounds': ['A']}]}
        apply_sing_groups(document, [{'name': 'Region', 'members': ['A']}], ['Region'], {'Unused'})
        self.assertEqual([item['tag'] for item in document['outbounds']].count('Region'), 1)
        self.assertEqual(next(item for item in document['outbounds'] if item['tag'] == 'Region'), {'tag': 'Region', 'type': 'selector', 'outbounds': ['A'], 'default': 'A'})
        self.assertIn(custom, document['outbounds'])
        self.assertNotIn('Unused', [item['tag'] for item in document['outbounds']])
        validate_rendered_references({}, document)

    def test_native_import_preserves_coexisting_entries_and_primary_identity(self):
        source = (ROOT/'assets/remote/existing-vps-import-audit.sh').read_text().split("python3 <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder)
            def path(value): return root/str(value).lstrip('/')
            reality = {'inbounds': [{'tag': 'reality-'+label+'-ipv4', 'port': port, 'protocol': 'vless', 'settings': {'clients': [{'id': 'synthetic-user', 'flow': 'xtls-rprx-vision'}]}, 'streamSettings': {'security': 'reality', 'realitySettings': {'serverNames': ['entry.example.com'], 'shortIds': ['abcd'], 'privateKey': 'synthetic-key', 'target': '127.0.0.1:9444'}}} for label, port in [('primary', 9443), ('backup', 7443)]]}
            anytls = {'inbounds': [{'type': 'anytls', 'listen_port': 8443, 'users': [{'password': 'synthetic-anytls'}], 'tls': {'server_name': 'node.example.com'}}]}
            contents = {'/usr/local/etc/xray/config.json': json.dumps(reality), '/etc/sing-box-anytls/config.json': json.dumps(anytls), '/etc/sing-box-anytls/ech-config.pem': 'synthetic-config', '/etc/sing-box-anytls/ech-key.pem': 'synthetic-key', '/etc/os-release': 'ID=debian\nVERSION_ID=13', '/proc/meminfo': 'MemTotal: 1048576 kB'}
            for name, content in contents.items(): path(name).parent.mkdir(parents=True, exist_ok=True); path(name).write_text(content)
            for name in ('/usr/local/bin/xray', '/usr/local/bin/sing-box-anytls'): path(name).parent.mkdir(parents=True, exist_ok=True); path(name).write_text('synthetic executable'); path(name).chmod(0o755)
            active = {'xray.service', 'sing-box-anytls.service'}
            def run(args, **kwargs):
                if args[0] == 'systemctl': return subprocess.CompletedProcess(args, 0 if args[-1] in active else 1, '', '')
                if args[:2] == ('sshd', '-T') or args[:2] == ['sshd', '-T']: output = 'port 22\npubkeyauthentication yes\n'
                elif args[0] == 'openssl': output = 'DNS:node.example.com, DNS:ech.example.com'
                elif args[0] == '/usr/local/bin/xray': output = 'Password: synthetic-public-key' if args[1] == 'x25519' else 'Xray 26.10.1'
                elif args[0] == '/usr/local/bin/sing-box-anytls': output = 'sing-box version 1.14.2'
                elif args[0] == 'ss': output = '\n'.join('LISTEN 0 128 0.0.0.0:'+str(port)+' 0.0.0.0:* xray sing-box-anytls' for port in (9443, 7443, 8443))
                elif args[0] == 'uname': output = 'x86_64'
                else: output = ''
                return subprocess.CompletedProcess(args, 0, output, '')
            pwd_stub = types.SimpleNamespace(getpwnam=mock.Mock(side_effect=KeyError()))
            output = io.StringIO()
            with mock.patch.dict(sys.modules, {'pwd': pwd_stub}), mock.patch('pathlib.Path', path), mock.patch.object(os, 'access', lambda value, mode: path(value).is_file()), mock.patch.object(subprocess, 'run', run), mock.patch.dict(os.environ, {'VPS_PARAM_NATIVE_IMPORT': 'true'}), contextlib.redirect_stdout(output):
                exec(compile(source, 'native-import', 'exec'), {})
            line = next(line for line in output.getvalue().splitlines() if line.startswith('VPSDEPLOY_IMPORT_PRIVATE_B64='))
            result = json.loads(base64.b64decode(line.split('=', 1)[1]))
            self.assertEqual(result['Protocols']['RealityEntry']['PrimaryPort'], 9443)
            self.assertEqual(result['Protocols']['RealityEntry']['BackupPort'], 7443)
            self.assertEqual(result['Protocols']['RealityEntry']['LocalHttpsPort'], 9444)
            self.assertTrue(result['Audit']['ProtocolInventory']['RealityEntry']['Enabled'])
            self.assertTrue(result['Audit']['ProtocolInventory']['AnyTlsEntry']['Enabled'])
            anytls['inbounds'][0]['listen_port'] = 9443; path('/etc/sing-box-anytls/config.json').write_text(json.dumps(anytls))
            with mock.patch.dict(sys.modules, {'pwd': pwd_stub}), mock.patch('pathlib.Path', path), mock.patch.object(os, 'access', lambda value, mode: path(value).is_file()), mock.patch.object(subprocess, 'run', run), mock.patch.dict(os.environ, {'VPS_PARAM_NATIVE_IMPORT': 'true'}), mock.patch('builtins.print'):
                with self.assertRaisesRegex(RuntimeError, 'ports conflict'): exec(compile(source, 'native-import', 'exec'), {})

    def test_fresh_deployment_firewall_recovery_preserves_other_tables(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); baseline = root/('a'*32); baseline.mkdir(); (baseline/'baseline.complete').write_text('fixture')
            config = root/'nftables.conf'; config.write_text('original conffile')
            with tarfile.open(baseline/'files.tar.gz', 'w:gz') as archive: archive.add(config, arcname='etc/nftables.conf')
            candidate = root/'candidate'; candidate.write_text('table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n tcp dport { 22, 443 } accept\n }\n}\n')
            code = FIREWALL.replace("Path('/etc/nftables.conf')", 'Path('+repr(str(config))+')').replace("r'/root/vps-deploy-transaction-baselines/[a-f0-9]{32}'", 're.escape('+repr(str(baseline))+')')
            live = {'managed': None, 'unrelated': 'preserved'}; calls = []
            def run(command, **kwargs):
                calls.append(command)
                if command == ['nft', '-j', 'list', 'tables']:
                    tables = [{'table': {'family': 'ip', 'name': 'unrelated'}}]
                    if live['managed'] is not None: tables.append({'table': {'family': 'inet', 'name': 'filter'}})
                    result = json.dumps({'nftables': tables})
                elif command[:4] == ['nft', '-s', '-nn', 'list']: result = live['managed']
                elif command == ['nft', 'delete', 'table', 'inet', 'filter']: live['managed'] = None; result = ''
                else: raise AssertionError(command)
                return subprocess.CompletedProcess(command, 0, result, '')
            def invoke(action, *args):
                with mock.patch.object(sys, 'argv', ['firewall', action, str(baseline), *map(str, args)]), mock.patch.object(subprocess, 'run', run), mock.patch('builtins.print'):
                    with self.assertRaises(SystemExit) as exit_code: exec(compile(code, 'baseline-firewall', 'exec'), {})
                    self.assertEqual(exit_code.exception.code, 0)
            invoke('deployment-intent', candidate); config.write_bytes(candidate.read_bytes()); live['managed'] = candidate.read_text().split('\n\n', 1)[1]
            invoke('deployment-check'); invoke('deployment-clear')
            self.assertIsNone(live['managed']); self.assertEqual(live['unrelated'], 'preserved')
            self.assertIn(['nft', 'delete', 'table', 'inet', 'filter'], calls)
            self.assertFalse(any('ruleset' in call for call in calls))
            config.write_text('external administrator edit'); before = len(calls)
            with mock.patch.object(sys, 'argv', ['firewall', 'deployment-clear', str(baseline)]), mock.patch.object(subprocess, 'run', run):
                with self.assertRaisesRegex(SystemExit, 'externally'): exec(compile(code, 'baseline-firewall', 'exec'), {})
            self.assertFalse(any(call[:2] == ['nft', 'delete'] for call in calls[before:]))

    def test_retirement_retains_shared_certificate_materials(self):
        if not BASH: self.skipTest('Bash fixture unavailable')
        source = (ROOT/'assets/remote/maintenance-decommission.sh').read_text()
        preamble = 'systemctl(){ [[ "$1" != is-active ]]; }\nrm(){ printf "REMOVE %s\\n" "$*"; }\n'
        result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+source, env=dict(os.environ, VPS_PARAM_SCOPE='RemoveManaged', VPS_PARAM_REMOVE_CONTROLLER='false'), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/usr/local/bin/xray', result.stdout)
        for retained in ('/etc/mxh-tls', 'mxh-certbot-renew', 'mxh-certbot-dns'): self.assertNotIn(retained, result.stdout)

    def test_fresh_deployment_accepts_only_untouched_new_package_conffile(self):
        for edited in (False, True):
            with self.subTest(edited=edited), tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
                root = Path(folder); baseline = root/('a'*32); baseline.mkdir(); (baseline/'baseline.complete').write_text('fixture')
                with tarfile.open(baseline/'files.tar.gz', 'w:gz'): pass
                config = root/'nftables.conf'; original = b'package default'; config.write_bytes(original + (b'\nexternal edit' if edited else b''))
                candidate = root/'candidate'; candidate.write_text('table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n tcp dport 22 accept\n }\n}\n')
                code = FIREWALL.replace("Path('/etc/nftables.conf')", 'Path('+repr(str(config))+')').replace("r'/root/vps-deploy-transaction-baselines/[a-f0-9]{32}'", 're.escape('+repr(str(baseline))+')')
                def run(command, **kwargs):
                    output = json.dumps({'nftables': []}) if command[0] == 'nft' else ' /etc/nftables.conf '+hashlib.md5(original).hexdigest()+'\n'
                    return subprocess.CompletedProcess(command, 0, output, '')
                with mock.patch.object(sys, 'argv', ['firewall', 'deployment-intent', str(baseline), str(candidate)]), mock.patch.object(subprocess, 'run', run):
                    with self.assertRaises(SystemExit) as error: exec(compile(code, 'baseline-conffile', 'exec'), {})
                if edited:
                    self.assertIn('changed externally', str(error.exception)); self.assertFalse((baseline/'firewall-state.json').exists())
                else:
                    self.assertEqual(error.exception.code, 0); self.assertIsNone(json.loads((baseline/'firewall-state.json').read_text())['Original']['File'])

    def test_legacy_ssh_recovery_uses_scoped_firewall_and_key_rotation_preserves_it(self):
        if not BASH: self.skipTest('Bash fixture unavailable')
        for firewall in ('true', 'false'):
            with self.subTest(firewall=firewall), tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
                root = Path(folder)
                for relative, content in {'etc/ssh/sshd_config': 'original ssh', 'etc/nftables.conf': 'flush ruleset\noriginal rules', 'root/.ssh/authorized_keys': 'ssh-ed25519 old'}.items():
                    file = root/relative; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(content)
                for relative in ('etc/systemd/system', 'root/vps-deploy-backups', 'var/lib/mxh-vps-deploy'): (root/relative).mkdir(parents=True, exist_ok=True)
                source = (ROOT/'assets/remote/maintenance-ssh-apply.sh').read_text()
                source = re.sub(r"/(?:var/lib|root|etc)(?=/|['\"\s])", lambda match: shell_path(root)+match[0], source)
                preamble = r'''
flock(){ return 0; }
systemctl(){ [[ "$1" != is-active ]]; }
sshd(){ return 0; }
id(){ [[ "${1:-}" != -gn ]] || echo root; }
getent(){ printf 'root:x:0:0:root:%s/root:/bin/bash\n' "$TEST_ROOT"; }
chmod(){ return 0; }
chown(){ return 0; }
install(){ if [[ "$1" == -d ]]; then mkdir -p "${@: -1}"; else cp "${@: -2:1}" "${@: -1}"; fi; }
mxh_firewall(){
  echo "$1" >> "$TEST_ROOT/firewall-calls"
  case "$1" in
    check) return 0;;
    snapshot) echo '{"Version":1}' > "$2";;
    restore) printf 'table inet filter {}\nflush table inet filter\n' > "$4";;
    *) return 1;;
  esac
}
nft(){ [[ "$1" != -f ]] || { ! grep -q 'flush ruleset' "$2" || return 90; }; }
'''
                env = dict(os.environ, TEST_ROOT=shell_path(root), VPS_PARAM_OLD_PORTS='22,2222', VPS_PARAM_NEW_PRIMARY='3333', VPS_PARAM_NEW_RESCUE='4444', VPS_PARAM_NEW_PUBLIC_KEY='ssh-ed25519 synthetic-new', VPS_PARAM_ADMIN_USER='root', VPS_PARAM_FIREWALL_REQUIRED=firewall)
                result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+source, text=True, capture_output=True, env=env, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                backup = next((root/'root/vps-deploy-backups').glob('*/ssh-maintenance'))
                self.assertTrue((backup/'deadline-epoch').is_file())
                before = (root/'etc/nftables.conf').read_bytes()
                result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+'source "'+shell_path(backup/'rollback')+'"\n', text=True, capture_output=True, env=env, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root/'root/.ssh/authorized_keys').read_text().strip(), 'ssh-ed25519 old')
                if firewall == 'true':
                    self.assertEqual((root/'firewall-calls').read_text().splitlines(), ['check', 'snapshot', 'restore'])
                    self.assertNotIn('flush ruleset', (root/'etc/nftables.conf').read_text())
                else:
                    self.assertFalse((root/'firewall-calls').exists()); self.assertEqual((root/'etc/nftables.conf').read_bytes(), before)

    def test_removed_and_renamed_authority_nodes_do_not_survive_builder(self):
        for client, key, groupkey in [('clash', 'name', 'proxy-groups'), ('sing_box', 'tag', 'outbounds')]:
            removed = {'A', 'B'}; renamed = {'B': 'C'}
            nodes = replace_named([{key: 'A'}, {key: 'B'}, {key: 'unowned', 'advanced': True}], key, [{key: 'C'}], removed)
            self.assertEqual([item[key] for item in nodes], ['unowned', 'C'])
            self.assertTrue(nodes[0]['advanced'])
            document = {groupkey: [{'type': 'selector', key: 'Custom', 'proxies' if client == 'clash' else 'outbounds': ['A', 'B', 'unowned'], 'default': 'A', 'advanced': {'preserve': True}}]}
            update_node_references(document, removed, renamed, client)
            group = document[groupkey][0]
            self.assertEqual(group['proxies' if client == 'clash' else 'outbounds'], ['C', 'unowned'])
            self.assertEqual(group['default'], 'C'); self.assertTrue(group['advanced']['preserve'])

    def test_renamed_nodes_update_direct_rules_and_removed_rule_targets_are_refused(self):
        document = {'rules': ['DOMAIN,example.com,B', 'IP-CIDR,192.0.2.0/24,B,no-resolve', 'MATCH,DIRECT'], 'sub-rules': {'custom': ['DOMAIN,another.example,B']}}
        update_node_references(document, {'B'}, {'B': 'C'}, 'clash')
        self.assertEqual(document['rules'], ['DOMAIN,example.com,C', 'IP-CIDR,192.0.2.0/24,C,no-resolve', 'MATCH,DIRECT'])
        self.assertEqual(document['sub-rules']['custom'], ['DOMAIN,another.example,C'])
        with self.assertRaises(SystemExit): update_node_references(document, {'C'}, {}, 'clash')
        sing = {'route': {'rule_set': [{'download_detour': 'B', 'url': 'https://example.com/rules'}]}, 'outbounds': []}
        update_node_references(sing, {'B'}, {'B': 'C'}, 'sing_box')
        self.assertEqual(sing['route']['rule_set'][0]['download_detour'], 'C')

    def test_node_rename_preserves_independent_dns_server_names(self):
        sing = {'outbounds': [], 'route': {'final': 'B'}, 'dns': {'servers': [{'tag': 'B', 'detour': 'B'}, {'tag': 'C'}], 'final': 'B', 'rules': [{'server': 'B'}]}}
        update_node_references(sing, {'B'}, {'B': 'C'}, 'sing_box')
        self.assertEqual(sing['route']['final'], 'C')
        self.assertEqual(sing['dns']['final'], 'B')
        self.assertEqual(sing['dns']['rules'][0]['server'], 'B')
        self.assertEqual(sing['dns']['servers'][0]['tag'], 'B')
        self.assertEqual(sing['dns']['servers'][0]['detour'], 'C')

    def test_actual_builder_deletion_preserves_source_and_advanced_settings(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); clash = root/'source.yaml'; sing = root/'source.json'; specification = root/'layout.json'; output = root/'candidate'
            c = {'dns': {'enable': True, 'nameserver': ['https://dns.example/dns-query']}, 'proxies': [{'name': 'A', 'type': 'ss', 'server': '192.0.2.1', 'port': 10001, 'cipher': 'aes-128-gcm', 'password': 'synthetic'}, {'name': 'B', 'type': 'ss', 'server': '192.0.2.2', 'port': 10002, 'cipher': 'aes-128-gcm', 'password': 'synthetic'}], 'proxy-groups': [{'name': 'Custom', 'type': 'select', 'proxies': ['A', 'B'], 'hidden': True}]}
            s = {'outbounds': [{'tag': name, 'type': 'shadowsocks', 'server': '192.0.2.2', 'server_port': 10002, 'method': 'aes-128-gcm', 'password': 'synthetic'} for name in ('A', 'B')]+[{'tag': 'Custom', 'type': 'selector', 'outbounds': ['A', 'B'], 'default': 'A', 'interrupt_exist_connections': True}], 'route': {'final': 'Custom'}}
            with clash.open('w', encoding='utf-8') as f: YAML().dump(c, f)
            sing.write_text(json.dumps(s), encoding='utf-8')
            spec = {'schema_version': 1, 'manual_nodes': [{'name': 'B', 'kind': 'entry', 'region_group': 'Region', 'clash': c['proxies'][1], 'sing_box': s['outbounds'][1]}], 'groups': [{'name': 'Region', 'members': ['B']}], 'remove_nodes': ['A']}
            specification.write_text(json.dumps(spec)); before = [p.read_bytes() for p in (clash, sing)]
            result = subprocess.run([sys.executable, str(ROOT/'scripts/build_client_authority.py'), '--clash', str(clash), '--sing-box', str(sing), '--spec', str(specification), '--output', str(output)], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            actual_c = YAML(typ='safe').load((output/'Clash_General.candidate.yaml').read_text(encoding='utf-8')); actual_s = json.loads((output/'sing-box-general.candidate.json').read_text())
            self.assertEqual([n['name'] for n in actual_c['proxies']], ['B'])
            self.assertEqual([n['tag'] for n in actual_s['outbounds'] if n['type'] == 'shadowsocks'], ['B'])
            self.assertTrue(next(g for g in actual_c['proxy-groups'] if g['name'] == 'Custom')['hidden'])
            self.assertTrue(next(g for g in actual_s['outbounds'] if g['tag'] == 'Custom')['interrupt_exist_connections'])
            self.assertEqual(actual_c['dns'], c['dns']); self.assertEqual([p.read_bytes() for p in (clash, sing)], before)

    def firewall(self, action, root, live, *args, parameters=None):
        code = FIREWALL.replace("Path('/etc/nftables.conf')", 'Path('+repr(str(root/'nftables.conf'))+')')
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, live, '')
        with mock.patch.object(sys, 'argv', ['firewall', action, *map(str, args)]), mock.patch.object(subprocess, 'run', run), mock.patch.dict(os.environ, parameters or {}), mock.patch.dict(os.environ, {'VPS_PARAM_TCP_PORTS': parameters['VPS_PARAM_TCP_PORTS']} if parameters else {}), mock.patch('builtins.print'):
            exec(compile(code, 'firewall', 'exec'), {})
        return calls

    def test_firewall_restore_batch_does_not_flush_other_tables_and_rejects_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); config = root/'nftables.conf'; state = root/'firewall-state.json'; backup = root/'old.conf'; candidate = root/'candidate'; output = root/'restore'
            baseline = 'table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n tcp dport { 22, 443 } accept\n }\n}\n'
            config.write_text('#!/usr/sbin/nft -f\nflush ruleset\n'+baseline); backup.write_bytes(config.read_bytes())
            self.firewall('snapshot', root, baseline, state)
            candidate.write_text(baseline.replace('22, 443', '22, 443, 8443'))
            self.firewall('intent', root, baseline, state, candidate)
            self.assertNotIn('flush ruleset', candidate.read_text()); self.assertIn('flush table inet filter', candidate.read_text())
            config.write_bytes(candidate.read_bytes()); active = baseline.replace('22, 443', '22, 443, 8443')
            self.firewall('restore', root, active, state, backup, output)
            self.assertNotIn('flush ruleset', output.read_text()); self.assertIn('22, 443', output.read_text())
            config.write_text(candidate.read_text()+'# administrator edit\n')
            with self.assertRaisesRegex(SystemExit, 'changed externally'): self.firewall('restore', root, active, state, backup, output)

    def test_firewall_canonicalization_detects_extra_rule_and_accepts_split_tcp_rules(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); config = root/'nftables.conf'
            source = 'table inet filter {\n chain input {\n type filter hook input priority 0;\n policy drop;\n iifname "lo" accept\n ct state invalid drop\n ct state established,related accept\n tcp dport { 22, 443 } accept\n tcp dport { 8443 } accept\n udp sport 67 udp dport 68 accept\n udp sport 547 udp dport 546 accept\n ip protocol icmp accept\n ip6 nexthdr ipv6-icmp accept\n }\n chain forward {\n type filter hook forward priority 0; policy drop;\n }\n chain output {\n type filter hook output priority 0; policy accept;\n }\n}\n'
            config.write_text('flush ruleset\n'+source); parameters = {'VPS_PARAM_TCP_PORTS': '22,443,8443', 'VPS_PARAM_RESTRICTED_PORT': ''}
            live = source.replace('priority 0', 'priority filter').replace('tcp dport { 8443 }', 'tcp dport 8443')
            self.firewall('check', root, live, parameters=parameters)
            numeric = live.replace('ct state invalid', 'ct state 0x1').replace('ct state established,related', 'ct state 0x2,0x4').replace('ip protocol icmp', 'ip protocol 1').replace('ip6 nexthdr ipv6-icmp', 'ip6 nexthdr 58')
            self.firewall('check', root, numeric, parameters=parameters)
            drift = live.replace('udp sport 67', 'tcp dport 9000 accept\n udp sport 67')
            with self.assertRaises(SystemExit): self.firewall('check', root, drift, parameters=parameters)
            config.write_text(drift)
            with self.assertRaisesRegex(SystemExit, 'managed archive'): self.firewall('check', root, drift, parameters=parameters)
            config.write_text(source)
            moved = live.replace(' tcp dport { 22, 443 } accept\n', '').replace('chain output {\n', 'chain output {\n tcp dport { 22, 443 } accept\n')
            with self.assertRaisesRegex(SystemExit, 'runtime has drifted'): self.firewall('check', root, moved, parameters=parameters)
            dropped = live.replace(' tcp dport 8443 accept', ' drop\n tcp dport 8443 accept')
            with self.assertRaisesRegex(SystemExit, 'runtime has drifted'): self.firewall('check', root, dropped, parameters=parameters)

    def test_basic_network_applies_only_selected_keys(self):
        if not BASH: self.skipTest('Bash unavailable')
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder)
            for relative in ('etc/sysctl.d', 'etc/systemd/system', 'usr/local/libexec', 'snapshot'): (root/relative).mkdir(parents=True)
            (root/'snapshot/network-state.json').write_text('{}')
            config = root/'etc/sysctl.d/99-mxh-vps-deploy.conf'
            config.write_text('# Managed by MXH VPS Deploy.\nnet.ipv4.tcp_fastopen = 3\nnet.ipv4.tcp_mtu_probing = 1\nnet.core.rmem_max = 16777216\n')
            source = (ROOT/'assets/remote/network-apply.sh').read_text(encoding='utf-8')
            for prefix in ('/etc', '/usr/local'): source = source.replace(prefix, shell_path(root)+prefix)
            source = re.sub(r"(<<'PY'\n)(.*?)(\nPY)", lambda m: m[1]+m[2].replace(shell_path(root), root.as_posix())+m[3], source, flags=re.S)
            preamble = '''python3(){ "$TEST_PYTHON" "$@"; }
modprobe(){ return 0; }
systemctl(){ return 0; }
mxh_network(){ return 0; }
sysctl(){
  if [[ "$1" == -p ]]; then echo 'unexpected broad replay' >&2; return 91; fi
  if [[ "$1" == -w ]]; then echo "$2" >> "$TEST_ROOT/applied"; return 0; fi
  case "$2" in
    net.ipv4.tcp_available_congestion_control) echo 'cubic bbr';;
    net.ipv4.tcp_congestion_control) [[ -f "$TEST_ROOT/applied" ]] && echo bbr || echo cubic;;
    net.core.default_qdisc) echo fq;;
    *) echo 'unexpected unselected query' >&2; return 92;;
  esac
}
'''
            env = dict(os.environ, TEST_ROOT=shell_path(root), TEST_PYTHON=shell_path(sys.executable), VPS_PARAM_EXPECTED_TRANSACTION=shell_path(root/'snapshot'), VPS_PARAM_PROFILE='EntryBasic')
            result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+source, capture_output=True, text=True, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root/'applied').read_text().splitlines(), ['net.core.default_qdisc=fq', 'net.ipv4.tcp_congestion_control=bbr'])
            self.assertIn('net.ipv4.tcp_fastopen = 3', config.read_text()); self.assertIn('net.core.rmem_max = 16777216', config.read_text())

    def test_measured_network_only_raises_send_ceiling(self):
        if not BASH: self.skipTest('Bash unavailable')
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder)
            for relative in ('etc/sysctl.d', 'etc/systemd/system', 'usr/local/libexec', 'snapshot'): (root/relative).mkdir(parents=True)
            (root/'snapshot/network-state.json').write_text('{}')
            config = root/'etc/sysctl.d/99-mxh-vps-deploy.conf'
            config.write_text('# Managed by MXH VPS Deploy.\nnet.core.rmem_max = 16777216\nnet.ipv4.tcp_rmem = 4096 131072 6291456\nnet.ipv4.tcp_fastopen = 3\n')
            source = (ROOT/'assets/remote/network-apply.sh').read_text(encoding='utf-8')
            for prefix in ('/etc', '/usr/local'): source = source.replace(prefix, shell_path(root)+prefix)
            source = re.sub(r"(<<'PY'\n)(.*?)(\nPY)", lambda m: m[1]+m[2].replace(shell_path(root), root.as_posix())+m[3], source, flags=re.S)
            preamble = '''python3(){ "$TEST_PYTHON" "$@"; }
modprobe(){ return 0; }
systemctl(){ return 0; }
mxh_network(){ return 0; }
sysctl(){
  if [[ "$1" == -w ]]; then echo "$2" >> "$TEST_ROOT/applied"; return 0; fi
  case "$2" in
    net.ipv4.tcp_available_congestion_control) echo 'cubic bbr';;
    net.ipv4.tcp_congestion_control) [[ -f "$TEST_ROOT/applied" ]] && echo bbr || echo cubic;;
    net.core.default_qdisc) echo fq;;
    net.ipv4.tcp_rmem) echo '4096 131072 6291456';;
    net.ipv4.tcp_wmem) echo '4096 16384 4194304';;
    net.core.rmem_max) echo 16777216;;
    net.core.wmem_max) echo 212992;;
    *) return 92;;
  esac
}
'''
            env = dict(os.environ, TEST_ROOT=shell_path(root), TEST_PYTHON=shell_path(sys.executable), VPS_PARAM_EXPECTED_TRANSACTION=shell_path(root/'snapshot'), VPS_PARAM_PROFILE='EntryMeasured', VPS_PARAM_BUFFER_TARGET_BYTES='25165824', VPS_PARAM_BUFFER_CAP_BYTES='33554432')
            result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble+source, capture_output=True, text=True, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root/'applied').read_text().splitlines(), ['net.core.default_qdisc=fq', 'net.ipv4.tcp_congestion_control=bbr', 'net.core.wmem_max=25165824', 'net.ipv4.tcp_wmem=4096 16384 25165824'])
            for unchanged in ('net.core.rmem_max = 16777216', 'net.ipv4.tcp_rmem = 4096 131072 6291456', 'net.ipv4.tcp_fastopen = 3'): self.assertIn(unchanged, config.read_text())

    def test_anytls_reinstall_reuses_only_verified_managed_certificate_layout(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder)
            for relative in ('etc/letsencrypt/renewal', 'etc/letsencrypt/live/mxh-anytls', 'etc/letsencrypt/archive/mxh-anytls', 'etc/mxh-tls/anytls', 'usr/local/libexec'):
                (root/relative).mkdir(parents=True)
            (root/'etc/letsencrypt/renewal/mxh-anytls.conf').write_text('version = 2.1.0\n[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = '+root.as_posix()+'/etc/letsencrypt/mxh-anytls-cloudflare.ini\n')
            runner = root/'usr/local/libexec/mxh-certbot-dns'; runner.write_text('#!/usr/bin/python3\n# MXH managed Cloudflare DNS API transport\n')
            for leaf in ('fullchain.pem', 'privkey.pem'):
                for directory in ('etc/letsencrypt/live/mxh-anytls', 'etc/letsencrypt/archive/mxh-anytls', 'etc/mxh-tls/anytls'): (root/directory/leaf).write_text('synthetic-certificate-data')
            code = (ROOT/'assets/remote/component-install-preflight.sh').read_text(encoding='utf-8').split("python3 <<'PY'\n", 1)[1].split('\nPY', 1)[0]
            code = re.sub(r'(?<![\w/])/(?:usr/local|usr/bin|etc|var/lib|opt|root|nonexistent)(?=/|[\'"\s])', lambda m: root.as_posix()+m[0], code)
            real_stat, real_resolve = Path.stat, Path.resolve
            def stat(path, *args, **kwargs):
                value = real_stat(path, *args, **kwargs)
                return types.SimpleNamespace(st_uid=0, st_mode=value.st_mode)
            def resolve(path, *args, **kwargs):
                if path.parent == root/'etc/letsencrypt/live/mxh-anytls': return root/'etc/letsencrypt/archive/mxh-anytls'/path.name
                return real_resolve(path, *args, **kwargs)
            def run(args, **kwargs):
                return subprocess.CompletedProcess(args, 0 if args[0] in ('ss', 'openssl') else 1, 'DNS:node.example.com, DNS:ech.example.com' if args[0] == 'openssl' else '', '')
            def preflight(domains):
                output = io.StringIO()
                with mock.patch.object(Path, 'stat', stat), mock.patch.object(Path, 'resolve', resolve), mock.patch.object(subprocess, 'run', run), mock.patch.dict(os.environ, {'VPS_PARAM_COMPONENT': 'AnyTlsEntry', 'VPS_PARAM_PORTS': '8443', 'VPS_PARAM_ANYTLS_DOMAINS': domains}), contextlib.redirect_stdout(output):
                    exec(compile(code, 'certificate-preflight', 'exec'), {})
                return json.loads(base64.b64decode(output.getvalue().split('=', 1)[1]))
            self.assertTrue(preflight('node.example.com,ech.example.com')['Allowed'])
            self.assertEqual(preflight('different.example.com,ech.example.com')['Code'], 'ComponentExists')
            runner.write_text('# foreign DNS runner\n')
            self.assertEqual(preflight('node.example.com,ech.example.com')['Code'], 'ComponentExists')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--bash'); options, remaining = parser.parse_known_args()
    BASH = options.bash
    unittest.main(argv=[sys.argv[0], *remaining])
