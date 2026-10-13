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
import unittest
import types
from unittest import mock

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from build_client_authority import replace_named, update_node_references, validate_rendered_references

BASH = None
FIREWALL = (ROOT/'assets/remote/firewall-tools.sh').read_text(encoding='utf-8').split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]

def shell_path(path):
    value = Path(path).as_posix()
    return '/'+value[0].lower()+value[2:] if os.name == 'nt' and value[1:2] == ':' else value

class ReviewRepairs(unittest.TestCase):
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
