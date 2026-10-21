"""Portable validation boundaries for the remote multi-hop acceptance probe."""
import argparse
import copy
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSET = (ROOT / 'assets/remote/server-hop-probe.sh').read_text(encoding='utf-8')
PROGRAM = ASSET.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
API = {'__name__': 'probe_fixture'}
exec(compile(PROGRAM, 'server-hop-probe.sh:embedded-python', 'exec'), API)
BASH = None


def item():
    return {'Id': '0123456789abcdef', 'ExpectedAddress': '198.51.100.21', 'Outbound': {
        'type': 'shadowsocks', 'tag': 'may-hop-0123456789abcdef', 'server': '192.0.2.21',
        'server_port': 20001, 'method': 'aes-128-gcm', 'password': 'synthetic-only'}}


class ProbeBoundaries(unittest.TestCase):
    def test_valid_shadowsocks_and_ss2022(self):
        for method in ('aes-128-gcm', 'aes-256-gcm', '2022-blake3-aes-128-gcm'):
            probe = item()
            probe['Outbound']['method'] = method
            API['validate']([probe], 'AnyTlsEntry')

    def test_scope_and_bounds(self):
        for value in (None, {}, [], [item()] * 8):
            with self.assertRaises(ValueError):
                API['validate'](value, 'AnyTlsEntry')
        with self.assertRaises(ValueError):
            API['validate']([item()], 'ShadowsocksLanding')

    def test_duplicate_or_foreign_identity(self):
        with self.assertRaises(ValueError):
            API['validate']([item(), item()], 'AnyTlsEntry')
        for key, value in (('Id', 'foreign'), ('ExpectedAddress', 'example.test')):
            probe = item()
            probe[key] = value
            with self.assertRaises(ValueError):
                API['validate']([probe], 'AnyTlsEntry')
        probe = item()
        probe['Outbound']['tag'] = 'direct'
        with self.assertRaises(ValueError):
            API['validate']([probe], 'AnyTlsEntry')

    def test_no_plugins_or_native_injection(self):
        for key, value in (('plugin', 'external'), ('detour', 'direct'), ('bind_interface', 'eth0')):
            probe = item()
            probe['Outbound'][key] = value
            with self.assertRaises(ValueError):
                API['validate']([probe], 'AnyTlsEntry')

    def test_invalid_parameters(self):
        for key, value in (('server_port', True), ('server_port', 0), ('server_port', 65536),
                           ('method', 'none'), ('password', ''), ('server', 'example.test')):
            probe = item()
            probe['Outbound'][key] = value
            with self.assertRaises(ValueError):
                API['validate']([probe], 'AnyTlsEntry')

    def test_xray_parameters(self):
        probe = item()
        probe['Outbound'] = {'tag': probe['Outbound']['tag'], 'protocol': 'shadowsocks', 'settings': {
            'servers': [{'address': '192.0.2.21', 'port': 20001, 'method': 'aes-128-gcm', 'password': 'synthetic-only'}]}}
        API['validate']([probe], 'RealityEntry')
        for transform in (lambda p: p['Outbound']['settings']['servers'].append(copy.deepcopy(p['Outbound']['settings']['servers'][0])),
                          lambda p: p['Outbound'].update(streamSettings={'sockopt': {'mark': 1}})):
            changed = copy.deepcopy(probe)
            transform(changed)
            with self.assertRaises(ValueError):
                API['validate']([changed], 'RealityEntry')

    def test_bash_wrapper_refuses_missing_binary_and_invalid_role(self):
        if not BASH:
            self.skipTest('Bash unavailable')
        with tempfile.TemporaryDirectory(prefix='probe-guards-', dir=ROOT / '.test-output') as temp:
            path = Path(temp)
            target = path.as_posix()
            if re.match(r'^[A-Za-z]:/', target):
                target = '/' + target[0].lower() + target[2:]
            source = ASSET.replace('/usr/local', target + '/usr/local')
            script = path / 'fixture.sh'
            script.write_text(source, encoding='utf-8', newline='\n')
            for role in ('AnyTlsEntry', 'RealityEntry', 'Other'):
                result = subprocess.run([BASH, str(script)], env=dict(os.environ, VPS_PARAM_ROLE=role, VPS_PARAM_PROBES_JSON='[]'), capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'PASSED', result.stdout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bash')
    args, rest = parser.parse_known_args()
    BASH = args.bash
    (ROOT / '.test-output').mkdir(exist_ok=True)
    unittest.main(argv=[__file__, *rest])
