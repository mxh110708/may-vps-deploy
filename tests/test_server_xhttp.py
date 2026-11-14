import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_xhttp', ROOT / 'scripts/server-xhttp.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def peer():
    return {'tag': 'may-fixed-next-hop', 'protocol': 'vless', 'settings': {'vnext': [{'address': '192.0.2.35', 'port': 443, 'users': [{'id': str(uuid.uuid4()), 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'xhttp', 'security': 'tls', 'tlsSettings': {'serverName': 'next.example.test', 'allowInsecure': False, 'alpn': ['h2']},
                               'xhttpSettings': {'path': '/upload/?q=%2F', 'host': 'front.example.test', 'mode': 'packet-up', 'extra': {'headers': {'X-Private': 'synthetic-private-value'}, 'xmux': {'maxConcurrency': '4-8', 'maxConnections': 0}}}}}


class ServerXhttpTests(unittest.TestCase):
    def test_exact_runtime_version_required(self):
        for text in (b'Xray 26.3.26 synthetic', b'Xray 26.4.1 synthetic', b'Xray 26.3.270 synthetic', b'not Xray'):
            with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, text)):
                with self.assertRaises(ValueError): module.require_xhttp_binary('owned-core')
        with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'Xray 26.3.27 synthetic\n')):
            module.require_xhttp_binary('owned-core')
    def test_all_versions_and_modes_preserve_input(self):
        for alpn in ('http/1.1', 'h2', 'h3'):
            for mode in ('auto', 'stream-one', 'stream-up', 'packet-up'):
                item = peer(); item['streamSettings']['tlsSettings']['alpn'] = [alpn]; item['streamSettings']['xhttpSettings']['mode'] = mode
                before = copy.deepcopy(item)
                self.assertEqual(module.validate_xray_xhttp(item), ('192.0.2.35', 443))
                proof = module.xhttp_proof(item)
                self.assertEqual(proof['TransportAlpn'], alpn)
                self.assertEqual(item, before)
                self.assertNotIn('synthetic-private-value', json.dumps(proof))

    def split(self):
        item = peer(); down = copy.deepcopy(item['streamSettings']); down.update(address='2001:db8::35', port=8443)
        down['tlsSettings']['serverName'] = 'download.example.test'; down['tlsSettings']['alpn'] = ['h3']; down['xhttpSettings']['path'] = '/download/'
        item['streamSettings']['xhttpSettings']['extra']['downloadSettings'] = down
        return item, down

    def test_split_identity_and_field_order_digest(self):
        item, down = self.split(); original = module.xhttp_proof(item)
        down['tlsSettings']['serverName'] = 'changed.example.test'
        self.assertNotEqual(original['XhttpFingerprint'], module.xhttp_proof(item)['XhttpFingerprint'])
        self.assertEqual(module.xhttp_fingerprint({'b': ['梅', True, 3], 'a': '\\<+\n'}), module.xhttp_fingerprint({'a': '\\<+\n', 'b': ['梅', True, 3]}))

    def test_reality_upload_and_tls_download(self):
        item, down = self.split(); stream = item['streamSettings']; stream['security'] = 'reality'; del stream['tlsSettings']
        stream['realitySettings'] = {'serverName': 'reality.example.test', 'fingerprint': 'chrome', 'publicKey': 'A' * 43, 'shortId': 'ab12cd34'}
        self.assertEqual(module.xhttp_proof(item)['TransportAlpn'], 'h2')
        self.assertEqual(down['tlsSettings']['alpn'], ['h3'])

    def test_rejects_unknown_or_unverified_transport(self):
        mutations = [lambda n: n.update(proxySettings={'tag': 'other'}), lambda n: n['streamSettings'].update(sockopt={}),
                     lambda n: n['streamSettings']['tlsSettings'].update(allowInsecure=True), lambda n: n['streamSettings']['tlsSettings'].update(alpn=['h2', 'h3']),
                     lambda n: n['settings']['vnext'][0]['users'][0].update(flow='xtls-rprx-vision'),
                     lambda n: n['streamSettings']['xhttpSettings']['extra'].update(downloadSettings={}),
                     lambda n: n['streamSettings']['xhttpSettings']['extra'].update(headers={'Host': 'hidden.example.test'}),
                     lambda n: n['streamSettings']['xhttpSettings']['extra'].update(unknown=True),
                     lambda n: n['settings']['vnext'][0].update(port=True), lambda n: n['settings']['vnext'][0].update(address='example.test')]
        for mutate in mutations:
            item = peer(); mutate(item)
            with self.assertRaises((ValueError, TypeError)):
                module.validate_xray_xhttp(item)

    def test_rejects_nested_and_insecure_download(self):
        for damage in ('nested', 'insecure', 'stream-one', 'unknown', 'endpoint'):
            item, down = self.split()
            if damage == 'nested': down['xhttpSettings']['extra']['downloadSettings'] = copy.deepcopy(down)
            elif damage == 'insecure': down['tlsSettings']['allowInsecure'] = True
            elif damage == 'stream-one': item['streamSettings']['xhttpSettings']['mode'] = 'stream-one'
            elif damage == 'unknown': down['sockopt'] = {}
            else: down['address'] = 'download.example.test'
            with self.assertRaises(ValueError): module.validate_xray_xhttp(item)

    def test_metadata_requires_explicit_packet_up(self):
        item = peer(); item['streamSettings']['xhttpSettings']['extra'].update(uplinkHTTPMethod='GET', uplinkDataPlacement='header')
        module.validate_xray_xhttp(item)
        item['streamSettings']['xhttpSettings']['mode'] = 'stream-up'
        with self.assertRaises(ValueError): module.validate_xray_xhttp(item)


if __name__ == '__main__':
    unittest.main()
