"""Inspect native QUIC client sources without conversion or credential loss."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


class ClientSourcesTests(unittest.TestCase):
    def test_quic_native_formats(self):
        from ruamel.yaml import YAML
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for protocol in ('hysteria2', 'tuic'):
                clash = {'name': protocol, 'type': protocol, 'server': '192.0.2.1', 'port': 443,
                         'password': 'synthetic-client-source', 'sni': 'example.test',
                         'udp': True, 'alpn': ['h3']}
                sing = {'tag': protocol, 'type': protocol, 'server': '192.0.2.1', 'server_port': 443,
                        'password': 'synthetic-client-source', 'tls': {'enabled': True, 'server_name': 'example.test', 'alpn': ['h3']}}
                if protocol == 'tuic':
                    clash['uuid'] = sing['uuid'] = str(uuid.uuid4())
                    clash['congestion-controller'] = sing['congestion_control'] = 'bbr'
                else:
                    clash['ports'] = '8443-8445'
                    sing['server_ports'] = ['8443:8445']
                    clash['obfs'], clash['obfs-password'] = 'salamander', 'synthetic-obfs'
                    sing['obfs'] = {'type': 'salamander', 'password': 'synthetic-obfs'}
                yaml, config = root / 'source.yaml', root / 'source.json'
                with yaml.open('w', encoding='utf-8') as stream:
                    YAML().dump({'proxies': [clash]}, stream)
                config.write_text(json.dumps({'outbounds': [sing]}), encoding='utf-8')
                for arguments in (['--clash', str(yaml)], ['--sing-box', str(config)], ['--clash', str(yaml), '--sing-box', str(config)]):
                    with self.subTest(protocol=protocol, arguments=arguments[::2]):
                        result = subprocess.run([sys.executable, str(ROOT / 'scripts/inspect_client_sources.py'), *arguments], capture_output=True, text=True, timeout=10, check=True)
                        nodes = json.loads(result.stdout)
                        self.assertEqual(len(nodes), 1)
                        self.assertEqual(nodes[0]['kind'], 'entry')
                        if '--clash' in arguments:
                            self.assertEqual(nodes[0]['clash'], clash)
                        if '--sing-box' in arguments:
                            self.assertEqual(nodes[0]['sing_box'], sing)


if __name__ == '__main__':
    unittest.main()
