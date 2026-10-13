"""DNS API source binding remains local to the Certbot process and hostname."""
import socket
import configparser
import sys
import types
import tempfile
import pathlib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "assets/remote/certbot-dns-setup.sh").read_text(encoding="utf-8")
RUNNER = SCRIPT.split("<<'RUNNER'\n", 1)[1].split("\nRUNNER\n", 1)[0]
RENEWAL = SCRIPT.split("<<'RENEWAL'\n", 1)[1].split("\nRENEWAL\n", 1)[0]


class CertbotSourceTests(unittest.TestCase):
    def run_runner(self, source, invalid=False, argv=None, path_factory=None):
        calls = {"resolve": [], "connect": []}
        def resolve(*args):
            calls["resolve"].append(args)
            return []
        def connect(address, timeout=None, source_address=None, socket_options=None):
            calls["connect"].append((address, timeout, source_address, socket_options))
            return "connection"
        connection = types.ModuleType("urllib3.util.connection")
        connection.create_connection = connect
        util = types.ModuleType("urllib3.util")
        util.connection = connection
        certbot_main = types.ModuleType("certbot.main")
        def main():
            socket.getaddrinfo("api.cloudflare.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            socket.getaddrinfo("API.CLOUDFLARE.COM.", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            socket.getaddrinfo("acme-v02.api.letsencrypt.org", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            socket.getaddrinfo("api.cloudflare.com", 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            connection.create_connection(("api.cloudflare.com", 443), 7, None, [])
            connection.create_connection(("acme-v02.api.letsencrypt.org", 443), 8, ("127.0.0.2", 0), [])
            connection.create_connection(("api.cloudflare.com.example.org", 443), 9, None, [])
            connection.create_connection(("api.cloudflare.com", 443), timeout=10)
            return 0
        certbot_main.main = main
        modules = {"urllib3.util": util, "urllib3.util.connection": connection,
                   "certbot": types.ModuleType("certbot"), "certbot.main": certbot_main}
        with patch.dict(sys.modules, modules), patch.object(socket, "getaddrinfo", resolve), patch.object(sys, 'argv', argv or ['runner', 'certonly']), patch.object(pathlib, 'Path', path_factory or Path):
            if invalid:
                with self.assertRaises(ValueError):
                    exec(compile(RUNNER, "mxh-certbot-dns", "exec"), {"DNS_API_SOURCE": source})
            else:
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(RUNNER, "mxh-certbot-dns", "exec"), {"DNS_API_SOURCE": source})
                self.assertEqual(stopped.exception.code, 0)
        return calls

    def test_ipv4_preflight_source_is_used_for_dns_api(self):
        calls = self.run_runner("192.0.2.10")
        self.assertEqual(calls["resolve"][0][2], socket.AF_INET)
        self.assertEqual(calls["resolve"][1][2], socket.AF_INET)
        self.assertEqual(calls["connect"][0][2], ("192.0.2.10", 0))

    def test_ipv6_preflight_source_is_used_for_dns_api(self):
        calls = self.run_runner("2001:db8::10")
        self.assertEqual(calls["resolve"][0][2], socket.AF_INET6)
        self.assertEqual(calls["connect"][0][2], ("2001:db8::10", 0))

    def test_acme_and_other_hosts_keep_their_original_transport(self):
        calls = self.run_runner("192.0.2.10")
        self.assertEqual(calls["resolve"][2][2], socket.AF_UNSPEC)
        self.assertEqual(calls["connect"][1][2], ("127.0.0.2", 0))
        self.assertIsNone(calls["connect"][2][2])

    def test_socket_keywords_and_connection_defaults_are_preserved(self):
        calls = self.run_runner("192.0.2.10")
        self.assertEqual(calls["resolve"][3][2], socket.AF_INET)
        self.assertEqual(calls["connect"][3][1:3], (10, ("192.0.2.10", 0)))

    def test_invalid_source_is_rejected_before_any_request(self):
        calls = self.run_runner("not-an-address", invalid=True)
        self.assertEqual(calls, {"resolve": [], "connect": []})

    def test_each_credential_retains_its_own_dns_source_after_append(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); (root/'renewal').mkdir()
            for name, credentials, address in [('mxh-reality-target', 'cloudflare.ini', '2001:db8::10'), ('mxh-anytls', 'mxh-anytls-cloudflare.ini', '192.0.2.10')]:
                (root/'renewal'/f'{name}.conf').write_text(f'version = 2.1.0\n[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = /etc/letsencrypt/{credentials}\n')
                (root/(credentials+'.mxh-source')).write_text(address+'\n')
            class FixturePath:
                def __init__(self, value): self.path = Path(str(value).replace('/etc/letsencrypt', str(root)))
                def is_symlink(self): return self.path.is_symlink()
                @property
                def name(self): return self.path.name
                @property
                def parents(self): return self.path.parents
                def exists(self): return self.path.exists()
                def read_text(self): return self.path.read_text()
                def stat(self): return types.SimpleNamespace(st_uid=0, st_mode=0o100600)
            old = self.run_runner(None, argv=['runner', 'renew', '--cert-name', 'mxh-reality-target'], path_factory=FixturePath)
            new = self.run_runner(None, argv=['runner', 'renew', '--cert-name', 'mxh-anytls'], path_factory=FixturePath)
            self.assertEqual(old['connect'][0][2], ('2001:db8::10', 0))
            self.assertEqual(new['connect'][0][2], ('192.0.2.10', 0))
            self.assertEqual(old['resolve'][0][2], socket.AF_INET6); self.assertEqual(new['resolve'][0][2], socket.AF_INET)

    def test_batch_renewal_uses_one_child_per_lineage_and_reports_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder)
            for name in ('mxh-anytls', 'mxh-reality-target'): (root/(name+'.conf')).write_text('fixture')
            class FixturePath:
                def __init__(self, value): self.path = root if str(value) == '/etc/letsencrypt/renewal' else Path(value)
                def glob(self, pattern): return self.path.glob(pattern)
            import subprocess
            with patch.object(pathlib, 'Path', FixturePath), patch.object(sys, 'argv', ['runner', 'renew', '--quiet']), patch.object(subprocess, 'run', side_effect=[types.SimpleNamespace(returncode=0), types.SimpleNamespace(returncode=1)]) as children:
                with self.assertRaises(SystemExit) as stopped: exec(compile(RUNNER, 'runner', 'exec'), {})
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual([call.args[0][-2:] for call in children.call_args_list], [['--cert-name', 'mxh-anytls'], ['--cert-name', 'mxh-reality-target']])

    def renewal_fixture(self, root, credentials):
        code = RENEWAL.replace('/etc/letsencrypt', root.as_posix())
        actual_stat = Path.stat
        def root_stat(path, *args, **kwargs):
            value = actual_stat(path, *args, **kwargs)
            return types.SimpleNamespace(st_uid=0, st_mode=value.st_mode)
        with patch.object(Path, 'stat', root_stat), patch.object(sys, 'argv', ['renewal', 'mxh-anytls', (root/credentials).as_posix()]):
            exec(compile(code, 'renewal-update', 'exec'), {})

    def test_reinstall_rebinds_only_selected_lineage_and_preserves_other_parameters(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); (root/'renewal').mkdir()
            original = 'version = 2.1.0\narchive_dir = /preserved/archive\n[renewalparams]\nauthenticator = dns-cloudflare\ndns_cloudflare_credentials = '+(root/'cloudflare.ini').as_posix()+'\nserver = https://acme.example/directory\n'
            selected = root/'renewal/mxh-anytls.conf'; selected.write_text(original)
            other = root/'renewal/mxh-reality-target.conf'; other.write_text(original)
            self.renewal_fixture(root, 'mxh-anytls-cloudflare.ini')
            self.assertEqual(selected.read_text(), original.replace((root/'cloudflare.ini').as_posix(), (root/'mxh-anytls-cloudflare.ini').as_posix()))
            self.assertEqual(other.read_text(), original)
            self.assertFalse((root/'renewal/mxh-anytls.mxh-write').exists())

    def test_reinstall_rejects_unmanaged_or_ambiguous_renewal_without_writing(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.tmp') as folder:
            root = Path(folder); (root/'renewal').mkdir(); selected = root/'renewal/mxh-anytls.conf'
            for body in ('authenticator = manual\ndns_cloudflare_credentials = '+(root/'cloudflare.ini').as_posix(),
                         'authenticator = dns-cloudflare\ndns_cloudflare_credentials = /foreign/credentials',
                         'authenticator = dns-cloudflare\ndns_cloudflare_credentials = '+(root/'cloudflare.ini').as_posix()+'\ndns_cloudflare_credentials = '+(root/'cloudflare.ini').as_posix()):
                original = 'version = 2.1.0\n[renewalparams]\n'+body+'\n'; selected.write_text(original)
                with self.assertRaises((SystemExit, ValueError, configparser.Error)):
                    self.renewal_fixture(root, 'mxh-anytls-cloudflare.ini')
                self.assertEqual(selected.read_text(), original)


if __name__ == "__main__":
    unittest.main()
