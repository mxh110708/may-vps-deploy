"""Real OpenSSL public-certificate reads in a private fixture, plus failure bounds."""
import copy
import base64
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('resource_certificates', ROOT / 'scripts/resource-certificates.py')
resource = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resource)


class CertificateResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which('openssl')
        if not cls.openssl:
            raise unittest.SkipTest('OpenSSL is required for actual public-certificate checks.')
        cls.temporary = tempfile.TemporaryDirectory(prefix='resource31-', dir=ROOT / '.tmp')
        cls.root = Path(cls.temporary.name)
        cls.certificate = cls.root / 'public.pem'
        key = cls.root / 'synthetic-key.pem'
        config = cls.root / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=subject\n[subject]\nCN=tls.example.test\n')
        result = subprocess.run([cls.openssl, 'req', '-new', '-newkey', 'rsa:2048', '-x509', '-nodes', '-days', '45',
                                 '-config', str(config),
                                 '-subj', '/CN=tls.example.test', '-addext', 'subjectAltName=DNS:tls.example.test,DNS:outer.example.test',
                                 '-keyout', str(key), '-out', str(cls.certificate)], capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Fixture public certificate generation failed.')
        cls.pem = cls.certificate.read_text()
        cls.id = 'a' * 32

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.calls = []
        self.fixture = tempfile.TemporaryDirectory(prefix='case-', dir=self.root)
        self.host = Path(self.fixture.name)
        self.request = {'Version': 1, 'Items': [{'Key': 'anytls', 'ServerNames': ['tls.example.test', 'outer.example.test']}]}
        self.put('/etc/mxh-tls/anytls/fullchain.pem', self.pem)

    def tearDown(self):
        self.fixture.cleanup()

    def put(self, logical, content):
        file = self.host.joinpath(*resource.PurePosixPath(logical).parts[1:])
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding='utf-8')
        return file

    def openssl_run(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[:2], ['openssl', 'x509'])
        self.assertEqual(kwargs['timeout'], 3)
        return subprocess.run([self.openssl, *args[1:]], **kwargs)

    def collect(self, value=None, runner=None):
        return resource.collect(value or self.request, self.host, runner or self.openssl_run)

    def test_actual_certificate_identity_names_dates_and_no_writes(self):
        before = {p.relative_to(self.host): p.read_bytes() for p in self.host.rglob('*') if p.is_file()}
        value = self.collect()
        item, = value['Items']
        self.assertEqual(item['Status'], 'Observed')
        self.assertTrue(item['HostnameMatches'])
        self.assertRegex(item['Sha256'], '^[a-f0-9]{64}$')
        self.assertLess(datetime.datetime.now(datetime.timezone.utc), datetime.datetime.fromisoformat(item['NotAfter']))
        self.assertEqual(before, {p.relative_to(self.host): p.read_bytes() for p in self.host.rglob('*') if p.is_file()})
        self.assertNotIn('PRIVATE KEY', json.dumps(value))
        self.assertNotIn('BEGIN CERTIFICATE', json.dumps(value))
        self.assertEqual(len(self.calls), 3)

    def test_hostname_mismatch_is_not_treated_as_success(self):
        self.request['Items'][0]['ServerNames'] = ['wrong.example.test']
        self.assertFalse(self.collect()['Items'][0]['HostnameMatches'])
        def misleading(args, **kwargs):
            result = self.openssl_run(args, **kwargs)
            if '-checkhost' in args:
                return subprocess.CompletedProcess(args, 0, b'Hostname wrong.example.test does NOT match certificate\n', b'')
            return result
        self.assertFalse(self.collect(runner=misleading)['Items'][0]['HostnameMatches'])

    def test_independent_singbox_and_xray_inline_certificate_consumers(self):
        for xray in [False, True]:
            with self.subTest(xray=xray):
                inbound = {'tag': self.id, 'streamSettings': {'security': 'tls', 'tlsSettings': {'certificates': [{'certificate': self.pem.splitlines(), 'key': ['synthetic-private-marker']}]}}} if xray else {'tag': self.id, 'tls': {'certificate': self.pem.splitlines(), 'key': ['synthetic-private-marker']}}
                self.put('/etc/may-inbounds/' + self.id + '.json', json.dumps({'inbounds': [inbound]}))
                value = self.collect({'Version': 1, 'Items': [{'Key': 'inbound:' + self.id, 'ServerNames': ['tls.example.test']}]})
                self.assertEqual(value['Items'][0]['Status'], 'Observed')
                self.assertNotIn('synthetic-private-marker', json.dumps(value))
                self.assertTrue(value['Items'][0]['HostnameMatches'])

    def test_missing_invalid_and_oversized_files_are_distinct_from_valid(self):
        file = self.host / 'etc/mxh-tls/anytls/fullchain.pem'
        file.unlink()
        self.assertEqual(self.collect()['Items'][0]['Status'], 'Missing')
        for content in ['broken PEM synthetic-secret', self.pem + '\n-----BEGIN ' + 'PRIVATE KEY-----\nsynthetic-secret', 'x' * (resource.LIMIT + 1)]:
            file.write_text(content)
            result = self.collect()
            self.assertEqual(result['Items'][0]['Status'], 'Unreadable')
            self.assertNotIn('synthetic-secret', json.dumps(result))

    def test_no_key_path_and_certificate_file_references_are_not_followed(self):
        for inbound in [{'tag': self.id, 'tls': {'certificate_path': str(self.root / 'synthetic-key.pem')}},
                        {'tag': self.id, 'tls': {'certificate': self.pem}, 'streamSettings': {'security': 'reality'}},
                        {'tag': 'b' * 32, 'tls': {'certificate': self.pem}}]:
            self.put('/etc/may-inbounds/' + self.id + '.json', json.dumps({'inbounds': [inbound]}))
            result = self.collect({'Version': 1, 'Items': [{'Key': 'inbound:' + self.id, 'ServerNames': ['tls.example.test']}]})
            self.assertEqual(result['Items'][0]['Status'], 'Unreadable')

    def test_timeouts_and_missing_tool_are_not_missing_certificate(self):
        def timed(*args, **kwargs):
            raise subprocess.TimeoutExpired(args, 3, stderr='synthetic-secret')
        def missing(*args, **kwargs):
            raise FileNotFoundError('synthetic-secret')
        for run in [timed, missing]:
            result = self.collect(runner=run)
            self.assertEqual(result['Items'][0], {'Key': 'anytls', 'Status': 'Unreadable'})
            self.assertNotIn('synthetic-secret', json.dumps(result))

    def test_unexpected_scope_path_and_host_inputs_are_rejected(self):
        variants = []
        for key in ['../../secret', 'inbound:../secret', 'inbound:' + 'a' * 31, 'reality/../../', '/etc/shadow']:
            value = copy.deepcopy(self.request); value['Items'][0]['Key'] = key; variants.append(value)
        for names in [[], ['-help'], ['ok.test', 'ok.test'], ['a.test', 'b.test', 'c.test'], ['a.test\nsecret'], [{}]]:
            value = copy.deepcopy(self.request); value['Items'][0]['ServerNames'] = names; variants.append(value)
        duplicate = copy.deepcopy(self.request); duplicate['Items'] *= 2; variants.append(duplicate)
        extra = copy.deepcopy(self.request); extra['Items'][0]['Path'] = '/etc/shadow'; variants.append(extra)
        too_many = copy.deepcopy(self.request); too_many['Items'] *= 19; variants.append(too_many)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.collect(value)
        self.assertEqual(self.calls, [])

    def test_linked_file_or_parent_is_not_followed(self):
        file = self.host / 'etc/mxh-tls/anytls/fullchain.pem'
        file.unlink()
        try:
            file.symlink_to(self.certificate)
        except OSError:
            self.skipTest('Host does not permit creating fixture symbolic links.')
        self.assertEqual(self.collect()['Items'][0]['Status'], 'Unreadable')
        file.unlink(); file.parent.rmdir(); file.parent.symlink_to(self.certificate.parent, target_is_directory=True)
        self.assertEqual(self.collect()['Items'][0]['Status'], 'Unreadable')
        self.assertEqual(self.calls, [])
        file.parent.unlink()

    def test_one_unreadable_consumer_does_not_hide_other_certificates(self):
        self.request['Items'].append({'Key': 'reality', 'ServerNames': ['tls.example.test']})
        result = self.collect()
        self.assertEqual([i['Status'] for i in result['Items']], ['Observed', 'Missing'])

    def test_cli_entrypoint_emits_only_public_result_markers(self):
        env = dict(os.environ, VPS_PARAM_CERTIFICATE_REQUEST=json.dumps({'Version': 1, 'Items': []}))
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/resource-certificates.py')], env=env, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.decode().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], 'VPSDEPLOY_RESOURCE_READ_OK')
        value = json.loads(base64.b64decode(lines[0].split('=', 1)[1]))
        self.assertEqual(value['Version'], 1)
        self.assertEqual(value['Items'], [])
        self.assertEqual(result.stderr, b'')


if __name__ == '__main__':
    unittest.main(verbosity=2)
