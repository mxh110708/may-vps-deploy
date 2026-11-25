"""Credential boundary and transaction fixtures. Real protocols use the owned VM test."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_forward_target_groups as fixture
from test_tcp_forwarding import BACKUP, Kernel

G, TCP = fixture.GROUP, fixture.TCP


def rule(udp=False):
    r = fixture.rule('Echo' if udp else 'Ssh')
    r['Validation'] = dict(Type='Shadowsocks' if udp else 'Proxy', SchemeId='c' * 32, NodeId='d' * 32, NodeFingerprint='e' * 64)
    if udp:
        r['Validation'].update(QueryName='example.test', QueryType='A', ResolverAddress='192.0.2.53', ResolverPort=53)
    r['TargetGroup']['Health'] = dict(Type='Proxy', Consent=True, EgressFamily='IPv4', PrimaryExit='', BackupExit='')
    return r


def document(r):
    return dict(Version=1, Core=dict(Engine='sing-box', Version='1.14.2', Artifact='sing-box-1.14.2-linux-amd64.tar.gz', Sha256='b' * 64),
                Rules={r['Id']: dict(RuleFingerprint=G.group_fingerprint(r), NodeFingerprint=r['Validation']['NodeFingerprint'], Outbound=dict(type='shadowsocks', server=r['TargetAddress'], server_port=r['TargetPort'], method='2022-blake3-aes-128-gcm', password=base64.b64encode(b'synthetic key40!').decode()))})


class ProxyHealthModel(unittest.TestCase):
    def test_consent_and_transport_are_explicit(self):
        for udp in (False, True):
            r = rule(udp)
            self.assertEqual(G.normalize_group(r, 'UDP' if udp else 'TCP')['Health']['Type'], 'Proxy')
            for key, value in [('Consent', False), ('Consent', 'true'), ('EgressFamily', 'Auto'), ('PrimaryExit', '127.0.0.1'), ('BackupExit', '2001:db8::1'), ('SkipTls', True)]:
                bad = copy.deepcopy(r); bad['TargetGroup']['Health'][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError): G.normalize_group(bad, 'UDP' if udp else 'TCP')
            with self.assertRaises(ValueError): G.normalize_group(r, 'QUIC')

    def test_service_uses_per_rule_credential_and_resource_caps(self):
        r = rule()
        unit = G.target_group_service(r, TCP.CONFIG, 'TCP')
        self.assertIn('/probe-' + r['Id'] + '.json', unit)
        self.assertNotIn('proxy-health.json', unit)
        self.assertIn('DynamicUser=yes', unit)
        self.assertIn('MemoryMax=160M', unit)
        self.assertIn('TasksMax=48', unit)
        self.assertNotIn(document(r)['Rules'][r['Id']]['Outbound']['password'], unit)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'isolated Linux root filesystem fixture')
class PrivateMaterial(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='may-health40-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.kernel = Kernel(self.root); self.host = TCP.Host(self.root, self.kernel)
        for path in ['/lib/systemd/systemd-socket-proxyd', '/usr/sbin/nft']:
            p = self.host.path(path); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'synthetic executable'); p.chmod(0o755)
        self.rule = rule(); self.config = dict(Version=1, Rules=[self.rule]); self.doc = document(self.rule)
        binary = self.host.path(G.proxy_core_path(self.doc['Core'])); binary.parent.mkdir(parents=True); binary.write_bytes(b'fixture core bytes'); binary.chmod(0o755)
        self.doc['Core']['BinarySha256'] = G.proxy_digest(binary.read_bytes())
        (binary.parent / 'core.json').write_text(json.dumps(dict(Managed='MayForwardProbe.v1', ArchiveSha256=self.doc['Core']['Sha256'], Version=self.doc['Core']['Version'], BinarySha256=self.doc['Core']['BinarySha256'])))
        (binary.parent / 'core.json').chmod(0o644)

    def material(self, doc=None):
        return self.host.auxiliary(self.config, payload=doc or self.doc)

    def seed(self):
        files = self.host.material(self.config, self.host.proxy()); files.update(self.material())
        for name, data in files.items(): self.host.write(name, data)
        self.host.activate(self.config)
        return self.host.read()

    def test_private_sidecars_and_individual_credential_scope(self):
        self.seed()
        for name in self.material(): self.assertEqual(self.host.path(name).stat().st_mode & 0o777, 0o600)
        side = json.loads(self.host.path(self.host.DIRECTORY + '/probe-' + self.rule['Id'] + '.json').read_text())
        self.assertEqual(set(side['Rules']), {self.rule['Id']})
        result = self.host.read()
        self.assertNotIn('password', json.dumps(result))

    def test_mismatched_rule_source_endpoint_and_unknown_fields_are_rejected(self):
        for key, value in [('RuleFingerprint', 'f' * 64), ('NodeFingerprint', 'f' * 64), ('Other', True)]:
            bad = copy.deepcopy(self.doc); bad['Rules'][self.rule['Id']][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.material(bad)
        bad = copy.deepcopy(self.doc); bad['Rules'][self.rule['Id']]['Outbound']['server'] = '192.0.2.22'
        with self.assertRaises(ValueError): self.material(bad)

    def test_private_permission_core_drift_and_symlinks_are_rejected(self):
        self.seed(); path = self.host.path(self.host.DIRECTORY + '/probe-' + self.rule['Id'] + '.json')
        path.chmod(0o644)
        with self.assertRaises(ValueError): self.host.read()
        path.chmod(0o600); raw = path.read_bytes(); path.unlink(); path.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): self.host.read()
        path.unlink(); path.write_bytes(raw); path.chmod(0o600)
        self.host.path(G.proxy_core_path(self.doc['Core'])).write_bytes(b'foreign executable')
        with self.assertRaises(ValueError): self.host.read()

    def test_remove_and_scoped_restore_preserve_original_credential_bytes(self):
        import tarfile
        before = self.seed(); backup = self.host.path(str(BACKUP)); backup.mkdir(parents=True)
        self.host.snapshot(backup, before['Hash'])
        with tarfile.open(backup / 'protocol-files.tar.gz', 'w:gz') as tar:
            for path in before['Files']: tar.add(self.host.path(path), arcname=path.lstrip('/'))
        self.host.apply(dict(Version=1, Rules=[]), before['Hash'], 'Remove', BACKUP)
        self.assertEqual(self.host.read()['Hash'], 'Absent')
        self.host.rollback_prepare(BACKUP)
        with tarfile.open(backup / 'protocol-files.tar.gz') as tar:
            for member in tar.getmembers():
                p = self.host.path('/' + member.name); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(tar.extractfile(member).read()); p.chmod(member.mode)
        self.host.rollback_complete(BACKUP)
        self.assertEqual(self.host.read()['Hash'], before['Hash'])

    def test_address_transaction_refreshes_private_references_and_restores_exact_bytes(self):
        from test_instance_address import address
        before = self.seed(); mapping = {'192.0.2.20': '192.0.2.22'}
        after = address.rewrite(self.config, mapping)
        health = address.rewrite(self.doc, mapping)
        health['Rules'][self.rule['Id']]['RuleFingerprint'] = G.group_fingerprint(after['Rules'][0])
        resource = dict(Kind='TcpForwarding', Component='TcpForwarding', ExpectedHash=before['Hash'], Before=self.config, After=after, AfterProbeHealth=health)
        d = dict(Task='f' * 32, Addresses=mapping, Resources=[resource])
        host = lambda: address.AddressHost(copy.deepcopy(d), self.root, self.kernel)
        host().inspect(); host().prepare(); host().apply('Bridge'); host().apply('Apply'); host().apply('Finalize')
        self.assertTrue(host().status()['Consistent'])
        self.assertEqual(json.loads(self.host.path(self.host.DIRECTORY + '/proxy-health.json').read_text())['Rules'][self.rule['Id']]['Outbound']['server'], '192.0.2.22')
        self.assertTrue(host().rollback()['Consistent'])
        self.assertEqual(self.host.read()['Hash'], before['Hash'])

    def test_modified_embedded_program_requires_original_archive_pin(self):
        before = self.seed(); program = self.host.path('/etc/may-tcp-forward/group-worker.py'); program.write_bytes(program.read_bytes() + b'\n# old synthetic revision\n')
        with self.assertRaises(ValueError): self.host.read()
        identity = self.host.identity(before['Files']); expected = TCP.digest(TCP.encoded(dict(identity, Units=before['Units'])))
        self.host.archived_hash = expected
        self.assertFalse(self.host.read()['TemplateCurrent'])
        program.write_bytes(program.read_bytes() + b'# unexpected external edit\n')
        with self.assertRaises(ValueError): self.host.read()

    def test_bad_download_digest_and_plaintext_redirect_leave_no_executable(self):
        core = copy.deepcopy(self.doc['Core']); core['Sha256'] = 'f' * 64; core.pop('BinarySha256')
        class Response:
            url = 'https://example.test/synthetic-fixed-core'
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return b'incorrect synthetic archive bytes'
        for url in ('https://example.test/synthetic-fixed-core', 'http://example.test/untrusted'):
            response = Response(); response.url = url
            with patch.object(G.urllib.request, 'urlopen', return_value=response), self.assertRaises(ValueError): G.proxy_ensure_core(self.host, core)
            self.assertFalse(self.host.path(G.proxy_core_path(core)).exists())
            self.assertEqual(list(self.host.path(G.PROXY_CORE_ROOT).glob('.stage-*')), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
