"""Isolated CA/key validation and scoped certificate deployment, no public DNS."""
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('managed_certificates', REPOSITORY / 'scripts/managed-certificates.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
OPENSSL = r'D:\Program Files\Git\usr\bin\openssl.exe' if os.name == 'nt' and Path(r'D:\Program Files\Git\usr\bin\openssl.exe').exists() else shutil.which('openssl')
IDENTIFIER = 'a' * 32
BACKUP = '/root/vps-deploy-backups/20261112-010203/protocol-lifecycle'
POLICY = {'Provider': 'Cloudflare', 'Zone': 'example.test', 'Email': 'operator@example.test', 'Domains': ['service.example.test'], 'PropagationSeconds': 30}


class Fixture(M.Host):
    def __init__(self, root, ca, certificate, private_key):
        super().__init__(root, self.execute)
        self.ca, self.certificate, self.private_key = ca, certificate, private_key
        self.states = {}; self.events = []; self.acquisitions = 0; self.fail_restart = None; self.fail_acquire = False

    def execute(self, arguments, **kwargs):
        if arguments[0] == 'openssl':
            arguments = [OPENSSL, *arguments[1:]]
            if arguments[1] == 'verify':
                i = arguments.index('-CApath'); arguments[i:i+2] = ['-CAfile', str(self.ca)]
            return subprocess.run(arguments, **kwargs)
        if arguments[0] != 'systemctl':
            raise AssertionError('Unexpected external command')
        action = arguments[1]; name = arguments[-1] if action != 'show' else arguments[2]
        state = self.states.setdefault(name, {'active': False, 'enabled': False})
        code, output = 0, b''
        if action == 'show': output = ('/etc/systemd/system/' + name if 'FragmentPath' in arguments else '').encode()
        elif action == 'is-active': code = 0 if state['active'] else 3
        elif action == 'is-enabled': code = 0 if state['enabled'] else 1
        elif action in ('enable', 'disable'):
            state['enabled'] = action == 'enable'
            if '--now' in arguments: state['active'] = action == 'enable'
            self.events.append((action, name))
        elif action == 'restart':
            self.events.append((action, name)); state['active'] = True
            if self.fail_restart == name:
                self.fail_restart = None; state['active'] = False; code = 1
        elif action != 'daemon-reload': raise AssertionError(action)
        return subprocess.CompletedProcess(arguments, code, output, b'')

    def acquire(self, identifier, settings, token):
        self.acquisitions += 1
        if self.fail_acquire: raise ValueError('simulated acquisition failure')
        return self.certificate, self.private_key, b'{}'

    def authorize(self, settings, token):
        if token == 'bad' * 15: raise ValueError('simulated authorization failure')


@unittest.skipUnless(OPENSSL, 'OpenSSL required for real certificate checks')
class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='may-cert33-ca-'); p = Path(cls.temp.name).resolve()
        def run(*args): subprocess.run([OPENSSL, *map(str, args)], check=True, capture_output=True)
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', p/'ca.key', '-out', p/'ca.pem', '-days', '90', '-subj', '/CN=Round33 Isolated CA')
        (p/'extensions.cnf').write_text('subjectAltName=DNS:service.example.test,DNS:*.example.test\nextendedKeyUsage=serverAuth\n')
        for name in ('old', 'new'):
            run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', p/(name+'.key'), '-out', p/(name+'.csr'), '-subj', '/CN=service.example.test')
            run('x509', '-req', '-in', p/(name+'.csr'), '-CA', p/'ca.pem', '-CAkey', p/'ca.key', '-CAcreateserial', '-out', p/(name+'.pem'), '-days', '10' if name == 'old' else '60', '-extfile', p/'extensions.cnf')
        cls.material = p

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='may-cert33-host-'); self.root = Path(self.temp.name).resolve()
        self.host = Fixture(self.root, self.material/'ca.pem', (self.material/'old.pem').read_bytes(), (self.material/'old.key').read_bytes())
        self.directory = M.ROOT + '/' + IDENTIFIER
        os.environ['VPS_CERTIFICATE_PROGRAM'] = '# isolated acquisition adapter fixture\n'

    def tearDown(self): self.temp.cleanup()

    def request(self, action='Issue'):
        return dict(Action=action, CertificateId=IDENTIFIER, Name='Isolated certificate', Policy=POLICY, ExpectedCertificateHash=self.host.observe(IDENTIFIER)['Hash'], Token='x'*40)

    def issue(self):
        request = self.request(); self.host.snapshot(BACKUP, IDENTIFIER, 'Absent'); return self.host.operate(BACKUP, request)

    def consumer(self, identifier, enabled=True):
        config = {'inbounds': [{'tag': identifier, 'tls': {'certificate_path': '/run/credentials/may-inbound-'+identifier+'.service/certificate.pem', 'key_path': '/run/credentials/may-inbound-'+identifier+'.service/certificate.key'}}]}
        path = '/etc/may-inbounds/'+identifier+'.json'; self.host.write(path, M.encoded(config).encode())
        unit = '/etc/systemd/system/may-inbound-'+identifier+'.service'
        text = '# owned fixture\n' + ''.join('LoadCredential='+name+':'+self.directory+'/'+source+'\n' for name, source in (('certificate.pem','fullchain.pem'),('certificate.key','privkey.pem')))
        self.host.write(unit, text.encode())
        name = 'may-inbound-'+identifier+'.service'; self.host.states[name] = {'active': enabled, 'enabled': enabled}
        registry_file = '/etc/may-inbounds/model.json'
        registry = json.loads(self.host.read(registry_file)) if self.host.path(registry_file).exists() else {'Model': {'Inbounds': []}, 'Bindings': []}
        registry['Model']['Inbounds'].append({'Id': identifier, 'CertificateId': IDENTIFIER, 'Protocol': 'AnyTLS', 'Enabled': enabled, 'Options': {'ServerName': 'service.example.test'}})
        registry['Bindings'].append({'Id': identifier, 'Sha256': M.digest(self.host.read(path))})
        self.host.write(registry_file, M.encoded(registry).encode()); return name

    def test_issue_and_independent_ownership(self):
        self.host.write('/etc/letsencrypt/unmanaged.txt', b'preserve')
        result = self.issue()
        self.assertNotEqual(result['Hash'], 'Absent'); self.assertTrue(result['State']['Enabled'])
        self.assertEqual(self.host.read('/etc/letsencrypt/unmanaged.txt'), b'preserve')
        self.assertTrue(self.host.states[M.service(IDENTIFIER)+'.timer']['active'])
        self.assertNotIn(b'x'*40, self.host.read(self.directory+'/state.json'))
        self.assertTrue(self.host.verify(self.host.certificate, self.host.private_key, ['*.example.test']))

    def test_shared_renewal_preserves_disabled_and_other_services(self):
        self.issue(); active = self.consumer('b'*32); disabled = self.consumer('c'*32, False)
        self.host.events.clear(); self.host.certificate = (self.material/'new.pem').read_bytes(); self.host.private_key = (self.material/'new.key').read_bytes()
        self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash'])
        result = self.host.operate(BACKUP, self.request('Renew'))
        self.assertIn(('restart', active), self.host.events)
        self.assertNotIn(('restart', disabled), self.host.events)
        self.assertFalse(self.host.states[disabled]['active']); self.assertNotEqual(result['State']['Sha256'], self.host.verify((self.material/'old.pem').read_bytes(), (self.material/'old.key').read_bytes(), POLICY['Domains'])['Sha256'])

    def test_failed_service_restores_old_pair(self):
        self.issue(); active = self.consumer('b'*32)
        old = self.host.read(self.directory+'/fullchain.pem'); old_key = self.host.read(self.directory+'/privkey.pem')
        self.host.certificate = (self.material/'new.pem').read_bytes(); self.host.private_key = (self.material/'new.key').read_bytes(); self.host.fail_restart = active
        self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash'])
        with self.assertRaises(ValueError): self.host.operate(BACKUP, self.request('Renew'))
        self.assertEqual(self.host.read(self.directory+'/fullchain.pem'), old); self.assertEqual(self.host.read(self.directory+'/privkey.pem'), old_key)
        self.assertTrue(self.host.states[active]['active']); self.assertFalse(self.host.path(self.directory+'/renewal-journal.json').exists())

    def test_bad_key_wrong_sni_and_acquisition_failure_do_not_deploy(self):
        self.issue(); old = self.host.read(self.directory+'/fullchain.pem')
        with self.assertRaises(ValueError): self.host.verify(self.host.certificate, (self.material/'new.key').read_bytes(), POLICY['Domains'])
        with self.assertRaises(ValueError): self.host.verify(self.host.certificate, self.host.private_key, ['wrong.elsewhere.test'])
        self.host.fail_acquire = True; self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash'])
        with self.assertRaises(ValueError): self.host.operate(BACKUP, self.request('Renew'))
        self.assertEqual(self.host.read(self.directory+'/fullchain.pem'), old)

    def test_not_due_does_not_contact_acme(self):
        self.host.certificate = (self.material/'new.pem').read_bytes(); self.host.private_key = (self.material/'new.key').read_bytes(); self.issue()
        self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash']); self.host.operate(BACKUP, self.request('Renew'))
        self.assertEqual(self.host.acquisitions, 1)

    def test_disable_enable_remove_and_token_rejection(self):
        self.issue()
        for action, enabled in (('Disable', False), ('Enable', True)):
            self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash']); result = self.host.operate(BACKUP, self.request(action)); self.assertEqual(result['State']['Enabled'], enabled)
        token = self.host.read(self.directory+'/cloudflare.ini'); request = self.request('RotateToken'); request['Token'] = 'bad'*15; self.host.snapshot(BACKUP, IDENTIFIER, request['ExpectedCertificateHash'])
        with self.assertRaises(ValueError): self.host.operate(BACKUP, request)
        self.assertEqual(self.host.read(self.directory+'/cloudflare.ini'), token)
        self.consumer('b'*32, False); self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash'])
        with self.assertRaises(ValueError): self.host.operate(BACKUP, self.request('Remove'))

    def test_stale_unknown_and_linked_paths_are_rejected(self):
        self.issue(); request = self.request('Disable'); self.host.write(self.directory+'/state.json', self.host.read(self.directory+'/state.json')+b' ')
        with self.assertRaises(ValueError): self.host.operate(BACKUP, request)
        self.host.write(self.directory+'/unmanaged', b'keep')
        with self.assertRaises(ValueError): self.host.observe(IDENTIFIER)
        self.host.path(self.directory+'/unmanaged').unlink()
        path = self.host.path(self.directory+'/runner.py'); path.unlink()
        try: path.symlink_to(self.material/'old.pem')
        except OSError: return
        with self.assertRaises(ValueError): self.host.observe(IDENTIFIER)

    def test_global_rollback_will_not_overwrite_external_change(self):
        self.issue(); self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash'])
        self.host.write(self.directory+'/fullchain.pem', b'external edit')
        with self.assertRaises(ValueError): self.host.rollback_check(BACKUP)
        self.assertEqual(self.host.read(self.directory+'/fullchain.pem'), b'external edit')

    def test_scoped_transaction_restores_certificate_and_timer(self):
        self.issue(); before = {p:self.host.read(p) for p in self.host.paths(IDENTIFIER)}
        self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash'])
        archive = self.host.path(BACKUP+'/protocol-files.tar.gz')
        with tarfile.open(archive,'w:gz') as saved:
            for p in before: saved.add(self.host.path(p), arcname=p.lstrip('/'), recursive=False)
        self.host.operate(BACKUP, self.request('Disable'))
        self.host.rollback_prepare(BACKUP)
        for p, data in before.items(): self.host.write(p,data)
        self.host.rollback_complete(BACKUP)
        self.assertTrue(self.host.observe(IDENTIFIER)['State']['Enabled'])
        self.assertEqual({p:self.host.read(p) for p in self.host.paths(IDENTIFIER)}, before)

    def test_renewal_keeps_explicitly_disabled_timer_disabled(self):
        self.issue();self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash']);self.host.operate(BACKUP,self.request('Disable'))
        self.host.snapshot(BACKUP, IDENTIFIER, self.host.observe(IDENTIFIER)['Hash']);result=self.host.operate(BACKUP,self.request('Renew'))
        self.assertFalse(result['State']['Enabled']);self.assertFalse(self.host.states[M.service(IDENTIFIER)+'.timer']['enabled'])

    def test_transaction_cannot_write_another_resource(self):
        self.host.snapshot(BACKUP,IDENTIFIER,'Absent')
        with self.assertRaises(ValueError): self.host.tracked(BACKUP,M.ROOT+'/'+'f'*32+'/policy.json',b'{}')
        self.assertFalse(self.host.path(M.ROOT+'/'+'f'*32+'/policy.json').exists())

    def test_expired_or_changed_lease_stops_before_write(self):
        self.host.snapshot(BACKUP,IDENTIFIER,'Absent')
        self.host.write('/var/lib/may-vps-deploy/transaction.owner',BACKUP.encode())
        self.host.write(BACKUP+'/deadline-epoch',b'0')
        with patch.dict(os.environ,{'VPS_PARAM_EXPECTED_TRANSACTION':BACKUP}):
            with self.assertRaises(ValueError): self.host.tracked(BACKUP,self.directory+'/policy.json',b'{}')
        self.assertFalse(self.host.path(self.directory+'/policy.json').exists())

    def test_interrupted_renewal_recovery_rejects_changed_consumer(self):
        self.issue(); self.consumer('b'*32)
        previous = {n: base64.b64encode(self.host.read(self.directory+'/'+n)).decode() for n in ('fullchain.pem','privkey.pem','accounts.json','state.json')}
        updates = {'fullchain.pem': (self.material/'new.pem').read_bytes(), 'privkey.pem': (self.material/'new.key').read_bytes(), 'accounts.json': b'{}', 'state.json': self.host.read(self.directory+'/state.json')}
        journal = dict(Version=1, Original=previous, Applied={n:M.digest(b) for n,b in updates.items()}, Consumers=self.host.consumers(IDENTIFIER))
        self.host.write(self.directory+'/renewal-journal.json', M.encoded(journal).encode())
        self.host.write(self.directory+'/fullchain.pem', updates['fullchain.pem'])
        def change(name, data):
            if data is None: self.host.path(name).unlink(missing_ok=True)
            else: self.host.write(name, data)
        self.host.restore_renewal(IDENTIFIER, change)
        self.assertEqual(self.host.read(self.directory+'/fullchain.pem'), (self.material/'old.pem').read_bytes())
        self.assertFalse(self.host.path(self.directory+'/renewal-journal.json').exists())


class Policy(unittest.TestCase):
    def test_region_domain_email_and_bounds(self):
        self.assertEqual(M.policy(POLICY), POLICY)
        for field, value in [('Domains',['other.test']), ('Domains',['service.example.test']*2), ('Zone','../bad'), ('Email','x\nheader@example.test'), ('PropagationSeconds',True), ('Provider','Aliyun')]:
            with self.assertRaises(ValueError): M.policy(dict(POLICY, **{field:value}))
        with self.assertRaises(ValueError): M.identity('../../x')


if __name__ == '__main__': unittest.main()
