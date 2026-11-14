"""Scoped Cloudflare certificates; no global Certbot lineages or DNS routing edits.

The SSH caller uses the existing transaction owner. A per-resource systemd
timer only renews its fixed policy and deploys to current catalogue consumers.
"""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import tempfile
import tarfile

ROOT = '/etc/may-certificates'
HEADER = '# Managed by May VPS Deploy certificate identities.\n'
FILES = ('policy.json', 'state.json', 'cloudflare.ini', 'accounts.json', 'runner.py', 'fullchain.pem', 'privkey.pem', 'renewal-journal.json')
LIMIT = 2 * 1024 * 1024


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identity(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{32}', value):
        raise ValueError('Invalid certificate identity.')
    return value


def policy(value):
    if not isinstance(value, dict) or set(value) != {'Provider', 'Zone', 'Email', 'Domains', 'PropagationSeconds'} or value['Provider'] != 'Cloudflare':
        raise ValueError('Invalid certificate policy.')
    domain = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+'
    zone = value['Zone']
    if not isinstance(zone, str) or len(zone) > 253 or not re.fullmatch(domain, zone):
        raise ValueError('Invalid certificate zone.')
    names = value['Domains']
    if not isinstance(names, list) or not 1 <= len(names) <= 8 or not all(isinstance(n, str) for n in names) or len(set(names)) != len(names):
        raise ValueError('Invalid certificate domains.')
    for name in names:
        host = name[2:] if name.startswith('*.') else name
        if len(name) > 253 or not re.fullmatch(domain, host) or host != zone and not host.endswith('.' + zone):
            raise ValueError('Certificate domain exceeds the selected zone.')
    if not isinstance(value['Email'], str) or len(value['Email']) > 254 or not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+', value['Email']) or type(value['PropagationSeconds']) is not int or not 10 <= value['PropagationSeconds'] <= 300:
        raise ValueError('Invalid certificate email or propagation wait.')
    return value


def service(identifier):
    return 'may-certificate-' + identity(identifier)


class Host:
    def __init__(self, root=Path('/'), run=subprocess.run):
        self.root, self.run = root, run

    def path(self, logical):
        if not logical.startswith('/') or logical.startswith('//') or '\\' in logical or '..' in logical.split('/'):
            raise ValueError('Invalid certificate path.')
        result = self.root / logical.lstrip('/')
        if any(p.is_symlink() for p in (result, *result.parents)):
            raise ValueError('Linked certificate path.')
        return result

    def read(self, logical):
        path = self.path(logical)
        if not path.is_file() or path.stat().st_size > LIMIT:
            raise ValueError('Invalid certificate file.')
        if self.root == Path('/') and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
            raise ValueError('Certificate file is not root owned.')
        if self.root == Path('/') and logical.startswith(ROOT + '/') and path.stat().st_mode & 0o077:
            raise ValueError('Certificate private material is accessible to other users.')
        return path.read_bytes()

    def write(self, logical, data, mode=0o600):
        if len(data) > LIMIT:
            raise ValueError('Certificate file exceeds its bound.')
        path = self.path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        stage = path.with_name(path.name + '.new')
        self.path(logical + '.new')
        with stage.open('xb') as stream:
            os.chmod(stage, mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(stage, path)

    def command(self, args, input=None, timeout=60, check=True):
        result = self.run(args, input=input, capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise ValueError('Certificate command failed.')
        return result

    def paths(self, identifier):
        directory = ROOT + '/' + identity(identifier)
        folder = self.path(directory)
        names = []
        if folder.exists():
            if not folder.is_dir():
                raise ValueError('Certificate directory is occupied.')
            for entry in folder.iterdir():
                if entry.name.removesuffix('.new') not in FILES:
                    raise ValueError('Unknown certificate resource.')
                logical = directory + '/' + entry.name
                self.read(logical)
                names.append(logical)
        for suffix in ('.service', '.timer'):
            logical = '/etc/systemd/system/' + service(identifier) + suffix
            if self.path(logical).exists():
                if not self.read(logical).startswith(HEADER.encode()):
                    raise ValueError('Certificate unit is not owned.')
                names.append(logical)
            for other in ('/run/systemd/system/', '/usr/lib/systemd/system/', '/lib/systemd/system/'):
                if other.startswith('/lib/') and (self.root / 'lib').is_symlink():
                    if (self.root / 'lib').resolve() != (self.root / 'usr/lib').resolve():
                        raise ValueError('Untrusted system library namespace.')
                    continue  # Debian merged-/usr alias of the already checked directory.
                if self.path(other + service(identifier) + suffix).exists():
                    raise ValueError('Unmanaged certificate unit.')
            if self.path(logical + '.d').exists():
                raise ValueError('Certificate unit override.')
        return sorted(names)

    def observe(self, identifier):
        directory = ROOT + '/' + identity(identifier)
        paths = self.paths(identifier)
        if not paths:
            return {'Hash': 'Absent', 'State': None}
        p = json.loads(self.read(directory + '/policy.json'))
        if set(p) != {'Owner', 'Id', 'Policy'} or p['Owner'] != 'MayCertificate.v1' or p['Id'] != identifier:
            raise ValueError('Unowned certificate policy.')
        policy(p['Policy'])
        state = json.loads(self.read(directory + '/state.json'))
        if set(state) - {'Enabled', 'Sha256', 'NotAfter', 'LastSuccess', 'LastAttempt', 'ErrorCode', 'ProgramSha256'} or type(state.get('Enabled')) is not bool:
            raise ValueError('Invalid certificate state.')
        if not re.fullmatch('[a-f0-9]{64}', state.get('Sha256', '')):
            raise ValueError('Invalid deployed certificate identity.')
        if digest(self.read(directory + '/runner.py')) != state.get('ProgramSha256'):
            raise ValueError('Managed certificate program changed.')
        for path, expected in self.timer_units(identifier).items():
            if self.read(path) != expected:
                raise ValueError('Certificate timer identity differs.')
            name = path.rsplit('/', 1)[1]
            for field in ('FragmentPath', 'DropInPaths'):
                actual = self.command(['systemctl', 'show', name, '-p', field, '--value']).stdout.decode().strip()
                if actual != (path if field == 'FragmentPath' else ''):
                    raise ValueError('Certificate unit identity or overrides differ.')
        if self.path(directory + '/renewal-journal.json').exists():
            state = dict(state, ErrorCode='PendingRenewalRecovery')
        else:
            actual = self.verify(self.read(directory + '/fullchain.pem'), self.read(directory + '/privkey.pem'), p['Policy']['Domains'], allow_expired=True)
            if actual['Sha256'] != state['Sha256'] or dt.datetime.fromisoformat(actual['NotAfter']) != dt.datetime.fromisoformat(state['NotAfter']):
                raise ValueError('Certificate state differs from deployed public material.')
        hashes = {name: digest(self.read(name)) for name in paths}
        return {'Hash': digest(encoded(hashes).encode()), 'State': state, 'Policy': p['Policy']}

    def snapshot(self, backup, identifier, expected):
        if not re.fullmatch(r'/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle', backup):
            raise ValueError('Invalid certificate recovery path.')
        observed = self.observe(identifier)
        if observed['Hash'] != expected:
            raise ValueError('Certificate changed before snapshot.')
        original = {p: digest(self.read(p)) for p in self.paths(identifier)}
        self.write(backup + '/certificate-state.json', encoded({'Version': 1, 'Id': identifier, 'Original': original, 'Applied': {}}).encode())

    def journal(self, backup):
        if not re.fullmatch(r'/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle', backup):
            raise ValueError('Invalid certificate recovery path.')
        j = json.loads(self.read(backup + '/certificate-state.json'))
        if j.get('Version') != 1:
            raise ValueError('Invalid certificate snapshot.')
        identifier = identity(j['Id'])
        allowed = {ROOT + '/' + identifier + '/' + f for f in FILES} | {'/etc/systemd/system/' + service(identifier) + s for s in ('.service', '.timer')}
        if any(p.removesuffix('.new') not in allowed for p in set(j['Original']) | set(j['Applied'])):
            raise ValueError('Certificate recovery exceeds its scope.')
        return j

    def tracked(self, backup, logical, content):
        j = self.journal(backup)
        if os.environ.get('VPS_PARAM_EXPECTED_TRANSACTION'):
            owner = self.read('/var/lib/may-vps-deploy/transaction.owner').decode().strip()
            deadline = self.read(backup + '/deadline-epoch').decode().strip()
            if owner != backup or os.environ['VPS_PARAM_EXPECTED_TRANSACTION'] != backup or not deadline.isdecimal() or time.time() >= int(deadline) or self.path(backup + '/transaction-committed').exists() or self.path(backup + '/rollback-executed').exists():
                raise ValueError('Certificate transaction lease expired or changed.')
        directory = ROOT + '/' + j['Id'] + '/'
        if not (logical.startswith(directory) and logical[len(directory):] in FILES or logical in ('/etc/systemd/system/' + service(j['Id']) + '.service', '/etc/systemd/system/' + service(j['Id']) + '.timer')):
            raise ValueError('Certificate write exceeds its transaction identity.')
        j['Applied'][logical] = None if content is None else digest(content)
        if content is not None:
            j['Applied'][logical + '.new'] = digest(content)
        self.write(backup + '/certificate-state.json', encoded(j).encode())
        if content is None:
            self.path(logical).unlink(missing_ok=True)
        else:
            self.write(logical, content, 0o644 if logical.endswith(('.service', '.timer')) else 0o600)

    def rollback_check(self, backup):
        j = self.journal(backup)
        current = set(self.paths(j['Id']))
        if current - set(j['Original']) - set(j['Applied']):
            raise ValueError('Unknown certificate file during recovery.')
        for path in set(j['Original']) | set(j['Applied']):
            actual = digest(self.read(path)) if self.path(path).exists() else None
            if actual not in (j['Original'].get(path), j['Applied'].get(path)):
                raise ValueError('Certificate changed outside this transaction.')
        with tarfile.open(self.path(backup + '/protocol-files.tar.gz')) as archive:
            for path, expected in j['Original'].items():
                members = [m for m in archive.getmembers() if m.name == path.lstrip('/')]
                if len(members) != 1 or not members[0].isfile() or members[0].size > LIMIT or digest(archive.extractfile(members[0]).read()) != expected:
                    raise ValueError('Certificate recovery archive differs.')
            for member in archive.getmembers():
                if member.name.startswith(('etc/may-certificates/', 'etc/systemd/system/may-certificate-')) and ('/' + member.name not in j['Original'] or not member.isfile()):
                    raise ValueError('Certificate archive exceeds its recovery identity.')
        return j

    def rollback_prepare(self, backup):
        j = self.rollback_check(backup)
        self.command(['systemctl', 'disable', '--now', service(j['Id']) + '.timer'], check=False)
        for path in set(j['Original']) | set(j['Applied']):
            self.path(path).unlink(missing_ok=True)

    def rollback_complete(self, backup):
        j = self.journal(backup)
        self.command(['systemctl', 'daemon-reload'])
        if j['Original']:
            enabled = self.observe(j['Id'])['State']['Enabled']
            self.command(['systemctl', 'enable' if enabled else 'disable', '--now', service(j['Id']) + '.timer'])
        for consumer in self.consumers(j['Id'], strict_runtime=False):
            registry = json.loads(self.read('/etc/may-inbounds/model.json'))
            identifier = consumer['Unit'].removeprefix('may-inbound-').removesuffix('.service')
            item = next(i for i in registry['Model']['Inbounds'] if i['Id'] == identifier)
            if item['Enabled']:
                self.command(['systemctl', 'restart', consumer['Unit']])
                self.command(['systemctl', 'is-active', '--quiet', consumer['Unit']])

    def consumers(self, identifier, strict_runtime=True):
        path = '/etc/may-inbounds/model.json'
        if not self.path(path).exists():
            return []
        registry = json.loads(self.read(path))
        result = []
        for item in registry['Model']['Inbounds']:
            if item.get('CertificateId') != identifier:
                continue
            identity(item['Id'])
            config = '/etc/may-inbounds/' + item['Id'] + '.json'
            unit = '/etc/systemd/system/may-inbound-' + item['Id'] + '.service'
            binding = next(b for b in registry['Bindings'] if b['Id'] == item['Id'])
            if digest(self.read(config)) != binding['Sha256']:
                raise ValueError('Certificate consumer configuration changed.')
            content = json.loads(self.read(config))['inbounds'][0]
            expected = '/run/credentials/may-inbound-' + item['Id'] + '.service/'
            cert = content.get('streamSettings', {}).get('tlsSettings', {}).get('certificates', [{}])[0] if item['Protocol'] == 'VLESS' else content.get('tls', {})
            actual = (cert.get('certificateFile'), cert.get('keyFile')) if item['Protocol'] == 'VLESS' else (cert.get('certificate_path'), cert.get('key_path'))
            if actual != (expected + 'certificate.pem', expected + 'certificate.key'):
                raise ValueError('Certificate consumer does not use the scoped credential.')
            unit_data = self.read(unit).decode()
            for leaf, source in (('certificate.pem', 'fullchain.pem'), ('certificate.key', 'privkey.pem')):
                if 'LoadCredential=' + leaf + ':' + ROOT + '/' + identifier + '/' + source + '\n' not in unit_data:
                    raise ValueError('Certificate consumer unit changed.')
            name = 'may-inbound-' + item['Id'] + '.service'
            for field in ('FragmentPath', 'DropInPaths'):
                observed = self.command(['systemctl', 'show', name, '-p', field, '--value']).stdout.decode().strip()
                if observed != (unit if field == 'FragmentPath' else ''):
                    raise ValueError('Certificate consumer service identity differs.')
            active = self.command(['systemctl', 'is-active', '--quiet', name], check=False).returncode == 0
            enabled = self.command(['systemctl', 'is-enabled', '--quiet', name], check=False).returncode == 0
            if strict_runtime and (active != item['Enabled'] or enabled != item['Enabled']):
                raise ValueError('Certificate consumer runtime differs.')
            result.append({'Unit': name, 'Active': active, 'Sni': item['Options']['ServerName'], 'Config': config, 'Hash': binding['Sha256']})
        return result

    def verify(self, cert, key, names, allow_expired=False):
        # Certificate/key agreement, chain validation, validity and every SAN.
        public = self.command(['openssl', 'x509', '-pubkey', '-noout'], cert).stdout
        if public != self.command(['openssl', 'pkey', '-pubout'], key).stdout:
            raise ValueError('Certificate private key mismatch.')
        if not allow_expired:
            self.command(['openssl', 'x509', '-checkend', '172800', '-noout'], cert)
        with tempfile.TemporaryDirectory(prefix='may-certificate-check-') as temp:
            leaf = Path(temp) / 'chain.pem'; leaf.write_bytes(cert)
            self.command(['openssl', 'verify', *(['-no_check_time'] if allow_expired else []), '-CApath', '/etc/ssl/certs', '-untrusted', str(leaf), str(leaf)])
        for name in names:
            if name.startswith('*.'):
                sans = self.command(['openssl', 'x509', '-noout', '-ext', 'subjectAltName'], cert).stdout.decode()
                if name not in [s.strip().removeprefix('DNS:') for s in sans.replace('\n', ' ').split(',')]:
                    # The first token includes the extension heading.
                    if 'DNS:' + name not in re.findall(r'DNS:[^,\s]+', sans):
                        raise ValueError('Missing wildcard SAN.')
            else:
                r = self.command(['openssl', 'x509', '-noout', '-checkhost', name], cert)
                if r.stdout.decode().strip() != 'Hostname ' + name + ' does match certificate':
                    raise ValueError('Certificate hostname mismatch.')
        info = self.command(['openssl', 'x509', '-noout', '-dates', '-sha256', '-fingerprint'], cert).stdout.decode()
        fields = dict(s.split('=', 1) for s in info.splitlines() if '=' in s)
        def date(field):
            return dt.datetime.strptime(fields[field], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc)
        if not allow_expired and date('notBefore') > dt.datetime.now(dt.timezone.utc):
            raise ValueError('Certificate is not yet valid.')
        fingerprint = fields.get('sha256 Fingerprint', fields.get('SHA256 Fingerprint', '')).replace(':', '').lower()
        if not re.fullmatch('[a-f0-9]{64}', fingerprint):
            raise ValueError('Invalid certificate fingerprint.')
        return {'Sha256': fingerprint, 'NotAfter': date('notAfter').isoformat()}

    def acquire(self, identifier, settings, token):
        # The token is sent to curl on stdin, never as an argv or URL component.
        source = None
        for family in ('-4', '-6'):
            request = 'header = "Authorization: Bearer ' + token + '"\n'
            args = ['curl', family, '--config', '-', '--silent', '--fail', '--connect-timeout', '10', '--max-time', '30', '--get', '--data-urlencode', 'name=' + settings['Zone'], '--write-out', '\n%{local_ip}', 'https://api.cloudflare.com/client/v4/zones']
            response = self.command(args, request.encode(), check=False)
            try:
                body, address = response.stdout.rsplit(b'\n', 1)
                data = json.loads(body)
                if response.returncode == 0 and data.get('success') is True and len(data['result']) == 1 and data['result'][0]['name'] == settings['Zone']:
                    import ipaddress
                    source = str(ipaddress.ip_address(address.decode())); break
            except (ValueError, KeyError, TypeError):
                pass
        if source is None:
            raise ValueError('Cloudflare zone authorization failed.')
        with tempfile.TemporaryDirectory(prefix='may-acme-') as temp:
            folder = Path(temp); os.chmod(folder, 0o700)
            configuration = folder / 'config'; configuration.mkdir()
            account_file = ROOT + '/' + identifier + '/accounts.json'
            if self.path(account_file).exists():
                for name, data in json.loads(self.read(account_file)).items():
                    if not re.fullmatch(r'[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)+', name) or '..' in name.split('/') or not name.startswith('acme-v02.api.letsencrypt.org/directory/'):
                        raise ValueError('Invalid stored ACME account path.')
                    p = configuration / 'accounts' / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(base64.b64decode(data, validate=True)); os.chmod(p, 0o600)
            credential = folder / 'cloudflare.ini'; credential.write_text('dns_cloudflare_api_token = ' + token + '\n'); os.chmod(credential, 0o600)
            arguments = ['certonly', '--config', '/dev/null', '--non-interactive', '--agree-tos', '--email', settings['Email'], '--config-dir', str(configuration), '--work-dir', str(folder / 'work'), '--logs-dir', str(folder / 'logs'), '--server', 'https://acme-v02.api.letsencrypt.org/directory', '--cert-name', 'may-' + identifier, '--dns-cloudflare', '--dns-cloudflare-credentials', str(credential), '--dns-cloudflare-propagation-seconds', str(settings['PropagationSeconds'])]
            for name in settings['Domains']:
                arguments.extend(['-d', name])
            runner = ROOT + '/' + identifier + '/runner.py'
            self.command(['/usr/bin/python3', str(self.path(runner)), 'certbot', source, *arguments], timeout=720)
            # Certbot's live links must resolve inside this fresh private workspace.
            def read_live(name):
                p = configuration / 'live' / ('may-' + identifier) / name
                resolved = p.resolve(strict=True)
                if not resolved.is_relative_to(configuration / 'archive') or resolved.stat().st_size > 131072:
                    raise ValueError('Unexpected ACME lineage output.')
                return resolved.read_bytes()
            accounts = {}
            for p in (configuration / 'accounts').rglob('*'):
                if p.is_symlink():
                    raise ValueError('Linked ACME account.')
                if p.is_file():
                    if p.stat().st_size > 65536 or len(accounts) >= 16:
                        raise ValueError('ACME account exceeds bounds.')
                    accounts[p.relative_to(configuration / 'accounts').as_posix()] = base64.b64encode(p.read_bytes()).decode()
            return read_live('fullchain.pem'), read_live('privkey.pem'), encoded(accounts).encode()

    def timer_units(self, identifier):
        directory = ROOT + '/' + identifier
        common = HEADER + '[Unit]\nDescription=May managed certificate ' + identifier + '\n'
        unit = common + '\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 ' + directory + '/runner.py scheduled ' + identifier + '\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=read-only\nProtectSystem=strict\nReadWritePaths=' + directory + ' /var/lib/may-vps-deploy\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nTimeoutStartSec=900\nMemoryMax=256M\nCPUQuota=25%\n'
        timer = common + '\n[Timer]\nOnCalendar=*-*-* 00,12:00:00\nRandomizedDelaySec=3600\nPersistent=true\nUnit=' + service(identifier) + '.service\n\n[Install]\nWantedBy=timers.target\n'
        return {('/etc/systemd/system/' + service(identifier) + suffix): data.encode() for suffix, data in (('.service', unit), ('.timer', timer))}

    def deploy(self, identifier, certificate, private_key, accounts, settings, change):
        directory = ROOT + '/' + identifier
        consumers = self.consumers(identifier)
        proof = self.verify(certificate, private_key, settings['Domains'] + [c['Sni'] for c in consumers])
        old = {name: self.read(directory + '/' + name) for name in ('fullchain.pem', 'privkey.pem', 'accounts.json', 'state.json') if self.path(directory + '/' + name).exists()}
        enabled = json.loads(old['state.json'])['Enabled'] if 'state.json' in old else True
        proof.update(Enabled=enabled, LastAttempt=dt.datetime.now(dt.timezone.utc).isoformat(), LastSuccess=dt.datetime.now(dt.timezone.utc).isoformat(), ErrorCode='', ProgramSha256=digest(self.read(directory + '/runner.py')))
        replacement = {'fullchain.pem': certificate, 'privkey.pem': private_key, 'accounts.json': accounts, 'state.json': encoded(proof).encode()}
        journal = {'Version': 1, 'Original': {n: base64.b64encode(b).decode() for n, b in old.items()}, 'Applied': {n: digest(b) for n, b in replacement.items()}, 'Consumers': consumers}
        change(directory + '/renewal-journal.json', encoded(journal).encode())
        try:
            for name, content in replacement.items():
                if name != 'state.json':
                    change(directory + '/' + name, content)
            for consumer in consumers:
                if digest(self.read(consumer['Config'])) != consumer['Hash']:
                    raise ValueError('Consumer changed during certificate deployment.')
                if consumer['Active']:
                    self.command(['systemctl', 'restart', consumer['Unit']])
                    self.command(['systemctl', 'is-active', '--quiet', consumer['Unit']])
            change(directory + '/state.json', replacement['state.json'])
            change(directory + '/renewal-journal.json', None)
            return proof
        except BaseException:
            # The old pair and all previous enabled states are restored as one
            # deployment scope. An interrupted process leaves this journal.
            self.restore_renewal(identifier, change)
            raise

    def restore_renewal(self, identifier, change):
        directory = ROOT + '/' + identifier
        j = json.loads(self.read(directory + '/renewal-journal.json'))
        if set(j) != {'Version', 'Original', 'Applied', 'Consumers'} or j['Version'] != 1 or set(j['Original']) - {'fullchain.pem', 'privkey.pem', 'accounts.json', 'state.json'} or set(j['Applied']) != {'fullchain.pem', 'privkey.pem', 'accounts.json', 'state.json'}:
            raise ValueError('Unknown renewal recovery scope.')
        current_consumers = self.consumers(identifier, strict_runtime=False)
        # Service failure is expected during compensation; validate immutable
        # catalogue/config/unit identity separately from the active flag.
        if [(c['Unit'], c['Config'], c['Hash']) for c in current_consumers] != [(c['Unit'], c['Config'], c['Hash']) for c in j['Consumers']]:
            raise ValueError('Certificate consumers changed during recovery.')
        for name in set(j['Original']) | set(j['Applied']):
            previous = base64.b64decode(j['Original'][name], validate=True) if name in j['Original'] else None
            actual = self.read(directory + '/' + name) if self.path(directory + '/' + name).exists() else None
            if actual != previous and (actual is None or digest(actual) != j['Applied'].get(name)):
                raise ValueError('Certificate changed outside renewal recovery.')
        for name in set(j['Original']) | set(j['Applied']):
            change(directory + '/' + name, base64.b64decode(j['Original'][name], validate=True) if name in j['Original'] else None)
        for consumer in j['Consumers']:
            if consumer['Active']:
                self.command(['systemctl', 'restart', consumer['Unit']])
                self.command(['systemctl', 'is-active', '--quiet', consumer['Unit']])
        change(directory + '/renewal-journal.json', None)

    def operate(self, backup, request):
        identifier = identity(request['CertificateId']); settings = policy(request['Policy'])
        if self.journal(backup)['Id'] != identifier:
            raise ValueError('Certificate transaction identity differs.')
        directory = ROOT + '/' + identifier; action = request['Action']
        before = self.observe(identifier)
        if before['Hash'] != request['ExpectedCertificateHash'] or before.get('Policy', settings) != settings:
            raise ValueError('Certificate changed after review.')
        if action == 'Issue' and before['Hash'] != 'Absent' or action != 'Issue' and before['Hash'] == 'Absent':
            raise ValueError('Certificate operation does not match its installed identity.')
        change = lambda name, content: self.tracked(backup, name, content)
        token = request.get('Token', '')
        if action in ('Issue', 'RotateToken') and not re.fullmatch(r'[a-zA-Z0-9_-]{20,512}', token):
            raise ValueError('Invalid Cloudflare token.')
        if action == 'Issue':
            self.path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.path(directory), 0o700)
            change(directory + '/policy.json', encoded({'Owner': 'MayCertificate.v1', 'Id': identifier, 'Policy': settings}).encode())
            source = os.environ['VPS_CERTIFICATE_PROGRAM'].encode()
            change(directory + '/runner.py', source)
            change(directory + '/cloudflare.ini', ('dns_cloudflare_api_token = ' + token + '\n').encode())
            for name, content in self.timer_units(identifier).items():
                change(name, content)
            certificate, key, accounts = self.acquire(identifier, settings, token)
            self.deploy(identifier, certificate, key, accounts, settings, change)
            self.command(['systemctl', 'daemon-reload'])
            self.command(['systemctl', 'enable', '--now', service(identifier) + '.timer'])
        elif action == 'Remove':
            if self.consumers(identifier):
                raise ValueError('Certificate still has consumers.')
            self.command(['systemctl', 'disable', '--now', service(identifier) + '.timer'])
            for name in self.paths(identifier):
                change(name, None)
            self.command(['systemctl', 'daemon-reload'])
        elif action in ('Enable', 'Disable'):
            self.command(['systemctl', 'enable' if action == 'Enable' else 'disable', '--now', service(identifier) + '.timer'])
            state = before['State']; state['Enabled'] = action == 'Enable'
            change(directory + '/state.json', encoded(state).encode())
        elif action == 'RotateToken':
            # Authorization is tested before replacing the old credential.
            self.authorize(settings, token)
            change(directory + '/cloudflare.ini', ('dns_cloudflare_api_token = ' + token + '\n').encode())
        elif action == 'Renew':
            if self.path(directory + '/renewal-journal.json').exists():
                self.restore_renewal(identifier, change)
            self.renew(identifier, settings, change)
        else:
            raise ValueError('Unsupported certificate mutation.')
        return self.observe(identifier)

    def authorize(self, settings, token):
        for family in ('-4', '-6'):
            response = self.command(['curl', family, '--config', '-', '--silent', '--fail', '--connect-timeout', '10', '--max-time', '30', '--get', '--data-urlencode', 'name=' + settings['Zone'], 'https://api.cloudflare.com/client/v4/zones'], ('header = "Authorization: Bearer ' + token + '"\n').encode(), check=False)
            try:
                data = json.loads(response.stdout)
                if response.returncode == 0 and data.get('success') is True and len(data['result']) == 1 and data['result'][0]['name'] == settings['Zone']:
                    return
            except (ValueError, KeyError, TypeError):
                pass
        raise ValueError('Cloudflare authorization failed.')

    def renew(self, identifier, settings, change):
        directory = ROOT + '/' + identifier
        state = self.observe(identifier)['State']
        if dt.datetime.fromisoformat(state['NotAfter']) > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30):
            return  # No forced reissue; avoid CA rate limits.
        credential = self.read(directory + '/cloudflare.ini').decode()
        match = re.fullmatch(r'dns_cloudflare_api_token = ([A-Za-z0-9_-]{20,512})\n', credential)
        if not match:
            raise ValueError('Invalid stored certificate credential.')
        certificate, key, accounts = self.acquire(identifier, settings, match[1])
        self.deploy(identifier, certificate, key, accounts, settings, change)

    def scheduled(self, identifier):
        # Serialize against desktop operations and independent rollback actors.
        import fcntl
        lock = self.path('/var/lib/may-vps-deploy/transaction.lock')
        with lock.open('a+b') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            owner = self.path('/var/lib/may-vps-deploy/transaction.owner')
            if owner.exists():
                backup = owner.read_text().strip()
                if not re.fullmatch(r'/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/(?:protocol-lifecycle|ssh-maintenance)', backup):
                    raise ValueError('Unknown active transaction owner.')
                if not self.path(backup + '/transaction-committed').exists() and not self.path(backup + '/rollback-executed').exists():
                    return
            directory = ROOT + '/' + identity(identifier)
            observed = self.observe(identifier)
            if not observed['State']['Enabled']:
                return
            def change(name, content):
                if content is None: self.path(name).unlink(missing_ok=True)
                else: self.write(name, content)
            try:
                if self.path(directory + '/renewal-journal.json').exists():
                    self.restore_renewal(identifier, change)
                self.renew(identifier, observed['Policy'], change)
            except BaseException:
                state = self.observe(identifier)['State']
                state.update(LastAttempt=dt.datetime.now(dt.timezone.utc).isoformat(), ErrorCode='RenewalFailed')
                change(directory + '/state.json', encoded(state).encode())
                raise ValueError('Managed certificate renewal failed; inspect its scoped recovery state.') from None


def certbot_source():
    import ipaddress
    from urllib3.util import connection
    address = ipaddress.ip_address(sys.argv[2])
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    resolve, connect = socket.getaddrinfo, connection.create_connection
    def cloudflare(host):
        if isinstance(host, bytes): host = host.decode('ascii')
        return isinstance(host, str) and host.rstrip('.').lower() == 'api.cloudflare.com'
    def lookup(host, port, af=0, kind=0, protocol=0, flags=0):
        return resolve(host, port, family if cloudflare(host) else af, kind, protocol, flags)
    def create(target, *args, **kwargs):
        if cloudflare(target[0]):
            if len(args) >= 2: args = (args[0], (str(address), 0), *args[2:])
            else: kwargs['source_address'] = (str(address), 0)
        return connect(target, *args, **kwargs)
    socket.getaddrinfo, connection.create_connection = lookup, create
    from certbot.main import main
    raise SystemExit(main(sys.argv[3:]))


def main():
    if sys.argv[1] == 'certbot':
        certbot_source()
    host = Host()
    if sys.argv[1] == 'scheduled':
        host.scheduled(identity(sys.argv[2])); return
    action = sys.argv[1]
    if action.startswith('rollback-'):
        getattr(host, action.replace('-', '_'))(sys.argv[2]); return
    request = json.loads(os.environ['VPS_PARAM_CERTIFICATE_DOCUMENT'])
    identifier = identity(request['CertificateId']); policy(request['Policy'])
    if action == 'snapshot': host.snapshot(sys.argv[2], identifier, request['ExpectedCertificateHash'])
    elif action == 'paths': print('\n'.join(p.lstrip('/') for p in host.paths(identifier)))
    elif action == 'apply':
        observed = host.operate(os.environ['VPS_PARAM_EXPECTED_TRANSACTION'], request)
        result = {'Observation': observed}
        if request['Action'] == 'Issue':
            result['Material'] = {'CertificatePem': host.read(ROOT + '/' + identifier + '/fullchain.pem').decode(), 'PrivateKeyPem': host.read(ROOT + '/' + identifier + '/privkey.pem').decode()}
        print('VPSDEPLOY_CERTIFICATE_RESULT_B64=' + base64.b64encode(encoded(result).encode()).decode())
    elif action == 'read':
        print('VPSDEPLOY_CERTIFICATE_RESULT_B64=' + base64.b64encode(encoded({'Observation': host.observe(identifier)}).encode()).decode())
    else: raise ValueError('Unknown certificate action.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never include Certbot / Cloudflare responses, PEM or tokens in logs.
        print('ManagedCertificateFailed', file=sys.stderr)
        raise SystemExit(1)
