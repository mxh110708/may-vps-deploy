"""May-owned monitoring lifecycle. No upstream installer or legacy Komari path."""
import base64
import contextlib
import fcntl
import grp
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


SCHEMA = 1
MAX_BACKUP = 2 * 1024 ** 3
ROLES = ('Server', 'Agent')
ACTIONS = ('Check', 'Begin', 'Apply', 'Commit', 'Rollback', 'Transaction')
OWNER = '/var/lib/may-vps-deploy/transaction.owner'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()


def version(value):
    if not isinstance(value, str) or len(value) > 80 or not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-rc\.([1-9]\d*))?', value):
        raise ValueError('Unsupported May Monitor version.')
    stable, _, rc = value.partition('-rc.')
    return tuple(int(x) for x in stable.split('.')) + (1 if not rc else 0, int(rc or 0))


def endpoint(value):
    parsed = urllib.parse.urlsplit(value)
    if len(value) > 2048 or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid monitoring endpoint.')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1', 'localhost')):
        raise ValueError('Monitoring requires HTTPS; HTTP is loopback only.')
    if not parsed.hostname:
        raise ValueError('Missing monitoring host.')
    return value.rstrip('/')


class Host:
    # Root/runner injection is confined to imported unit tests. The CLI has no
    # root override and operates only on fixed, role-specific resource paths.
    def __init__(self, root=Path('/'), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run

    def path(self, value):
        if not value.startswith('/') or '..' in value.split('/'):
            raise ValueError('Invalid owned path.')
        result = self.root / value.lstrip('/')
        for candidate in (result, *result.parents):
            if candidate.is_symlink():
                raise ValueError('Linked resource refused.')
        return result

    def run(self, args, required=True, timeout=40):
        result = self.runner(args, capture_output=True, text=True, timeout=timeout)
        if required and result.returncode:
            raise ValueError('Owned monitoring service command failed.')
        return result

    def atomic(self, path, data, mode=0o600, uid=0, gid=0):
        path = self.path('/' + str(path.relative_to(self.root)))
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.may-write-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as target:
                os.fchmod(target.fileno(), mode)
                os.fchown(target.fileno(), uid, gid)
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def read_json(self, path):
        if path.stat().st_size > 1024 * 1024:
            raise ValueError('Oversized lifecycle metadata.')
        return json.loads(path.read_text())

    def verify_process(self, unit, binary):
        result = self.run(['systemctl', 'show', unit, '-p', 'MainPID', '--value'])
        if not result.stdout.strip().isdigit() or int(result.stdout.strip()) < 1:
            raise ValueError('Monitoring service has no verified process.')
        running = Path('/proc') / result.stdout.strip() / 'exe'
        if not os.path.samefile(running, self.path(binary)):
            raise ValueError('Monitoring service is running another binary.')


class Lifecycle:
    def __init__(self, host, role):
        if role not in ROLES:
            raise ValueError('Unknown May monitoring scope.')
        self.host, self.role = host, role
        self.leaf = 'may-monitor-' + role.lower()
        self.config = '/etc/' + self.leaf
        self.data = '/var/lib/' + self.leaf
        self.unit = self.leaf + '.service'
        self.binary = '/usr/local/bin/' + self.leaf
        self.files = (self.binary, '/etc/systemd/system/' + self.unit,
                      self.config + '/runtime.env', self.config + '/read-access.env') if role == 'Server' else (
                          self.binary, '/etc/systemd/system/' + self.unit, self.config + '/config.json')
        self.meta = self.config + '/managed.json'

    def system(self, *args, required=True):
        return self.host.run(['systemctl', *args], required)

    def reviewed_theme(self, pin):
        if not isinstance(pin, str) or not re.fullmatch('[a-f0-9]{64}', pin):
            raise ValueError('Invalid reviewed theme lock digest.')
        root = self.host.path('/usr/local/share/may-monitor/themes/' + pin)
        for p in [root, *root.parents]:
            if p == self.host.root:
                break
            info = p.lstat()
            if p.is_symlink() or not p.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Unsafe reviewed theme directory.')
        lock = root / 'may-theme.lock.json'
        if lock.is_symlink() or lock.stat().st_size > 2 * 1024 ** 2 or digest(lock) != pin:
            raise ValueError('Reviewed theme lock differs.')
        value = self.host.read_json(lock)
        if set(value) != {'schema', 'short', 'files'} or value['schema'] != 1 or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', value['short']) or value['short'] == 'default' or not 2 <= len(value['files']) <= 10000:
            raise ValueError('Invalid reviewed theme identity.')
        total = 0
        for name, sha in {**value['files'], 'may-theme.lock.json': pin}.items():
            if name.startswith('/') or '\\' in name or any(part in ('', '.', '..') for part in name.split('/')) or not re.fullmatch('[a-f0-9]{64}', sha):
                raise ValueError('Invalid reviewed theme member.')
            if name != 'may-theme.lock.json' and name not in ('komari-theme.json', 'preview.png', 'preview-v2.0.0.png') and not name.startswith('dist/'):
                raise ValueError('Reviewed theme contains a non-static member.')
            p = root / name
            for parent in p.parents:
                if parent == root:
                    break
                info = parent.lstat()
                if parent.is_symlink() or not parent.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('Unsafe reviewed asset directory.')
            info = p.lstat(); total += info.st_size
            if p.is_symlink() or not p.is_file() or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 16 * 1024 ** 2 or digest(p) != sha:
                raise ValueError('Reviewed static asset changed.')
        if total > 256 * 1024 ** 2 or 'dist/index.html' not in value['files'] or self.host.read_json(root/'komari-theme.json').get('short') != value['short']:
            raise ValueError('Incomplete reviewed theme.')
        return value['short']

    def active(self):
        return self.system('is-active', '--quiet', self.unit, required=False).returncode == 0

    def enabled(self):
        return self.system('is-enabled', '--quiet', self.unit, required=False).returncode == 0

    def check_overrides(self):
        if self.system('show', self.unit, '-p', 'DropInPaths', '--value', required=False).stdout.strip() or self.host.path('/etc/systemd/system/' + self.unit + '.d').exists():
            raise ValueError('Monitoring service overrides require manual review.')

    def tree(self, directory):
        if not directory.exists():
            return []
        result, total = [directory], 0
        for current, dirs, names in os.walk(directory, followlinks=False):
            for name in dirs + names:
                path = Path(current) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                    raise ValueError('Unsupported object inside monitoring data.')
                total += info.st_size
                if total > MAX_BACKUP or len(result) >= 100000:
                    raise ValueError('Monitoring backup exceeds this workflow limit.')
                result.append(path)
        return result

    def inspect(self, expected=None, journal=None):
        meta_path = self.host.path(self.meta)
        for name in (*self.files, self.meta):
            path = self.host.path(name)
            if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
                raise ValueError('Non-regular monitoring resource refused.')
        actual = {name: digest(self.host.path(name)) if self.host.path(name).is_file() else None for name in self.files}
        if not meta_path.exists():
            if any(actual.values()) or self.host.path(self.config).exists() or self.host.path(self.data).exists() or self.system('cat', self.unit, required=False).returncode == 0:
                raise ValueError('Unmanaged monitoring resource collision.')
            try:
                pwd.getpwnam(self.leaf)
            except KeyError:
                pass
            else:
                raise ValueError('Unmanaged May monitoring system account.')
            try:
                grp.getgrnam(self.leaf)
            except KeyError:
                pass
            else:
                raise ValueError('Unmanaged May monitoring system group.')
            state = {'Installed': False, 'Version': '', 'Hash': 'Absent', 'Active': False, 'Enabled': False, 'Configuration': {}}
            if expected not in (None, 'Absent'):
                raise ValueError('Monitoring ownership changed.')
            return state
        meta = self.host.read_json(meta_path)
        if meta.get('SchemaVersion') != SCHEMA or meta.get('Role') != self.role or set(meta.get('Files', {})) != set(self.files):
            raise ValueError('Unknown monitoring ownership manifest.')
        if meta.get('Configuration', {}).get('ThemeLockSha256'):
            if self.role != 'Server':
                raise ValueError('Reviewed themes belong to the server only.')
            self.reviewed_theme(meta['Configuration']['ThemeLockSha256'])
        account = pwd.getpwnam(self.leaf)
        if account.pw_uid != meta['Uid'] or account.pw_gid != meta['Gid'] or account.pw_dir != self.data or account.pw_shell != '/usr/sbin/nologin':
            raise ValueError('Monitoring service identity changed.')
        if set(p.name for p in self.host.path(self.config).iterdir()) != {Path(p).name for p in self.files if p.startswith(self.config + '/') and actual[p] is not None} | {'managed.json'}:
            raise ValueError('Unmanaged file in monitoring configuration.')
        self.check_overrides()
        for name, value in actual.items():
            accepted = (journal or {}).get(name, [meta['Files'][name]])
            if value not in accepted:
                raise ValueError('Managed monitoring files were edited externally.')
            path = self.host.path(name)
            if path.exists() and (path.stat().st_uid != 0 or path.stat().st_nlink != 1 or path.stat().st_mode & 0o022):
                raise ValueError('Unsafe monitoring file ownership.')
            required_mode = 0o755 if name == self.binary else 0o644 if name.endswith('.service') else 0o640 if self.role == 'Agent' else 0o600
            if path.exists() and stat.S_IMODE(path.stat().st_mode) != required_mode:
                raise ValueError('Monitoring credential/file permissions changed.')
            if path.exists() and path.stat().st_gid != (account.pw_gid if self.role == 'Agent' and name.endswith('/config.json') else 0):
                raise ValueError('Monitoring file group changed.')
        if meta_path.stat().st_uid != 0 or stat.S_IMODE(meta_path.stat().st_mode) != 0o600:
            raise ValueError('Unsafe monitoring manifest permissions.')
        data_root = self.host.path(self.data)
        config_root = self.host.path(self.config)
        if config_root.stat().st_uid != 0 or config_root.stat().st_gid != (account.pw_gid if self.role == 'Agent' else 0) or stat.S_IMODE(config_root.stat().st_mode) != (0o750 if self.role == 'Agent' else 0o700):
            raise ValueError('Monitoring configuration directory permissions changed.')
        if not data_root.is_dir() or data_root.stat().st_uid != account.pw_uid or data_root.stat().st_gid != account.pw_gid or stat.S_IMODE(data_root.stat().st_mode) != 0o700:
            raise ValueError('Unsafe monitoring private data root.')
        self.tree(self.host.path(self.data))
        state = {'Installed': meta['Installed'], 'Version': meta['Version'], 'Active': self.active(), 'Enabled': self.enabled(), 'Configuration': meta['Configuration']}
        if state['Installed'] and state['Active']:
            self.host.verify_process(self.unit, self.binary)
        state['Hash'] = hashlib.sha256(canonical({'Manifest': meta, 'Files': actual, 'Active': state['Active'], 'Enabled': state['Enabled']})).hexdigest()
        if expected is not None and state['Hash'] != expected:
            raise ValueError('Monitoring state differs from the reviewed archive.')
        return state

    def backup_path(self, task):
        if not re.fullmatch('[a-f0-9]{32}', task):
            raise ValueError('Invalid monitoring task identity.')
        return self.host.path('/root/vps-deploy-backups/may-monitor-' + task)

    def transaction(self, task):
        backup = self.backup_path(task)
        record = self.host.read_json(backup / 'transaction.json')
        if record.get('SchemaVersion') != SCHEMA or record.get('TaskId') != task or record.get('Role') != self.role or record.get('MachineId') != self.host.path('/etc/machine-id').read_text().strip():
            raise ValueError('Monitoring transaction identity does not match this machine.')
        if digest(backup / 'program.py') != record['ProgramSha256']:
            raise ValueError('Monitoring recovery program changed.')
        return backup, record

    def save_transaction(self, backup, record):
        self.host.atomic(backup / 'transaction.json', canonical(record))

    def owned_transaction(self, task, phases):
        backup, record = self.transaction(task)
        if record['Phase'] not in phases or self.host.path(OWNER).read_text().strip() != str(backup):
            raise ValueError('Monitoring transaction is not the active owner.')
        return backup, record

    def schedule(self, backup, task):
        self.host.run(['systemd-run', '--quiet', '--unit=may-monitor-rollback-' + task, '--on-active=20m', '/usr/bin/python3', str(backup / 'program.py'), 'Rollback', task, self.role])

    def begin(self, task, expected, source):
        owner = self.host.path(OWNER)
        if owner.exists():
            raise ValueError('Another operation owns the remote transaction.')
        for unit in ('mxh-protocol-migration-rollback.timer', 'mxh-ssh-maintenance-rollback.timer'):
            if self.system('is-active', '--quiet', unit, required=False).returncode == 0:
                raise ValueError('Another recovery timer is active.')
        before = self.inspect(expected)
        backup = self.backup_path(task)
        if backup.exists():
            raise ValueError('Monitoring task identity already exists; reconcile first.')
        backup.mkdir(parents=True, mode=0o700)
        self.host.atomic(backup / 'program.py', source.encode())
        record = {'SchemaVersion': SCHEMA, 'Role': self.role, 'TaskId': task, 'MachineId': self.host.path('/etc/machine-id').read_text().strip(), 'Phase': 'Preparing', 'Before': before, 'ProgramSha256': digest(backup / 'program.py'), 'Writes': {}}
        self.save_transaction(backup, record)
        self.host.atomic(owner, (str(backup) + '\n').encode())
        self.schedule(backup, task)
        try:
            if before['Active']:
                self.system('stop', self.unit)
            if self.active():
                raise ValueError('Monitoring did not stop for a consistent snapshot.')
            paths = [self.host.path(name) for name in (*self.files, self.meta) if self.host.path(name).exists()]
            if self.host.path(self.data).exists():
                paths += self.tree(self.host.path(self.data))
            total = sum(p.stat().st_size for p in paths if p.is_file())
            if shutil.disk_usage(backup).free < total * 2 + 128 * 1024 ** 2:
                raise ValueError('Insufficient private backup space.')
            with tarfile.open(backup / 'files.tar.gz', 'w:gz', dereference=False) as archive:
                for path in paths:
                    archive.add(path, arcname=str(path.relative_to(self.host.root)), recursive=False)
            record['BackupSha256'] = digest(backup / 'files.tar.gz')
            record['Phase'] = 'Armed'
            self.save_transaction(backup, record)
        finally:
            if before['Active']:
                self.system('start', self.unit)
        return {'Backup': str(backup), 'Sha256': record['BackupSha256'], 'Before': before, 'Phase': record['Phase']}

    def write(self, backup, record, name, data, mode=0o600, gid=0):
        if name not in (*self.files, self.meta):
            raise ValueError('Write outside the selected monitoring scope.')
        before = digest(self.host.path(name)) if self.host.path(name).exists() else None
        planned = hashlib.sha256(data).hexdigest() if data is not None else None
        record['Writes'].setdefault(name, [before])
        if planned not in record['Writes'][name]:
            record['Writes'][name].append(planned)
        self.save_transaction(backup, record)
        if data is None:
            path = self.host.path(name)
            if path.exists():
                path.unlink()
        else:
            self.host.atomic(self.host.path(name), data, mode, gid=gid)

    def asset(self, backup, spec):
        if set(spec) != {'Version', 'Sha256', 'Bytes', 'Url', 'Name'}:
            raise ValueError('Invalid fixed May release asset.')
        version(spec['Version'])
        name = 'may-monitor-server-linux-amd64.tar.gz' if self.role == 'Server' else 'may-monitor-agent-linux-amd64'
        url = 'https://github.com/mxh110708/may-monitor-' + self.role.lower() + '/releases/download/v' + spec['Version'] + '/' + name
        if spec['Name'] != name or spec['Url'] != url or not re.fullmatch('[a-f0-9]{64}', spec['Sha256']) or type(spec['Bytes']) is not int or not 0 < spec['Bytes'] <= 128 * 1024 ** 2:
            raise ValueError('Artifact is not a pinned owned May release.')
        path = backup / 'artifact'
        if not path.exists():
            class Redirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, target):
                    parsed = urllib.parse.urlsplit(target)
                    if parsed.scheme != 'https' or not (parsed.hostname == 'github.com' or (parsed.hostname or '').endswith('.githubusercontent.com')):
                        raise ValueError('Untrusted release redirect.')
                    return super().redirect_request(req, fp, code, msg, headers, target)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
            with opener.open(url, timeout=30) as response, path.open('xb') as output:
                count, started = 0, time.monotonic()
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > spec['Bytes'] or time.monotonic() - started > 300:
                        raise ValueError('Artifact exceeds the pinned size.')
                    output.write(chunk)
            path.chmod(0o600)
        if path.is_symlink() or path.stat().st_size != spec['Bytes'] or digest(path) != spec['Sha256']:
            raise ValueError('Pinned artifact checksum mismatch.')
        binary = backup / 'candidate-binary'
        if self.role == 'Server':
            with tarfile.open(path, 'r:gz') as archive:
                seen, candidate = set(), None
                metadata = ('LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'RELEASE-' + spec['Version'] + '.md')
                for member in archive:
                    limit = 128 * 1024 ** 2 if member.name == 'may-monitor-server' else 1024 ** 2
                    if not member.isfile() or member.name not in ('may-monitor-server', *metadata) or member.name in seen or not 0 < member.size <= limit:
                        raise ValueError('Unexpected May server archive layout.')
                    seen.add(member.name)
                    if member.name == 'may-monitor-server':
                        candidate = member
                if candidate is None:
                    raise ValueError('Missing May server binary.')
                # Validate every member before materializing or executing the
                # candidate. Release notes must match this exact pinned version.
                with archive.extractfile(candidate) as source, binary.open('xb') as target:
                    shutil.copyfileobj(source, target, 65536)
        else:
            shutil.copyfile(path, binary)
        binary.chmod(0o700)
        check = self.host.run([str(binary), '--version'])
        if 'version ' + spec['Version'] not in check.stdout:
            raise ValueError('Artifact version differs from the reviewed release.')
        return binary

    def make_unit(self, configuration):
        command = self.binary + (' server --listen 127.0.0.1:' + str(configuration['Port']) if self.role == 'Server' else ' --config ' + self.config + '/config.json')
        environment = ('EnvironmentFile=' + self.config + '/runtime.env\nEnvironmentFile=-' + self.config + '/read-access.env\n') if self.role == 'Server' else ''
        capabilities = 'CapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW\n' if self.role == 'Agent' else 'CapabilityBoundingSet=\n'
        return ('# Managed by May VPS Deploy monitoring v1\n[Unit]\nDescription=May Monitor ' + self.role + '\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=exec\nUser=' + self.leaf + '\nGroup=' + self.leaf + '\nWorkingDirectory=' + self.data + '\nExecStart=' + command + '\n' + environment + capabilities + 'Restart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=' + self.data + '\nStandardOutput=append:' + self.data + '/logs/service.log\nStandardError=inherit\n[Install]\nWantedBy=multi-user.target\n').encode()

    def account(self, backup, record):
        try:
            account = pwd.getpwnam(self.leaf)
            if record['Before']['Hash'] == 'Absent':
                raise ValueError('Existing unowned monitoring system account.')
            return account
        except KeyError:
            if record['Before']['Hash'] != 'Absent':
                raise ValueError('Managed monitoring system account disappeared.')
        # A lost acknowledgement during account creation is ambiguous. Journal
        # intent first and refuse destructive recovery of an unconfirmed identity.
        record['CreatingAccount'] = True
        self.save_transaction(backup, record)
        self.host.run(['groupadd', '--system', self.leaf])
        self.host.run(['useradd', '--system', '--gid', self.leaf, '--home-dir', self.data, '--shell', '/usr/sbin/nologin', self.leaf])
        account = pwd.getpwnam(self.leaf)
        record['CreatedAccount'] = {'Uid': account.pw_uid, 'Gid': account.pw_gid}
        self.save_transaction(backup, record)
        return account

    def initialize(self, configuration, secrets):
        if self.role != 'Server':
            return
        base = 'http://127.0.0.1:' + str(configuration['Port'])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(50):
            try:
                with opener.open(base + '/ping', timeout=2) as response:
                    if response.status == 200 and response.read(32) == b'pong':
                        return
            except OSError:
                pass
            try:
                with opener.open(base + '/api/install/status', timeout=2) as response:
                    required = json.load(response)['data']['required']
                break
            except (OSError, ValueError, KeyError):
                time.sleep(.2)
        else:
            raise ValueError('May server initialization did not become ready.')
        if required:
            body = {'username': configuration['Username'], 'password': secrets['AdminPassword'], 'sitename': 'May Monitor', 'description': '', 'metric_dsn': './data/metrics.db'}
            request = urllib.request.Request(base + '/api/install/complete', canonical(body), {'Content-Type': 'application/json', 'X-May-Setup-Token': secrets['SetupToken']})
            try:
                with opener.open(request, timeout=25) as response:
                    response.read(65536)
            except (OSError, ValueError):
                raise ValueError('May server initialization was not confirmed.') from None
        for attempt in range(50):
            try:
                with opener.open(base + '/ping', timeout=2) as response:
                    if response.status == 200 and response.read(32) == b'pong':
                        return
            except OSError:
                pass
            time.sleep(.2)
        raise ValueError('May server readiness was not confirmed.')

    def verify_agent_credential(self, configuration, secrets):
        address = endpoint(configuration.get('Endpoint', ''))
        token = secrets.get('AgentToken', '')
        if not 12 <= len(token) <= 256 or token.startswith('may_read_') or any(ord(c) < 33 for c in token):
            raise ValueError('A dedicated May agent credential is required.')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        request = urllib.request.Request(address + '/api/clients/credential-check', canonical({'token': token}), {'Content-Type': 'application/json', 'User-Agent': 'May-VPS-Deploy/May-Monitor'})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=10) as response:
                raw = response.read(65537)
                if response.status != 200 or len(raw) > 65536:
                    raise ValueError('Invalid May agent credential check.')
                result = json.loads(raw)
            import uuid
            if result.get('schema_version') != 1 or str(uuid.UUID(result.get('uuid', ''))) != result['uuid']:
                raise ValueError('Unsupported May credential endpoint.')
            version(result.get('server_version', ''))
            configuration['ClientUUID'] = result['uuid']
            instance_id = result.get('server_instance_id', '')
            if instance_id:
                if str(uuid.UUID(instance_id)) != instance_id or uuid.UUID(instance_id).int == 0:
                    raise ValueError('Invalid May origin identity.')
                configuration['ServerInstanceId'] = instance_id
            return result
        except Exception:
            raise ValueError('May agent credential was not verified by the paired server.') from None

    def candidate_agent(self, configuration, secrets, current):
        import uuid
        if self.role != 'Agent' or not current['Installed'] or not current['Active']:
            raise ValueError('Configure a running owned agent; enable its service first if stopped.')
        if set(configuration) != {'Endpoint', 'ClientUUID', 'ServerInstanceId', 'ReplaceToken'} or type(configuration['ReplaceToken']) is not bool:
            raise ValueError('Explicit agent configuration and credential mode are required.')
        for name in ('ClientUUID', 'ServerInstanceId'):
            if str(uuid.UUID(configuration[name])) != configuration[name] or uuid.UUID(configuration[name]).int == 0:
                raise ValueError('Invalid expected May agent identity.')
        if current['Configuration'].get('ClientUUID') != configuration['ClientUUID']:
            raise ValueError('Agent maintenance cannot silently rebind the node.')
        saved = self.host.read_json(self.host.path(self.config + '/config.json'))
        if not configuration['ReplaceToken'] and endpoint(configuration['Endpoint']) == endpoint(saved['endpoint']):
            raise ValueError('Agent endpoint and credential are unchanged.')
        token = secrets.get('AgentToken', '') if configuration['ReplaceToken'] else saved['token']
        if not configuration['ReplaceToken'] and 'AgentToken' in secrets:
            import hmac
            if not hmac.compare_digest(secrets['AgentToken'].encode(), token.encode()):
                raise ValueError('Archived agent credential differs; explicitly provide the current credential.')
        confirmed = {'Endpoint': endpoint(configuration['Endpoint'])}
        response = self.verify_agent_credential(confirmed, {'AgentToken': token})
        if response.get('maintenance_schema_version') != 1 or confirmed.get('ClientUUID') != configuration['ClientUUID'] or confirmed.get('ServerInstanceId') != configuration['ServerInstanceId']:
            raise ValueError('The paired maintenance protocol, node or server identity does not match.')
        return confirmed, token

    def wait_agent_reports(self, configuration, token):
        import datetime
        deadline = time.monotonic() + 35
        reports = []
        while time.monotonic() < deadline:
            confirmed = {'Endpoint': configuration['Endpoint']}
            result = self.verify_agent_credential(confirmed, {'AgentToken': token})
            if confirmed.get('ClientUUID') != configuration['ClientUUID'] or confirmed.get('ServerInstanceId') != configuration['ServerInstanceId'] or result.get('maintenance_schema_version') != 1:
                raise ValueError('Agent source identity changed during verification.')
            try:
                captured = datetime.datetime.fromisoformat(result['captured_at'].replace('Z', '+00:00'))
                at = datetime.datetime.fromisoformat(result['report_at'].replace('Z', '+00:00'))
                now = datetime.datetime.now(datetime.timezone.utc)
                valid = result.get('online') is True and abs((now-captured).total_seconds()) <= 15 and -5 <= (captured-at).total_seconds() <= 15
            except (KeyError, TypeError, ValueError, AttributeError):
                valid = False
            if valid:
                if reports and at < reports[-1]:
                    raise ValueError('Agent report time moved backwards.')
                reports.append(at)
                if len(reports) >= 3 and len(set(reports)) >= 2:
                    return {'Status': 'Verified', 'Samples': len(reports), 'ReportAt': at.isoformat(), 'ClientUUID': confirmed['ClientUUID'], 'ServerInstanceId': confirmed['ServerInstanceId']}
            else:
                reports.clear()
            time.sleep(3)
        raise ValueError('Fresh advancing agent reports were not confirmed.')

    def verify_agent(self, expected=None):
        if self.role != 'Agent':
            raise ValueError('Agent verification requires its own scope.')
        state = self.inspect(expected)
        if not state['Installed'] or not state['Active']:
            raise ValueError('The selected May agent is not running.')
        saved = self.host.read_json(self.host.path(self.config + '/config.json'))
        confirmed = {'Endpoint': saved['endpoint']}
        self.verify_agent_credential(confirmed, {'AgentToken': saved['token']})
        if confirmed['ClientUUID'] != state['Configuration'].get('ClientUUID'):
            raise ValueError('The agent credential now belongs to another node.')
        return {'StateHash': state['Hash'], **confirmed}

    def apply(self, task, action, configuration, secrets, spec=None, repair_expected=None):
        backup, record = self.owned_transaction(task, ('Applying', 'Applied', 'CredentialRecoveryRequired') if repair_expected else ('Armed',))
        if repair_expected and (action != 'ConfigureAgent' or self.role != 'Agent' or record.get('Operation') != 'ConfigureAgent' or configuration.get('ReplaceToken') is not True):
            raise ValueError('Repair is limited to this pending agent configuration transaction.')
        current = self.inspect(repair_expected or record['Before']['Hash'])
        if action not in ('Install', 'Upgrade', 'ConfigureAgent', 'ConfigureRead', 'RevokeRead', 'ConfigureTheme', 'DisableTheme', 'Enable', 'Disable', 'Remove', 'Restore', 'Backup'):
            raise ValueError('Unsupported May monitoring action.')
        if action == 'Install' and current['Hash'] != 'Absent' or action not in ('Install', 'Restore') and not current['Installed']:
            raise ValueError('May monitoring installation state changed.')
        if action in ('Install', 'Upgrade'):
            # Reject incomplete controller input while the original service is
            # still running, before entering the applying phase or stopping it.
            if self.role == 'Server':
                if not 1024 <= configuration.get('Port', 0) <= 65535 or not re.fullmatch('[A-Za-z0-9_.-]{1,64}', configuration.get('Username', '')):
                    raise ValueError('Invalid May server configuration.')
                setup = secrets.get('SetupToken', '')
                if not re.fullmatch('[A-Za-z0-9_-]{32,128}', setup):
                    raise ValueError('Missing private initialization token.')
            else:
                endpoint(configuration.get('Endpoint', ''))
                token = secrets.get('AgentToken', '')
                if not 12 <= len(token) <= 256 or any(ord(c) < 33 for c in token):
                    raise ValueError('Invalid May agent credential.')
        candidate = self.asset(backup, spec) if action in ('Install', 'Upgrade') else None
        if action == 'Upgrade' and version(spec['Version']) <= version(current['Version']):
            raise ValueError('May downgrade or repeated upgrade refused.')
        if action == 'Upgrade' and any(current['Configuration'].get(key) != value for key, value in configuration.items()):
            raise ValueError('An upgrade cannot change the archived monitoring connection.')
        if self.role == 'Server' and action in ('Install', 'Upgrade'):
            import uuid
            configuration['InstanceId'] = current['Configuration'].get('InstanceId') or str(uuid.uuid4())
        if self.role == 'Agent' and action == 'Install':
            self.verify_agent_credential(configuration, secrets)
        agent_configuration = agent_token = None
        if action == 'ConfigureAgent':
            if repair_expected and configuration.get('ClientUUID') != record['Before']['Configuration'].get('ClientUUID'):
                raise ValueError('Repair cannot change the original May node identity.')
            agent_configuration, agent_token = self.candidate_agent(configuration, secrets, current)
        if action == 'RevokeRead' and (self.role != 'Server' or configuration):
            raise ValueError('Read revocation belongs to the selected May server only.')
        if action in ('ConfigureTheme', 'DisableTheme'):
            if self.role != 'Server' or set(configuration) != ({'ThemeLockSha256'} if action == 'ConfigureTheme' else set()):
                raise ValueError('Reviewed theme selection belongs to the server only.')
            if action == 'ConfigureTheme':
                self.reviewed_theme(configuration['ThemeLockSha256'])
        record['Operation'] = action
        record['Phase'] = 'Applying'
        self.save_transaction(backup, record)
        self.system('stop', self.unit, required=False)
        if self.active():
            raise ValueError('May service did not stop.')
        if self.role == 'Server' and action in ('Install', 'Upgrade'):
            with socket.socket() as listener:
                # Go's listener may leave accepted loopback connections in
                # TIME_WAIT after a clean stop. This still refuses a live
                # listener without treating those completed connections as one.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('127.0.0.1', configuration.get('Port', 0)))
        if action == 'Restore':
            self.restore_selected(backup, record, configuration)
        else:
            account = self.account(backup, record)
            data = self.host.path(self.data)
            data.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(data, 0o700); os.chown(data, account.pw_uid, account.pw_gid)
            logs = data / 'logs'; logs.mkdir(mode=0o700, exist_ok=True); os.chmod(logs, 0o700); os.chown(logs, account.pw_uid, account.pw_gid)
            config_dir = self.host.path(self.config); config_dir.mkdir(mode=0o750 if self.role == 'Agent' else 0o700, parents=True, exist_ok=True)
            os.chmod(config_dir, 0o750 if self.role == 'Agent' else 0o700); os.chown(config_dir, 0, account.pw_gid if self.role == 'Agent' else 0)
            if action in ('Install', 'Upgrade'):
                if self.role == 'Server':
                    theme = current['Configuration'].get('ThemeLockSha256')
                    theme_env = 'MAY_MONITOR_REVIEWED_THEME=' + theme + '\n' if theme else ''
                    self.write(backup, record, self.config + '/runtime.env', ('MAY_MONITOR_SETUP_TOKEN=' + setup + '\nMAY_MONITOR_INSTANCE_ID=' + configuration['InstanceId'] + '\n' + theme_env).encode())
                else:
                    address = endpoint(configuration.get('Endpoint', ''))
                    token = secrets.get('AgentToken', '')
                    agent_config = {'endpoint': address, 'token': token, 'interval': 3, 'info_report_interval': 5, 'reconnect_interval': 5, 'max_retries': -1, 'disable_web_ssh': True, 'disable_auto_update': True, 'ignore_unsafe_cert': False, 'get_ip_addr_from_nic': True}
                    self.write(backup, record, self.config + '/config.json', canonical(agent_config), 0o640, account.pw_gid)
                self.write(backup, record, self.binary, candidate.read_bytes(), 0o755)
                self.write(backup, record, '/etc/systemd/system/' + self.unit, self.make_unit(configuration), 0o644)
            if action == 'ConfigureRead':
                if self.role != 'Server':
                    raise ValueError('Read authorization belongs to the May server only.')
                authorization = configuration['ReadAuthorization']
                if set(authorization) != {'Sha256', 'Clients', 'ExpiresAt'} or not re.fullmatch('[a-f0-9]{64}', authorization['Sha256']) or not 0 < len(authorization['Clients']) <= 100:
                    raise ValueError('Invalid read-only authorization.')
                import datetime
                import uuid
                ids = authorization['Clients']
                if len(set(ids)) != len(ids) or any(str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0 for value in ids):
                    raise ValueError('Invalid read-only node scope.')
                expires = datetime.datetime.fromisoformat(authorization['ExpiresAt'].replace('Z', '+00:00'))
                remaining = expires - datetime.datetime.now(datetime.timezone.utc)
                if not datetime.timedelta(0) < remaining <= datetime.timedelta(days=90):
                    raise ValueError('Invalid read-only authorization expiry.')
                text = 'MAY_MONITOR_READ_TOKEN_SHA256=' + authorization['Sha256'] + '\nMAY_MONITOR_READ_CLIENT_UUIDS=' + ','.join(ids) + '\nMAY_MONITOR_READ_EXPIRES_AT=' + authorization['ExpiresAt'] + '\n'
                self.write(backup, record, self.config + '/read-access.env', text.encode())
            if action == 'RevokeRead':
                self.write(backup, record, self.config + '/read-access.env', None)
            if action in ('ConfigureTheme', 'DisableTheme'):
                lines = self.host.path(self.config + '/runtime.env').read_text().splitlines()
                lines = [line for line in lines if not line.startswith('MAY_MONITOR_REVIEWED_THEME=')]
                if action == 'ConfigureTheme':
                    lines.append('MAY_MONITOR_REVIEWED_THEME=' + configuration['ThemeLockSha256'])
                self.write(backup, record, self.config + '/runtime.env', ('\n'.join(lines) + '\n').encode())
            if action == 'ConfigureAgent':
                saved = self.host.read_json(self.host.path(self.config + '/config.json'))
                saved.update(endpoint=agent_configuration['Endpoint'], token=agent_token)
                if saved.get('disable_web_ssh') is not True or saved.get('disable_auto_update') is not True or saved.get('ignore_unsafe_cert') is not False:
                    raise ValueError('Agent maintenance cannot expand remote-control or TLS policy.')
                self.write(backup, record, self.config + '/config.json', canonical(saved), 0o640, account.pw_gid)
            if action == 'Remove':
                for name in self.files:
                    self.write(backup, record, name, None)
            old_meta = self.host.read_json(self.host.path(self.meta)) if self.host.path(self.meta).exists() else {}
            public_configuration = configuration if action == 'Install' else dict(old_meta['Configuration'])
            if self.role == 'Server' and action == 'Upgrade':
                public_configuration['InstanceId'] = configuration['InstanceId']
            if action == 'ConfigureAgent':
                public_configuration = agent_configuration
            if action == 'ConfigureRead':
                public_configuration['ReadAuthorization'] = configuration['ReadAuthorization']
            if action == 'RevokeRead':
                public_configuration.pop('ReadAuthorization', None)
            if action == 'ConfigureTheme':
                public_configuration['ThemeLockSha256'] = configuration['ThemeLockSha256']
            if action == 'DisableTheme':
                public_configuration.pop('ThemeLockSha256', None)
            public_configuration = {key: value for key, value in public_configuration.items() if key in ('Port', 'Username', 'Endpoint', 'ClientUUID', 'InstanceId', 'ServerInstanceId', 'ReadAuthorization', 'ThemeLockSha256')}
            meta = {'SchemaVersion': SCHEMA, 'Role': self.role, 'Uid': account.pw_uid, 'Gid': account.pw_gid, 'Installed': action != 'Remove', 'Version': spec['Version'] if candidate else old_meta['Version'], 'Configuration': public_configuration, 'Files': {name: digest(self.host.path(name)) if self.host.path(name).is_file() else None for name in self.files}}
            self.write(backup, record, self.meta, canonical(meta))
        self.system('daemon-reload')
        target = record.get('RestoredState', record['Before'])
        should_enable = action in ('Install', 'Enable') or action not in ('Disable', 'Remove') and target['Enabled']
        should_start = action in ('Install', 'Enable') or action not in ('Disable', 'Remove') and target['Active']
        if action == 'Remove':
            self.system('disable', self.unit, required=False)
        else:
            self.system('enable' if should_enable else 'disable', self.unit)
            if should_start:
                self.system('start', self.unit)
                time.sleep(.3)
                if not self.active():
                    raise ValueError('May service failed its startup check.')
                self.host.verify_process(self.unit, self.binary)
                self.initialize(self.host.read_json(self.host.path(self.meta))['Configuration'], secrets)
        after = self.inspect()
        if action == 'ConfigureAgent':
            after['ConnectionVerification'] = self.wait_agent_reports(agent_configuration, agent_token)
        record['After'] = after
        record['Phase'] = 'Applied'
        self.save_transaction(backup, record)
        return after

    def restore_selected(self, backup, record, configuration):
        old_task = configuration.get('RestoreTask', '')
        old_backup, old = self.transaction(old_task)
        if not old['Before']['Installed'] or old['Phase'] not in ('Committed', 'RolledBack') or old.get('BackupSha256') != configuration.get('RestoreSha256') or digest(old_backup / 'files.tar.gz') != old['BackupSha256']:
            raise ValueError('Unknown or inconsistent May restore point.')
        self.restore_files(backup, record, old_backup / 'files.tar.gz')
        record['RestoredState'] = old['Before']

    def restore_files(self, backup, record, source):
        allowed = (*self.files, self.meta, self.data)
        with tarfile.open(source, 'r:gz') as archive:
            members, names, total = [], set(), 0
            for member in archive:
                name = '/' + member.name.rstrip('/')
                total += member.size
                if len(members) >= 100000 or total > MAX_BACKUP or name in names:
                    raise ValueError('Oversized or duplicate May restore snapshot.')
                if any(part in ('', '.', '..') for part in member.name.rstrip('/').split('/')) or member.name.startswith('/') or not (name in allowed or name.startswith(self.data + '/')) or not (member.isdir() or member.isfile()) or member.mode & ~0o777:
                    raise ValueError('Restore snapshot escapes selected May scope.')
                if name in (*self.files, self.meta) and (not member.isfile() or member.size > 128 * 1024 ** 2):
                    raise ValueError('Invalid May configuration snapshot member.')
                names.add(name); members.append(member)
            identities = [m for m in members if '/' + m.name == self.meta]
            identity = None
            if identities:
                if identities[0].size > 1024 ** 2:
                    raise ValueError('Oversized May snapshot manifest.')
                with archive.extractfile(identities[0]) as stream:
                    identity = json.load(stream)
                account = pwd.getpwnam(self.leaf)
                if identity.get('Role') != self.role or identity.get('Uid') != account.pw_uid or identity.get('Gid') != account.pw_gid:
                    raise ValueError('May restore identity changed.')
            elif members:
                raise ValueError('May snapshot has no ownership manifest.')
            for member in members:
                name = '/' + member.name.rstrip('/')
                if name in (*self.files, self.meta):
                    mode = 0o755 if name == self.binary else 0o644 if name.endswith('.service') else 0o640 if self.role == 'Agent' and name.endswith('/config.json') else 0o600
                    gid = identity['Gid'] if self.role == 'Agent' and name.endswith('/config.json') else 0
                    if member.uid != 0 or member.gid != gid or member.mode != mode:
                        raise ValueError('May snapshot file permissions changed.')
                elif member.uid not in (0, identity['Uid']) or member.gid not in (0, identity['Gid']):
                    raise ValueError('May snapshot data belongs to another identity.')
        # Preserve the failed/current data instead of overwriting evidence.
        data = self.host.path(self.data)
        if data.exists():
            self.tree(data)
            data.rename(backup / ('preserved-data-' + str(time.time_ns())))
        with tarfile.open(source, 'r:gz') as archive:
            for name in (*self.files, self.meta):
                if name not in names:
                    self.write(backup, record, name, None)
            for member in members:
                path = self.host.path('/' + member.name.rstrip('/'))
                if member.isdir():
                    path.mkdir(parents=True, mode=member.mode & 0o777, exist_ok=True)
                elif '/' + member.name not in (self.meta, *self.files):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(member) as content, path.open('xb') as target:
                        shutil.copyfileobj(content, target, 65536)
                else:
                    with archive.extractfile(member) as content:
                        self.write(backup, record, '/' + member.name, content.read(128 * 1024 ** 2 + 1), member.mode & 0o777, member.gid)
                os.chmod(path, member.mode & 0o777)
                os.chown(path, member.uid, member.gid)
        config = self.host.path(self.config)
        if identity and config.exists():
            os.chmod(config, 0o750 if self.role == 'Agent' else 0o700)
            os.chown(config, 0, identity['Gid'] if self.role == 'Agent' else 0)

    def finish(self, task, rollback=False):
        backup, record = self.transaction(task)
        if record['Phase'] in ('Committed', 'RolledBack'):
            return {'Phase': record['Phase'], 'State': self.inspect()}
        self.owned_transaction(task, ('Preparing', 'Armed', 'Applying', 'Applied', 'CredentialRecoveryRequired'))
        if not rollback and record['Phase'] not in ('Armed', 'Applied'):
            raise ValueError('Cannot commit an incomplete May operation.')
        if rollback and record['Phase'] == 'Applying' and record.get('Operation') == 'Upgrade' and not record['Writes'] and record['Before']['Installed']:
            # A stopped upgrade with no file writes must not rewind metrics to
            # its earlier snapshot. Prove the entire original file identity,
            # restore only its runtime flags, then release the owned transaction.
            self.inspect()
            meta = self.host.read_json(self.host.path(self.meta))
            files = {name: digest(self.host.path(name)) if self.host.path(name).is_file() else None for name in self.files}
            identity = hashlib.sha256(canonical({'Manifest': meta, 'Files': files, 'Active': record['Before']['Active'], 'Enabled': record['Before']['Enabled']})).hexdigest()
            if identity != record['Before']['Hash']:
                raise ValueError('External edits block automatic May recovery.')
            for command, flag in (('enable', record['Before']['Enabled']), ('start', record['Before']['Active'])):
                self.system(command if flag else ('disable' if command == 'enable' else 'stop'), self.unit, required=flag)
            self.inspect(record['Before']['Hash'])
            record['Phase'] = 'RolledBack'
            rollback = False
        if rollback and record['Phase'] in ('Preparing', 'Armed') and not record['Writes']:
            self.inspect(record['Before']['Hash'])
            record['Phase'] = 'RolledBack'
            rollback = False
        if rollback:
            self.check_overrides()
            if self.active():
                self.host.verify_process(self.unit, self.binary)
            if record.get('CreatingAccount') and not record.get('CreatedAccount'):
                for lookup in (pwd.getpwnam, grp.getgrnam):
                    try:
                        lookup(self.leaf)
                    except KeyError:
                        pass
                    else:
                        raise ValueError('Unconfirmed May account creation requires review.')
            config = self.host.path(self.config)
            if config.exists():
                expected_names = {Path(name).name for name in (*self.files, self.meta) if name.startswith(self.config + '/')}
                if not config.is_dir() or any(p.name not in expected_names for p in config.iterdir()):
                    raise ValueError('Unmanaged configuration blocks May recovery.')
                gid = record.get('CreatedAccount', {}).get('Gid', grp.getgrnam(self.leaf).gr_gid) if self.role == 'Agent' else 0
                if config.stat().st_uid != 0 or config.stat().st_gid != gid or stat.S_IMODE(config.stat().st_mode) != (0o750 if self.role == 'Agent' else 0o700):
                    raise ValueError('External directory edits block May recovery.')
            # Every write is journaled before it happens. External edits are
            # refused rather than replaced by an old snapshot.
            for name in (*self.files, self.meta):
                path = self.host.path(name)
                if path.exists():
                    mode = 0o755 if name == self.binary else 0o644 if name.endswith('.service') else 0o640 if self.role == 'Agent' and name.endswith('/config.json') else 0o600
                    gid = grp.getgrnam(self.leaf).gr_gid if self.role == 'Agent' and name.endswith('/config.json') else 0
                    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_uid != 0 or path.stat().st_gid != gid or stat.S_IMODE(path.stat().st_mode) != mode:
                        raise ValueError('External file permissions block May recovery.')
                actual = digest(path) if path.is_file() else None
                values = record['Writes'].get(name)
                if values is None:
                    if record['Phase'] == 'Preparing':
                        continue
                    with tarfile.open(backup / 'files.tar.gz', 'r:gz') as archive:
                        members = [m for m in archive.getmembers() if '/' + m.name == name]
                        values = [hashlib.sha256(archive.extractfile(members[0]).read()).hexdigest()] if members else [None]
                if actual not in values:
                    raise ValueError('External edits block automatic May recovery.')
            self.system('stop', self.unit, required=False)
            if self.active():
                raise ValueError('May service is still active; restore refused.')
            if record.get('BackupSha256'):
                if digest(backup / 'files.tar.gz') != record['BackupSha256']:
                    raise ValueError('May snapshot checksum changed.')
                self.restore_files(backup, record, backup / 'files.tar.gz')
            self.system('daemon-reload')
            for command, flag in (('enable', record['Before']['Enabled']), ('start', record['Before']['Active'])):
                self.system(command if flag else ('disable' if command == 'enable' else 'stop'), self.unit, required=flag)
            if not record['Before']['Installed'] and record.get('CreatedAccount'):
                account = pwd.getpwnam(self.leaf)
                if account.pw_uid != record['CreatedAccount']['Uid'] or account.pw_dir != self.data:
                    raise ValueError('May account identity changed during recovery.')
                self.host.run(['userdel', self.leaf])
                self.host.run(['groupdel', self.leaf])
                config_dir = self.host.path(self.config)
                if config_dir.exists():
                    config_dir.rmdir()
            self.inspect(record['Before']['Hash'])
            if record.get('Operation') == 'ConfigureAgent' and record['Before']['Active']:
                saved = self.host.read_json(self.host.path(self.config + '/config.json'))
                try:
                    self.wait_agent_reports(record['Before']['Configuration'], saved['token'])
                except ValueError:
                    record['Phase'] = 'CredentialRecoveryRequired'
                    self.save_transaction(backup, record)
                    self.system('stop', 'may-monitor-rollback-' + task + '.timer', required=False)
                    raise ValueError('Files restored but agent connection is not verified; explicit credential repair is required.') from None
            record['Phase'] = 'RolledBack'
        elif record['Phase'] != 'RolledBack':
            if record['Phase'] == 'Applied' and self.inspect()['Hash'] != record['After']['Hash']:
                raise ValueError('May state changed before commit.')
            if record['Phase'] == 'Armed':
                self.inspect(record['Before']['Hash'])
            record['Phase'] = 'Committed'
        self.save_transaction(backup, record)
        owner = self.host.path(OWNER)
        if owner.read_text().strip() != str(backup):
            raise ValueError('Remote transaction owner changed.')
        owner.unlink()
        self.system('stop', 'may-monitor-rollback-' + task + '.timer', required=False)
        return {'Phase': record['Phase'], 'State': self.inspect()}


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('VPS_PARAM_ACTION', '')
    task = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('VPS_PARAM_TASK_ID', '')
    role = sys.argv[3] if len(sys.argv) > 3 else os.environ.get('VPS_PARAM_ROLE', '')
    host = Host()
    if os.geteuid() != 0:
        raise ValueError('Monitoring maintenance requires the reviewed root session.')
    reading = action in ('Check', 'Transaction', 'VerifyAgent', 'ValidateAgentConfiguration')
    lock_path = host.path('/var/lib/may-vps-deploy/transaction.lock')
    if not reading:
        lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_context = lock_path.open('r' if reading else 'a') if lock_path.exists() or not reading else contextlib.nullcontext()
    with lock_context as lock:
        if lock is not None:
            fcntl.flock(lock, (fcntl.LOCK_SH if reading else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        lifecycle = Lifecycle(host, role)
        if action == 'Check':
            result = lifecycle.inspect(os.environ.get('VPS_PARAM_EXPECTED_HASH'))
        elif action == 'VerifyAgent':
            result = lifecycle.verify_agent(os.environ.get('VPS_PARAM_EXPECTED_HASH'))
        elif action == 'ValidateAgentConfiguration':
            current = lifecycle.inspect(os.environ['VPS_PARAM_EXPECTED_HASH'])
            confirmed, _ = lifecycle.candidate_agent(json.loads(os.environ['VPS_PARAM_CONFIGURATION']), json.loads(os.environ.get('VPS_PARAM_PRIVATE', '{}')), current)
            result = {'StateHash': current['Hash'], 'Configuration': confirmed}
        elif action == 'Begin':
            result = lifecycle.begin(task, os.environ['VPS_PARAM_EXPECTED_HASH'], os.environ['VPS_MAY_MONITOR_PROGRAM'])
        elif action == 'Apply':
            result = lifecycle.apply(task, os.environ['VPS_PARAM_OPERATION'], json.loads(os.environ['VPS_PARAM_CONFIGURATION']), json.loads(os.environ.get('VPS_PARAM_PRIVATE', '{}')), json.loads(os.environ['VPS_PARAM_ASSET']) if 'VPS_PARAM_ASSET' in os.environ else None)
        elif action == 'RepairAgent':
            result = lifecycle.apply(task, 'ConfigureAgent', json.loads(os.environ['VPS_PARAM_CONFIGURATION']), json.loads(os.environ['VPS_PARAM_PRIVATE']), repair_expected=os.environ['VPS_PARAM_EXPECTED_HASH'])
        elif action in ('Commit', 'Rollback'):
            result = lifecycle.finish(task, action == 'Rollback')
        elif action == 'Transaction':
            record_path = lifecycle.backup_path(task) / 'transaction.json'
            if not record_path.exists() and not host.path(OWNER).exists():
                result = {'Phase': 'None', 'TaskId': task, 'Role': role}
            else:
                _, record = lifecycle.transaction(task)
                result = {'Phase': record['Phase'], 'TaskId': record['TaskId'], 'Role': record['Role']}
        else:
            raise ValueError('Unsupported monitoring lifecycle command.')
    print('VPSDEPLOY_MAY_MONITOR_RESULT_B64=' + base64.b64encode(canonical(result)).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never include configuration, HTTP bodies, initialization links or
        # credential-bearing exception messages in the controller's task log.
        print('May Monitor lifecycle could not be confirmed; inspect its owned transaction.', file=sys.stderr)
        raise SystemExit(1)
