"""Owned forwarding resources and scoped recovery; transport drivers supply material.
No production path overrides are exposed by the command-line entry points.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tarfile


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


class ForwardHost:
    def __init__(self, root=Path('/'), run=subprocess.run, archived_hash=None):
        self.root, self.run, self.archived_hash = root, run, archived_hash

    def path(self, absolute):
        return self.root / absolute.lstrip('/')

    def regular(self, absolute, missing=False):
        path = self.path(absolute)
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise ValueError('Linked forwarding path; refusing to overwrite.')
        if path.exists() and not path.is_file() or not missing and not path.is_file():
            raise ValueError('Missing or non-regular forwarding file.')
        return path

    def command(self, args, check=True):
        response = self.run(args, capture_output=True, text=True, timeout=25)
        if check and response.returncode:
            raise ValueError('Forwarding host command failed: ' + args[0] + ' ' + args[1])
        return response

    def table(self):
        tables = json.loads(self.command(['nft', '-j', 'list', 'tables']).stdout)
        exists = any(v.get('table', {}).get('family') == 'inet' and v.get('table', {}).get('name') == self.TABLE for v in tables['nftables'])
        if not exists:
            return None
        return self.canonical_table(self.command(['nft', '-s', '-nn', 'list', 'table', 'inet', self.TABLE]).stdout)

    def units(self):
        base = self.path('/etc/systemd/system')
        return sorted('/etc/systemd/system/' + p.name for p in base.glob(self.PREFIX + '-*'))

    def state(self, unit):
        return {'Enabled': self.command(['systemctl', 'is-enabled', '--quiet', unit], False).returncode == 0,
                'Active': self.command(['systemctl', 'is-active', '--quiet', unit], False).returncode == 0}

    def identity(self, paths):
        return {'Files': {p: digest(self.regular(p).read_bytes()) if self.regular(p, True).exists() else None for p in paths},
                'Table': self.table()}

    def read(self):
        path = self.regular(self.CONFIG, True)
        if not path.exists():
            if self.units() or self.path(self.DIRECTORY).exists() and list(self.path(self.DIRECTORY).iterdir()) or self.table() is not None:
                raise ValueError('Unmanaged forwarding resources occupy the component namespace.')
            # Vendor/run units or drop-ins also own this namespace, even without /etc files.
            for directory in ('/run/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
                if any(self.path(directory).glob(self.PREFIX + '-*')):
                    raise ValueError('Unmanaged forwarding units occupy the component namespace.')
            return {'Hash': 'Absent', 'Configuration': None, 'Files': {}, 'Units': {}, 'Table': None}
        if path.stat().st_size > 131072:
            raise ValueError('Forwarding configuration exceeds its size limit.')
        config = self.normalize(json.loads(path.read_text()))
        files = self.material(config, self.proxy())
        if set(self.units()) != {p for p in files if p.startswith('/etc/systemd/system/')} or set(p.name for p in self.path(self.DIRECTORY).iterdir()) != {Path(p).name for p in files if p.startswith(self.DIRECTORY + '/')}:
            raise ValueError('Unknown forwarding files or unit overrides; review required.')
        archived_units = False
        for target, content in files.items():
            actual = self.regular(target).read_bytes()
            # Installed program bytes are pinned by the controller's archived
            # resource hash. They may predate this app; a reviewed save updates
            # them without adopting an externally changed hash.
            if len(actual) > 131072:
                raise ValueError('Forwarding files changed outside this application.')
            if target not in self.ARCHIVED_PROGRAMS and actual != content.encode():
                if not (target.startswith('/etc/systemd/system/') and actual.startswith(content.splitlines()[0].encode() + b'\n') and re.fullmatch(r'[a-f0-9]{64}', self.archived_hash or '')):
                    raise ValueError('Forwarding files changed outside this application.')
                archived_units = True
        if self.table() != self.canonical_table(files[self.ACL]):
            raise ValueError('Forwarding whitelist runtime differs from its archive.')
        units = {}
        for target in files:
            if not target.startswith('/etc/systemd/system/'):
                continue
            unit = Path(target).name
            fragment = self.command(['systemctl', 'show', unit, '-p', 'FragmentPath', '--value']).stdout.strip()
            dropins = self.command(['systemctl', 'show', unit, '-p', 'DropInPaths', '--value']).stdout.strip()
            if fragment != target or dropins:
                raise ValueError('Forwarding service identity or overrides differ.')
            if unit.endswith('.socket') or unit == self.ACL_UNIT:
                units[unit] = self.state(unit)
        expected = {self.unit_name(r, 'socket'): {'Enabled': r['Enabled'], 'Active': r['Enabled']} for r in config['Rules']}
        expected[self.ACL_UNIT] = {'Enabled': True, 'Active': True}
        if units != expected:
            raise ValueError('Forwarding activation state differs from the saved rules.')
        identity = self.identity(files)
        fingerprint = digest(encoded(dict(identity, Units=units)))
        if archived_units and fingerprint != self.archived_hash:
            raise ValueError('Installed forwarding units do not match the controller archive.')
        return {'Hash': fingerprint, 'Configuration': config, 'Files': identity['Files'], 'Units': units, 'Table': identity['Table'], 'TemplateCurrent': not archived_units}

    def preflight(self, config):
        observed = self.read()
        if not self.path('/usr/sbin/nft').is_file():
            raise ValueError('Missing nftables; install it before forwarding maintenance.')
        self.proxy()
        old = observed['Configuration'] or {'Rules': []}
        existing = {(f, p) for r in old['Rules'] if r['Enabled'] for f, _, p in self.listeners(r)}
        local = json.loads(self.command(['ip', '-j', 'address', 'show']).stdout)
        addresses = {a['local'] for item in local for a in item.get('addr_info', [])}
        ports = {r['ListenPort'] for r in config['Rules']}
        for rule in config['Rules']:
            if rule['TargetPort'] in ports and (ipaddress.ip_address(rule['TargetAddress']).is_loopback or rule['TargetAddress'] in addresses):
                raise ValueError('Forwarding target would form a local loop.')
            if not rule['Enabled']:
                continue
            for family, address, port in self.listeners(rule):
                if (family, port) in existing:
                    continue
                with socket.socket(family, self.SOCKET_TYPE) as listener:
                    if self.SOCKET_TYPE == socket.SOCK_STREAM:
                        # systemd listeners also use SO_REUSEADDR. Closed TCP
                        # sessions in TIME_WAIT must not masquerade as a live
                        # listener when a reviewed route is removed/recreated.
                        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if family == socket.AF_INET6:
                        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    listener.bind((address, port))
        return observed

    def snapshot(self, backup, expected=None):
        observed = self.read()
        if expected is not None and observed['Hash'] != expected:
            raise ValueError('Forwarding resources changed before the snapshot.')
        journal = {'Version': 1, 'Original': {'Files': observed['Files'], 'Table': observed['Table']}, 'OriginalUnits': observed['Units']}
        self.write_journal(backup, journal)

    def write_journal(self, backup, journal):
        path = backup / self.JOURNAL
        if path.is_symlink() or backup.is_symlink():
            raise ValueError('Linked forwarding recovery path.')
        temporary = backup / self.JOURNAL.removesuffix('.json')
        temporary = temporary.with_suffix('.new')
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(encoded(journal))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def journal(self, backup):
        if not re.fullmatch(r'/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle', str(backup)):
            raise ValueError('Invalid forwarding transaction path.')
        path = self.regular(str(backup) + '/' + self.JOURNAL)
        value = json.loads(path.read_text())
        if value.get('Version') != 1:
            raise ValueError('Unsupported forwarding recovery version.')
        if type(value.get('Recovering', False)) is not bool:
            raise ValueError('Invalid forwarding recovery state.')
        for group in ('Original', 'Applied'):
            for name in value.get(group, {}).get('Files', {}):
                base = name.removesuffix('.may-new')
                if base not in (self.CONFIG, self.ACL, *self.EXTRA_FILES) and base != self.unit_path(self.ACL_UNIT) and not re.fullmatch(r'/etc/systemd/system/' + re.escape(self.PREFIX) + r'-[a-f0-9]{32}\.(socket|service)', base):
                    raise ValueError('Unowned forwarding recovery path.')
        return value

    def stop(self, files):
        names = [Path(p).name for p in files if p.startswith('/etc/systemd/system/')]
        for suffix in ('.socket', '.service'):
            for name in names:
                if name.endswith(suffix) and name != self.ACL_UNIT:
                    self.command(['systemctl', 'disable', '--now', name], False)
                    state = self.state(name)
                    if state['Active'] or name.endswith('.socket') and state['Enabled']:
                        raise ValueError('Forwarding unit did not stop.')
        if self.ACL_UNIT in names:
            self.command(['systemctl', 'disable', '--now', self.ACL_UNIT], False)
            state = self.state(self.ACL_UNIT)
            if state['Active'] or state['Enabled']:
                raise ValueError('Forwarding whitelist did not stop.')

    def write(self, name, content):
        path = self.regular(name, True)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.may-new')
        with temporary.open('xb') as stream:
            stream.write(content.encode())
        os.chmod(temporary, 0o600 if name in (self.CONFIG, self.ACL) else 0o644)
        os.replace(temporary, path)

    def activate(self, config):
        self.command(['systemctl', 'daemon-reload'])
        self.command(['systemctl', 'enable', '--now', self.ACL_UNIT])
        for rule in config['Rules']:
            name = self.unit_name(rule, 'socket')
            self.command(['systemctl', 'enable', '--now', name] if rule['Enabled'] else ['systemctl', 'disable', '--now', name])

    def apply(self, config, expected, action, backup):
        previous = self.preflight(config)
        if previous['Hash'] != expected:
            raise ValueError('Forwarding resources changed after review.')
        journal = self.journal(backup)
        if journal['Original'] != self.identity(previous['Files']):
            raise ValueError('Forwarding resources changed after the snapshot.')
        files = self.material(config, self.proxy()) if action == 'Apply' else {}
        paths = sorted(set(previous['Files']) | set(files))
        planned = {p: digest(files[p]) if p in files else None for p in paths}
        planned.update({p + '.may-new': digest(content) for p, content in files.items()})
        journal['Applied'] = {'Files': planned, 'Table': self.canonical_table(files[self.ACL]) if files else None}
        self.write_journal(self.path(str(backup)), journal)
        # Intent precedes the first resource change. Recovery accepts only the
        # original or reviewed bytes, including an interrupted mixed write.
        self.stop(previous['Files'])
        for name in paths:
            if name in files:
                self.write(name, files[name])
            else:
                path = self.regular(name, True)
                if path.exists():
                    path.unlink()
        if files:
            self.command(['nft', '-c', '-f', self.ACL])
            self.activate(config)
        else:
            self.command(['systemctl', 'daemon-reload'])
            if self.path(self.DIRECTORY).is_dir():
                self.path(self.DIRECTORY).rmdir()
        return self.read()

    def rollback_check(self, backup):
        journal = self.journal(backup)
        paths = sorted(set(journal['Original']['Files']) | set(journal.get('Applied', {}).get('Files', {})))
        actual = self.identity(paths)
        if set(self.units()) - set(paths):
            raise ValueError('Unknown forwarding resources appeared during maintenance.')
        for path, current in actual['Files'].items():
            allowed = (journal['Original']['Files'].get(path), journal.get('Applied', {}).get('Files', {}).get(path))
            if current not in allowed and not (current is None and journal.get('Recovering', False)):
                raise ValueError('Forwarding file changed externally; recovery refused.')
        # Stopping the owned firewall intentionally removes its table.
        if actual['Table'] not in (None, journal['Original']['Table'], journal.get('Applied', {}).get('Table')):
            raise ValueError('Forwarding whitelist changed externally; recovery refused.')
        archive = self.regular(str(backup) + '/protocol-files.tar.gz')
        with tarfile.open(archive) as saved:
            for path, expected in journal['Original']['Files'].items():
                matches = [m for m in saved.getmembers() if m.name == path.lstrip('/')]
                if len(matches) != 1 or not matches[0].isfile() or digest(saved.extractfile(matches[0]).read()) != expected:
                    raise ValueError('Forwarding recovery archive does not match its snapshot.')
        return journal, paths

    def rollback_prepare(self, backup):
        journal, paths = self.rollback_check(backup)
        # Recovery may stop between removing reviewed files and restoring the
        # snapshot. Record that intent so another recovery can finish safely.
        journal['Recovering'] = True
        self.write_journal(self.path(str(backup)), journal)
        self.stop(paths)
        for name in paths:
            path = self.regular(name, True)
            if path.exists():
                path.unlink()

    def rollback_complete(self, backup):
        journal = self.journal(backup)
        if journal['Original']['Files']:
            self.archived_hash = digest(encoded(dict(journal['Original'], Units=journal['OriginalUnits'])))
            config = self.normalize(json.loads(self.regular(self.CONFIG).read_text()))
            self.activate(config)
            observed = self.read()
            if observed['Files'] != journal['Original']['Files'] or observed['Units'] != journal['OriginalUnits']:
                raise ValueError('Forwarding recovery did not restore the original resources.')
        else:
            self.command(['systemctl', 'daemon-reload'])
            base = self.path(self.DIRECTORY)
            if base.is_dir():
                base.rmdir()
            if self.read()['Hash'] != 'Absent':
                raise ValueError('Forwarding recovery is incomplete.')
        journal['Recovering'] = False
        self.write_journal(self.path(str(backup)), journal)
