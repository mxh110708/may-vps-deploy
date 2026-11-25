"""Scoped address transactions. Entry points accept no filesystem overrides.
The injected host modules are pinned application resources, not downloaded code.
"""
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def replace(value, addresses):
    if value in addresses:
        return addresses[value]
    for old, new in addresses.items():
        suffix = '/128' if ':' in old else '/32'
        if value == old + suffix:
            return new + suffix
        if value.startswith('[' + old + ']:'):
            return '[' + new + ']:' + value[len(old) + 3:]
        if ':' not in old and value.startswith(old + ':') and value[len(old) + 1:].isdigit():
            return new + value[len(old):]
    return value


FIELDS = {'IPv4', 'IPv6', 'Endpoint', 'SourceAddress', 'FrontSourceAddress', 'TargetAddress', 'BackupAddress',
          'ExpectedAddress', 'ProbeDestination', 'PrimaryExit', 'BackupExit', 'Address', 'EndpointAddress', 'LandingAddress', 'FrontAddress',
          'RelayAddress', 'server', 'address', 'listen', 'sendThrough', 'bind_address',
          'inet4_bind_address', 'inet6_bind_address'}
LISTS = {'TrustedEntryIPv4s', 'TrustedEntryIPv6s', 'AllowedSources', 'FrontSources', 'TrustedSources'}


def rewrite(value, addresses, bridge=False, sources_only=False):
    result = copy.deepcopy(value)
    if isinstance(result, dict):
        for key, item in list(result.items()):
            if not sources_only and key in FIELDS and isinstance(item, str):
                result[key] = replace(item, addresses)
            elif not sources_only and key == 'ExpectedExits' and isinstance(item, dict):
                result[key] = {identity: replace(address, addresses) for identity, address in item.items()}
            elif key in LISTS and isinstance(item, list):
                result[key] = list(dict.fromkeys(v for s in item for v in
                    ([s, replace(s, addresses)] if bridge else [replace(s, addresses)])))
            elif isinstance(item, (dict, list)):
                result[key] = rewrite(item, addresses, bridge, sources_only)
    elif isinstance(result, list):
        result = [rewrite(v, addresses, bridge, sources_only) for v in result]
    return result


def merge_sources(value, bridge):
    result = copy.deepcopy(value)
    if isinstance(result, dict):
        for key, item in list(result.items()):
            if key in LISTS and key in bridge:
                result[key] = copy.deepcopy(bridge[key])
            elif isinstance(item, (dict, list)) and key in bridge:
                result[key] = merge_sources(item, bridge[key])
    elif isinstance(result, list) and len(result) == len(bridge):
        result = [merge_sources(a, b) for a, b in zip(result, bridge)]
    return result


def physical(value):
    if isinstance(value, dict):
        return {k: physical(v) for k, v in value.items() if not k.endswith('Fingerprint')}
    if isinstance(value, list):
        return [physical(v) for v in value]
    return value


def module(name, extra=''):
    namespace = {'__name__': 'may_address_embedded'}
    exec(extra + '\n' + ADDRESS_SOURCES[name], namespace)
    return namespace


class Adapter:
    def __init__(self, resource, root, run, addresses):
        self.r, self.root, self.run, self.addresses = resource, root, run, addresses
        self.kind = resource['Kind']
        self.host = None
        self.ns = None
        if self.kind in ('TcpForwarding', 'UdpForwarding'):
            seed = '\n'.join(k + ' = ' + repr(ADDRESS_SOURCES[v]) for k, v in
                [('TCP_PROXY_WORKER_SOURCE', 'tcp-proxy-worker'), ('UDP_WORKER_SOURCE', 'udp-forward-worker'),
                 ('FORWARD_GROUP_SOURCE', 'forward-target-groups'), ('FORWARD_GROUP_WORKER_SOURCE', 'forward-group-worker'), ('PROXY_HEALTH_SOURCE', 'forward-proxy-health')])
            ns = module('forwarding-host', seed)
            exec(ADDRESS_SOURCES['tcp-forwarding' if self.kind == 'TcpForwarding' else 'udp-forwarding'], ns)
            self.host, self.ns = ns['Host'](root=root, run=run, archived_hash=resource['ExpectedHash']), ns
        elif self.kind in ('WireGuardTunnel', 'WireGuardTunnel2'):
            slot = int(self.kind.endswith('2'))
            runtime = 'WG_SLOT = ' + str(slot) + '\n' + ADDRESS_SOURCES['wireguard-runtime']
            ns = module('forwarding-host')
            ns['WIREGUARD_RUNTIME_SOURCE'] = runtime
            exec(runtime, ns)
            exec(ADDRESS_SOURCES['wireguard-host'], ns)
            self.host, self.ns = ns['WireGuardHost'](root=root, run=run, archived_hash=resource['ExpectedHash']), ns
        elif self.kind == 'Inbounds':
            ns = module('server-xhttp')
            exec(ADDRESS_SOURCES['inbound-host'], ns)
            self.host, self.ns = ns['Host'](root=root, run=run), ns
        elif self.kind == 'Firewall':
            self.ns = module('firewall-canonical')
        elif self.kind not in ('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding'):
            raise ValueError('Unknown address-change component.')
        else:
            self.protocol = {'RealityEntry': ('/usr/local/etc/xray/config.json', '/usr/local/bin/xray', 'xray.service'),
                             'AnyTlsEntry': ('/etc/sing-box-anytls/config.json', '/usr/local/bin/sing-box-anytls', 'sing-box-anytls.service'),
                             'ShadowsocksLanding': ('/etc/sing-box/config.json', '/usr/local/bin/sing-box', 'sing-box.service')}[self.kind]

    def path(self, name, absent=False):
        p = self.root / name.lstrip('/')
        if p.is_symlink() or any(a.is_symlink() for a in p.parents) or p.exists() and not p.is_file() or not absent and not p.is_file():
            raise ValueError('Linked, missing or non-regular address resource.')
        return p

    def command(self, args, check=True):
        value = self.run(args, capture_output=True, text=True, timeout=45)
        if check and value.returncode:
            raise ValueError('Address resource command failed.')
        return value

    def states(self, names):
        return {name: {key: self.command(['systemctl', command, '--quiet', name], False).returncode == 0
                       for key, command in [('Active', 'is-active'), ('Enabled', 'is-enabled')]} for name in names}

    def read(self):
        if self.host:
            value = self.host.read()
            return value
        if self.kind == 'Firewall':
            content = self.path('/etc/nftables.conf').read_text()
            if '# Managed by May VPS Deploy.' not in content:
                raise ValueError('Unmanaged firewall is outside address-change scope.')
            canonical = self.ns['canonical']
            table = canonical(self.command(['nft', '-s', '-nn', 'list', 'table', 'inet', 'filter']).stdout)
            if table != canonical(content):
                raise ValueError('Firewall runtime differs from persistent rules.')
            return {'Hash': sha(content), 'Files': {'/etc/nftables.conf': sha(content)}, 'Units': {}, 'Table': table}
        paths = {'RealityEntry': ('/usr/local/etc/xray/config.json', '/usr/local/bin/xray', 'xray.service'),
                 'AnyTlsEntry': ('/etc/sing-box-anytls/config.json', '/usr/local/bin/sing-box-anytls', 'sing-box-anytls.service'),
                 'ShadowsocksLanding': ('/etc/sing-box/config.json', '/usr/local/bin/sing-box', 'sing-box.service')}
        config, binary, unit = paths[self.kind]
        raw = self.path(config).read_bytes()
        if len(raw) > 1048576:
            raise ValueError('Oversized managed protocol configuration.')
        self.path(binary)
        start = self.command(['systemctl', 'show', unit, '-p', 'ExecStart', '--value']).stdout
        if binary + (' run -config ' if self.kind == 'RealityEntry' else ' run -c ') + config not in start:
            raise ValueError('Protocol service identity differs from the managed archive.')
        if self.command(['systemctl', 'show', unit, '-p', 'DropInPaths', '--value']).stdout.strip():
            raise ValueError('Protocol service has external overrides.')
        self.protocol = (config, binary, unit)
        return {'Hash': sha(raw), 'Configuration': json.loads(raw), 'Files': {config: sha(raw)}, 'Units': self.states([unit]), 'Table': None}

    def materials(self, observed):
        before_files = {p: self.path(p).read_bytes() for p in observed['Files']}
        if self.kind == 'Firewall':
            original = before_files['/etc/nftables.conf'].decode()
            def rules(bridge):
                def sources(match):
                    old = match[2].strip('{} ').split(',')
                    items = list(dict.fromkeys(v for s in old for v in
                        ([s.strip(), replace(s.strip(), self.addresses)] if bridge else [replace(s.strip(), self.addresses)])))
                    return match[1] + ('{ ' + ', '.join(items) + ' }' if len(items) > 1 or '{' in match[2] else items[0])
                return re.sub(r'(\bip6? saddr\s+)(\{[^{}\n]*\}|[0-9a-fA-F.:/]+)', sources, original).encode()
            bridge, after = rules(True), rules(False)
            return [before_files, {'/etc/nftables.conf': bridge}, {'/etc/nftables.conf': bridge}, {'/etc/nftables.conf': after}]
        if self.kind == 'Inbounds':
            payload = copy.deepcopy(observed['Registry'])
            payload['Configurations'] = {b['Id']: base64.b64encode(self.path(self.ns['config_path'](b['Id'])).read_bytes()).decode() for b in payload['Bindings']}
            if payload['Model'] != self.r['Before']:
                raise ValueError('Inbound model differs from the archive.')
            after = copy.deepcopy(self.r['AfterPayload'])
            if after['Core'] != payload['Core'] or {b['Id'] for b in after['Bindings']} != {b['Id'] for b in payload['Bindings']} or after['Model'] != self.r['After']:
                raise ValueError('Address changes cannot replace cores or inbound identities.')
            for key, value in after['Configurations'].items():
                previous = json.loads(base64.b64decode(payload['Configurations'][key]))
                if physical(json.loads(base64.b64decode(value))) != physical(rewrite(previous, self.addresses)):
                    raise ValueError('Address candidate changes unrelated inbound fields.')
            self.ns['normalize'](after)
            self.after_payload = after
            updated = self.ns['material'](after)
            self.affected = [b['Id'] for b in payload['Bindings'] if b != next(x for x in after['Bindings'] if x['Id'] == b['Id'])]
            self.host.preflight(after, self.affected)
            return [before_files, before_files, updated, updated]
        old = observed['Configuration']
        if old != self.r['Before']:
            raise ValueError('Component configuration differs from the archive.')
        after = self.r['After']
        # Additional changes are limited to reference fingerprints prepared by
        # the controller. Physical connection parameters must match this map.
        if physical(rewrite(old, self.addresses)) != physical(after):
            raise ValueError('Address candidate changes unrelated component fields.')
        if self.host:
            bridge = rewrite(old, self.addresses, True, True)
            configs = [old, bridge, merge_sources(after, bridge), after]
            sets = [before_files]
            for config in configs[1:]:
                values = self.host.material(config) if self.kind.startswith('WireGuard') else self.host.material(config, self.host.proxy())
                if self.kind in ('TcpForwarding', 'UdpForwarding') and self.ns['proxy_health_rules'](config):
                    original_health = json.loads(before_files[self.host.DIRECTORY + '/proxy-health.json'])
                    health = copy.deepcopy(self.r.get('AfterProbeHealth', original_health) if config != old and config != bridge else original_health)
                    health['Core'] = original_health['Core']
                    for rule in self.ns['proxy_health_rules'](config):
                        entry = health['Rules'][rule['Id']]
                        entry['RuleFingerprint'] = self.ns['group_fingerprint'](rule)
                        entry['NodeFingerprint'] = rule['Validation']['NodeFingerprint']
                    values.update(self.host.auxiliary(config, payload=health))
                    self.host.proxy_candidate = copy.deepcopy(health)
                values = {p: v.encode() if isinstance(v, str) else v for p, v in values.items()}
                for name in getattr(self.host, 'ARCHIVED_PROGRAMS', ()):
                    if name in before_files:
                        values[name] = before_files[name]
                if self.kind.startswith('WireGuard'):
                    values[self.ns['WG_PROGRAM']] = before_files[self.ns['WG_PROGRAM']]
                sets.append(values)
            self.configs = configs
            if self.kind in ('TcpForwarding', 'UdpForwarding'):
                self.host.preflight(after)
            return sets
        config, binary, unit = self.protocol
        return [before_files, before_files, {config: compact(after).encode()}, {config: compact(after).encode()}]

    def stop(self, files):
        if self.kind == 'Firewall':
            return
        if self.host and self.kind != 'Inbounds':
            self.host.stop(files)
        else:
            names = [self.ns['unit_name'](i) for i in self.affected] if self.kind == 'Inbounds' else [self.protocol[2]]
            for name in names:
                self.command(['systemctl', 'stop', name])

    def validate(self, files, write):
        if self.kind == 'Firewall':
            name = '/etc/nftables.conf.may-address-check'
            write(name, files['/etc/nftables.conf'], {'Mode': 0o600, 'Uid': 0, 'Gid': 0})
            try:
                self.command(['nft', '-c', '-f', str(self.path(name))])
            finally:
                self.path(name).unlink()
        elif not self.host:
            config, binary, unit = self.protocol
            name = config + '.may-address-check'
            write(name, files[config], {'Mode': 0o600, 'Uid': 0, 'Gid': 0})
            try:
                self.command([binary, 'run', '-test', '-config', str(self.path(name))] if self.kind == 'RealityEntry' else [binary, 'check', '-c', str(self.path(name))])
            finally:
                self.path(name).unlink()
        elif self.kind == 'Inbounds':
            for identifier in self.affected:
                path = self.ns['config_path'](identifier)
                core = self.ns['selected_core'](self.after_payload, identifier)
                name = path + '.may-address-check'
                write(name, files[path], {'Mode': 0o600, 'Uid': 0, 'Gid': 0})
                try:
                    binary = self.ns['core_path'](core)
                    self.command([binary, 'run', '-test', '-config', str(self.path(name))] if core['Engine'] == 'xray' else [binary, 'check', '-c', str(self.path(name))])
                finally:
                    self.path(name).unlink()

    def activate(self, files, original, index):
        if self.kind == 'Firewall':
            self.command(['nft', '-f', str(self.path('/etc/nftables.conf'))])
            return
        self.command(['systemctl', 'daemon-reload'])
        if self.host and self.kind != 'Inbounds':
            config = json.loads(files[self.host.CONFIG])
            self.host.activate(config)
        else:
            for unit, status in original.items():
                self.command(['systemctl', 'enable' if status['Enabled'] else 'disable', unit])
                self.command(['systemctl', 'start' if status['Active'] else 'stop', unit])
            if self.kind == 'Inbounds':
                saved = json.loads(files[self.ns['REGISTRY']])
                for binding in saved['Bindings']:
                    if original[self.ns['unit_name'](binding['Id'])]['Active']:
                        self.host.wait_ready(binding)


class AddressHost:
    def __init__(self, document, root=Path('/'), run=subprocess.run, program=None):
        self.d, self.root, self.run = document, root, run
        self.program = program
        if set(document) not in ({'Task', 'Addresses', 'Resources'}, {'Task', 'ProgramSha256', 'Addresses', 'Resources'}) or not re.fullmatch('[a-f0-9]{32}', document['Task']):
            raise ValueError('Invalid address transaction identity.')
        if program is not None and sha(program) != document.get('ProgramSha256'):
            raise ValueError('Address program differs from the reviewed snapshot.')
        addresses = document['Addresses']
        if not isinstance(addresses, dict) or not 1 <= len(addresses) <= 2:
            raise ValueError('Invalid address map.')
        for old, new in addresses.items():
            a, b = ipaddress.ip_address(old), ipaddress.ip_address(new)
            if a.version != b.version or a.is_unspecified or b.is_unspecified or a.is_multicast or b.is_multicast or a.is_loopback or b.is_loopback:
                raise ValueError('Invalid replacement address.')
        if len(document['Resources']) > 24 or len({r['Kind'] for r in document['Resources']}) != len(document['Resources']):
            raise ValueError('Invalid or duplicate component scope.')
        self.adapters = [Adapter(r, root, run, addresses) for r in document['Resources']]
        self.directory = root / 'root/vps-deploy-address' / document['Task']
        self.file = self.directory / 'transaction.json'
        for p in [self.directory, *self.directory.parents]:
            if p.is_symlink():
                raise ValueError('Linked address transaction path.')

    def write(self, name, data, metadata):
        p = self.root / name.lstrip('/')
        if p.is_symlink() or any(a.is_symlink() for a in p.parents):
            raise ValueError('Linked address resource.')
        temp = p.with_name(p.name + '.may-address-new')
        with temp.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, metadata['Mode'])
        if os.geteuid() == 0:
            os.chown(temp, metadata['Uid'], metadata['Gid'])
        os.replace(temp, p)

    def save(self, journal):
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.directory.parent, 0o700)
        os.chmod(self.directory, 0o700)
        self.write('/' + self.file.relative_to(self.root).as_posix(), compact(journal).encode(), {'Mode': 0o600, 'Uid': 0, 'Gid': 0})

    def load(self):
        if self.file.is_symlink() or not self.file.is_file() or self.file.stat().st_size > 16777216:
            raise ValueError('Invalid address journal.')
        if self.file.stat().st_uid != 0 or self.file.stat().st_mode & 0o077:
            raise ValueError('Address journal permissions changed.')
        j = json.loads(self.file.read_text())
        if j.get('Version') != 1 or j.get('DocumentHash') != sha(compact(self.d)) or j.get('Task') != self.d['Task']:
            raise ValueError('Address journal identity differs.')
        if set(j.get('Components', {})) != {a.kind for a in self.adapters}:
            raise ValueError('Address journal component scope differs.')
        return j

    def inspect(self):
        result, projected = {}, {}
        for a in self.adapters:
            observed = a.read()
            if a.kind != 'Firewall' and observed['Hash'] != a.r['ExpectedHash']:
                raise ValueError('Remote component drift before address change.')
            sets = a.materials(observed)
            result[a.kind] = observed['Hash']
            if a.kind.startswith('WireGuard'):
                projected[a.kind] = a.ns['digest'](a.ns['encoded']({'Files': {p: sha(b) for p, b in sets[3].items()}, 'Table': None}))
        return {'Phase': 'Inspected', 'Hashes': result, 'ProjectedHashes': projected}

    def prepare(self):
        if self.directory.exists():
            raise ValueError('An address transaction is never automatically replayed.')
        journal = {'Version': 1, 'Task': self.d['Task'], 'DocumentHash': sha(compact(self.d)), 'Phase': 'Prepared', 'Components': {}}
        for a in self.adapters:
            observed = a.read()
            if a.kind != 'Firewall' and observed['Hash'] != a.r['ExpectedHash']:
                raise ValueError('Remote component changed before snapshot.')
            sets = a.materials(observed)
            if any(set(s) != set(sets[0]) for s in sets):
                raise ValueError('Address changes cannot add or remove component files.')
            metadata = {}
            for p in sets[0]:
                st = a.path(p).stat()
                if st.st_uid != 0 or st.st_mode & 0o022:
                    raise ValueError('Address resource ownership or permissions differ.')
                metadata[p] = {'Mode': st.st_mode & 0o777, 'Uid': st.st_uid, 'Gid': st.st_gid}
            units = {a.ns['unit_name'](i): state for i, state in observed['Runtime'].items()} if a.kind == 'Inbounds' else observed.get('Units', {})
            journal['Components'][a.kind] = {'Files': [{p: base64.b64encode(b).decode() for p, b in s.items()} for s in sets], 'Metadata': metadata, 'Units': units, 'Current': 0}
        if self.program is not None:
            self.directory.mkdir(parents=True, mode=0o700)
            os.chmod(self.directory.parent, 0o700)
            self.write('/' + (self.directory / 'recovery.py').relative_to(self.root).as_posix(), self.program, {'Mode': 0o600, 'Uid': 0, 'Gid': 0})
        self.save(journal)
        return self.status()

    def prime(self, a, component):
        # Only derive compatibility hashes from exact journal bytes, then read()
        # still verifies all files and runtime state. Never adopt current drift.
        if a.host and a.kind != 'Inbounds' and hasattr(a.host, 'identity'):
            files = component['Files'][component['Current']]
            identity = {'Files': {p: sha(base64.b64decode(b)) for p, b in files.items()}, 'Table': None}
            if a.kind.startswith('WireGuard'):
                a.host.archived_hash = a.ns['digest'](a.ns['encoded'](identity))
            else:
                config = json.loads(base64.b64decode(files[a.host.CONFIG]))
                identity['Table'] = a.host.canonical_table(base64.b64decode(files[a.host.ACL]).decode())
                units = {a.host.unit_name(r, 'socket'): {'Enabled': r['Enabled'], 'Active': r['Enabled']} for r in config['Rules']}
                units[a.host.ACL_UNIT] = {'Enabled': True, 'Active': True}
                a.host.archived_hash = a.ns['digest'](a.ns['encoded'](dict(identity, Units=units)))

    def safe_files(self, a, component):
        self.prime(a, component)
        sets = [{p: base64.b64decode(b, validate=True) for p, b in s.items()} for s in component['Files']]
        if len(sets) != 4 or any(set(s) != set(sets[0]) for s in sets) or set(sets[0]) != set(component['Metadata']):
            raise ValueError('Invalid saved address scope.')
        # The immutable initial read identified every path; never accept a
        # forged journal path even if its bytes happen to match another file.
        allowed = set(a.read()['Files'])
        if set(sets[0]) != allowed:
            raise ValueError('Address journal contains unowned resource paths.')
        for p in sets[0]:
            current = a.path(p).read_bytes()
            if not any(current == s[p] for s in sets):
                raise ValueError('An address resource was externally modified.')
        return sets

    def apply(self, stage):
        phases = ['Prepared', 'Bridge', 'Apply', 'Finalize']
        index = phases.index(stage)
        j = self.load()
        if index == 0 or j['Phase'] != phases[index - 1]:
            raise ValueError('Address stage cannot be replayed or skipped.')
        # Validate every component before the first write on this host.
        saved = [(a, j['Components'][a.kind]) for a in self.adapters]
        for a, c in saved:
            sets = self.safe_files(a, c)
            if any(a.path(p).read_bytes() != b for p, b in sets[c['Current']].items()):
                raise ValueError('Address stage source changed.')
        j['Phase'] = stage + 'Intent'
        self.save(j)
        for a, c in saved:
            # read() is only used before a component mutation. A failed write
            # leaves Intent and is handled by explicit ownership-checked restore.
            observed = a.read()
            a.materials(observed) if a.kind == 'Inbounds' and index == 1 else None
            sets = [{p: base64.b64decode(b) for p, b in s.items()} for s in c['Files']]
            wanted = sets[index]
            if wanted != sets[c['Current']]:
                if a.kind == 'Inbounds':
                    a.affected = [b['Id'] for b in observed['Registry']['Bindings'] if sets[0][a.ns['config_path'](b['Id'])] != sets[2][a.ns['config_path'](b['Id'])]]
                    a.after_payload = copy.deepcopy(observed['Registry'])
                a.validate(wanted, self.write)
                a.stop(sets[c['Current']])
                for p, data in wanted.items():
                    if a.path(p).read_bytes() != data:
                        self.write(p, data, c['Metadata'][p])
                a.activate(wanted, c['Units'], index)
            c['Current'] = index
            self.save(j)
        j['Phase'] = stage
        self.save(j)
        return self.status()

    def status(self):
        if not self.file.exists():
            # A crash can interrupt snapshot creation before the journal rename.
            # Only report no mutation after every original resource still matches;
            # deleting a journal after Apply must never hide changed resources.
            if self.directory.exists() and any(p.name not in ('recovery.py', 'transaction.json.may-address-new') or p.is_symlink() or not p.is_file() for p in self.directory.iterdir()):
                raise ValueError('Unknown incomplete address snapshot.')
            self.inspect()
            return {'Phase': 'Absent', 'Consistent': True}
        j = self.load()
        hashes, observations, consistent = {}, {}, True
        for a in self.adapters:
            c = j['Components'][a.kind]
            self.prime(a, c)
            try:
                c = j['Components'][a.kind]
                for p, b in c['Files'][c['Current']].items():
                    st = a.path(p).stat()
                    if a.path(p).read_bytes() != base64.b64decode(b) or st.st_mode & 0o777 != c['Metadata'][p]['Mode'] or st.st_uid != c['Metadata'][p]['Uid'] or st.st_gid != c['Metadata'][p]['Gid']:
                        raise ValueError('Address status differs from the journal.')
                value = a.read()
                if a.kind == 'Inbounds' and {a.ns['unit_name'](i): state for i, state in value['Runtime'].items()} != c['Units']:
                    raise ValueError('Inbound enabled/active state changed.')
                if not a.host and a.kind != 'Firewall' and value['Units'] != c['Units']:
                    raise ValueError('Protocol enabled/active state changed.')
                hashes[a.kind] = value['Hash']
                observations[a.kind] = {k: value[k] for k in ('Registry', 'Runtime', 'Healthy', 'Configuration') if k in value}
            except (ValueError, OSError):
                consistent = False
        return {'Phase': j['Phase'], 'Consistent': consistent, 'Hashes': hashes, 'Observations': observations}

    def rollback(self):
        j = self.load()
        # A partial write can make read() reject its own component. Check the
        # fixed path set and exact old/planned bytes without adopting new files.
        for a in self.adapters:
            c = j['Components'][a.kind]
            paths = c['Files'][0]
            for p in paths:
                if not self.owned_path(a, p):
                    raise ValueError('Unowned address recovery path.')
                raw = a.path(p).read_bytes()
                if not any(raw == base64.b64decode(s[p]) for s in c['Files']):
                    raise ValueError('External edit prevents address recovery.')
                st = a.path(p).stat()
                if st.st_mode & 0o777 != c['Metadata'][p]['Mode'] or st.st_uid != c['Metadata'][p]['Uid'] or st.st_gid != c['Metadata'][p]['Gid']:
                    raise ValueError('External ownership change prevents recovery.')
                for suffix in ('.may-address-new', '.may-address-check'):
                    temp = a.path(p + suffix, True)
                    if temp.exists() and temp.read_bytes() not in [base64.b64decode(s[p]) for s in c['Files']]:
                        raise ValueError('Unowned temporary address file.')
        j['Phase'] = 'Restoring'
        self.save(j)
        for a in reversed(self.adapters):
            c = j['Components'][a.kind]
            files = {p: base64.b64decode(b) for p, b in c['Files'][0].items()}
            if a.kind == 'Inbounds':
                a.affected = [p.rsplit('/', 1)[-1][:-5] for p in files if re.fullmatch('/etc/may-inbounds/[a-f0-9]{32}\\.json', p) and c['Files'][0][p] != c['Files'][2][p]]
            a.stop(files)
            for p, data in files.items():
                for suffix in ('.may-address-new', '.may-address-check'):
                    temp = a.path(p + suffix, True)
                    if temp.exists():
                        temp.unlink()
                if a.path(p).read_bytes() != data:
                    self.write(p, data, c['Metadata'][p])
            a.activate(files, c['Units'], 0)
            if any(a.path(p).read_bytes() != b for p, b in files.items()):
                raise ValueError('Address restore is incomplete.')
            c['Current'] = 0
            self.save(j)
        j['Phase'] = 'RolledBack'
        self.save(j)
        return self.status()

    @staticmethod
    def owned_path(a, path):
        if a.kind == 'Firewall':
            return path == '/etc/nftables.conf'
        if a.kind in ('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding'):
            return path == {'RealityEntry': '/usr/local/etc/xray/config.json', 'AnyTlsEntry': '/etc/sing-box-anytls/config.json', 'ShadowsocksLanding': '/etc/sing-box/config.json'}[a.kind]
        if a.kind == 'Inbounds':
            return bool(re.fullmatch('/etc/may-inbounds/(model|[a-f0-9]{32})\\.json|/etc/systemd/system/may-inbound-[a-f0-9]{32}\\.service', path))
        h = a.host
        return path in (h.CONFIG, h.ACL) or h.owned_extra(path) or path == h.unit_path(h.ACL_UNIT) or bool(re.fullmatch('/etc/systemd/system/' + re.escape(h.PREFIX) + '-[a-f0-9]{32}\\.(socket|service)', path))


def main():
    if os.geteuid() != 0:
        raise ValueError('Address changes require the managed root connection.')
    data = json.loads(Path(os.environ['VPS_PARAM_ADDRESS_DOCUMENT_FILE']).read_text())
    host, action = AddressHost(data, program=Path(__file__).read_bytes()), os.environ['VPS_PARAM_ADDRESS_ACTION']
    if action == 'Inspect':
        result = host.inspect()
    elif action == 'Prepare':
        result = host.prepare()
    elif action in ('Bridge', 'Apply', 'Finalize'):
        result = host.apply(action)
    elif action == 'Rollback':
        result = host.rollback()
    elif action == 'Status':
        result = {'Phase': 'Absent'} if not host.directory.exists() else host.status()
    elif action == 'Commit':
        j = host.load()
        if j['Phase'] != 'Finalize':
            raise ValueError('Only a fully verified address change can commit.')
        if not host.status()['Consistent']:
            raise ValueError('Address resources changed before commit.')
        j['Phase'] = 'Committed'
        host.save(j)
        result = host.status()
    else:
        raise ValueError('Unknown address action.')
    print('VPSDEPLOY_ADDRESS_STATE_B64=' + base64.b64encode(compact(result).encode()).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Address transaction failed; retain its journal and inspect ownership.', file=sys.stderr)
        raise SystemExit(1)
