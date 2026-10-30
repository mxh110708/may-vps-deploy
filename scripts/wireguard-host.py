"""Scoped WireGuard files, preflight and recovery. Embedded after ForwardHost
and wireguard-runtime.py by RemoteAssets, not a general remote command runner.
"""
WG_UNIT = '/etc/systemd/system/may-wireguard.service'
WG_PROGRAM = '/usr/local/libexec/may-wireguard'


class WireGuardHost(ForwardHost):
    CONFIG, DIRECTORY, ACL = WG_CONFIG, WG_DIRECTORY, WG_CONFIG
    PREFIX, ACL_UNIT = 'may-wireguard', 'may-wireguard.service'
    JOURNAL = 'wireguard-state.json'
    EXTRA_FILES = (WG_KEY, WG_UNIT, WG_PROGRAM)

    def table(self): return None

    def units(self):
        result = []
        for directory in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
            result.extend('/' + str(p.relative_to(self.root)) for p in self.path(directory).glob('may-wireguard.service*'))
        return sorted(result)

    def unit_path(self, name): return '/etc/systemd/system/' + name

    def write(self, name, content):
        if name.startswith(WG_DIRECTORY + '/'):
            directory = self.path(WG_DIRECTORY)
            if directory.is_symlink(): raise ValueError('Linked WireGuard directory.')
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        super().write(name, content)
        os.chmod(self.regular(name), 0o644 if name == WG_PROGRAM else 0o600)

    def material(self, c):
        wg_normalize(c)
        key = self.regular(WG_KEY).read_text()
        if wg_command(['wg', 'pubkey'], input=key).stdout.strip() != c['PublicKey']:
            raise ValueError('WireGuard private/public identity mismatch.')
        unit = '# Managed by May VPS Deploy: WireGuard v1\n[Unit]\nDescription=May point-to-point WireGuard underlay\nWants=network-online.target\nAfter=network-online.target nftables.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 ' + WG_PROGRAM + ' up\nExecStop=/usr/bin/python3 ' + WG_PROGRAM + ' down\nTimeoutStartSec=30\nTimeoutStopSec=20\nCapabilityBoundingSet=CAP_NET_ADMIN\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n[Install]\nWantedBy=multi-user.target\n'
        return {WG_CONFIG: encoded(c) + '\n', WG_KEY: key, WG_UNIT: unit, WG_PROGRAM: WIREGUARD_RUNTIME_SOURCE}

    def read(self):
        config = self.regular(WG_CONFIG, True)
        if not config.exists():
            if self.units() or self.path(WG_PROGRAM).exists() or self.path(WG_DIRECTORY).exists() or any(v['ifname'] == WG_INTERFACE for v in wg_links()):
                raise ValueError('Unowned or incomplete WireGuard resources occupy the namespace.')
            return {'Hash': 'Absent', 'Configuration': None, 'Files': {}, 'Table': None, 'Units': {}, 'Healthy': False}
        if config.stat().st_size > 4096: raise ValueError('Oversized WireGuard configuration.')
        c = wg_normalize(json.loads(config.read_text()))
        if self.path(WG_DIRECTORY).stat().st_uid != 0 or self.path(WG_DIRECTORY).stat().st_mode & 0o077:
            raise ValueError('WireGuard directory ownership or permissions changed.')
        files = self.material(c)
        if self.units() != [WG_UNIT] or set(p.name for p in self.path(WG_DIRECTORY).iterdir()) != {'configuration.json', 'private.key'}:
            raise ValueError('Unexpected WireGuard files or overrides.')
        for path, content in files.items():
            p = self.regular(path)
            if path != WG_PROGRAM and p.read_bytes() != content.encode() or p.stat().st_mode & (0o022 if path == WG_PROGRAM else 0o077):
                raise ValueError('WireGuard files or permissions changed outside this task.')
        if self.command(['systemctl', 'show', self.ACL_UNIT, '-p', 'FragmentPath', '--value']).stdout.strip() != WG_UNIT or self.command(['systemctl', 'show', self.ACL_UNIT, '-p', 'DropInPaths', '--value']).stdout.strip():
            raise ValueError('WireGuard unit identity differs.')
        state = self.state(self.ACL_UNIT)
        healthy = state == {'Enabled': True, 'Active': True}
        if state['Active'] or any(v['ifname'] == WG_INTERFACE for v in wg_links()): wg_runtime_check(c)
        identity = self.identity(files)
        if self.regular(WG_PROGRAM).read_bytes() != WIREGUARD_RUNTIME_SOURCE.encode() and digest(encoded(identity)) != self.archived_hash:
            raise ValueError('Installed WireGuard runtime is not pinned by the controller archive.')
        return {'Hash': digest(encoded(identity)), 'Configuration': c, 'Files': identity['Files'], 'Table': None, 'Units': {self.ACL_UNIT: state}, 'Healthy': healthy}

    def preflight(self, c):
        wg_normalize(c, keys=False)
        observed = self.read()
        if observed['Hash'] != 'Absent': return observed
        for directory in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
            if self.path(directory + '/may-wireguard.service').exists(): raise ValueError('WireGuard unit namespace occupied.')
        for ip in (c['LocalAddress'], c['PeerAddress']):
            if json.loads(self.command(['ip', '-j', '-4', 'route', 'show', 'exact', ip + '/32']).stdout):
                raise ValueError('A route already occupies a WireGuard host address.')
        local = json.loads(self.command(['ip', '-j', 'address', 'show']).stdout)
        if any(a['local'] in (c['LocalAddress'], c['PeerAddress']) for item in local for a in item.get('addr_info', [])):
            raise ValueError('WireGuard host addresses already exist.')
        if c['SourceAddress'] not in {a['local'] for item in local for a in item.get('addr_info', [])}:
            raise ValueError('The selected outer source address is not local; NAT is outside this round.')
        with socket.socket(socket.AF_INET6 if c['Family'] == 'IPv6' else socket.AF_INET, socket.SOCK_DGRAM) as listener:
            if c['Family'] == 'IPv6': listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(('::' if c['Family'] == 'IPv6' else '0.0.0.0', c['ListenPort']))
        return observed

    def prepare_key(self, backup):
        journal = self.journal(backup)
        if journal['Original']['Files'] or self.read()['Hash'] != 'Absent': raise ValueError('WireGuard creation requires absent resources.')
        private = self.command(['wg', 'genkey']).stdout.strip() + '\n'
        public = wg_command(['wg', 'pubkey'], input=private).stdout.strip(); wg_key(public)
        journal['Applied'] = {'Files': {WG_KEY: digest(private), WG_KEY + '.may-new': digest(private)}, 'Table': None}
        self.write_journal(self.path(str(backup)), journal)
        self.write(WG_KEY, private)
        return public

    def stop(self, files):
        if WG_CONFIG in files and self.regular(WG_CONFIG, True).exists():
            c = wg_normalize(json.loads(self.regular(WG_CONFIG).read_text()))
            # Reject replaced kernel identity before invoking ExecStop.
            links = [v for v in wg_links() if v['ifname'] == WG_INTERFACE]
            if links and links[0].get('ifalias') != wg_alias(c): raise ValueError('WireGuard interface identity changed externally.')
        self.command(['systemctl', 'disable', '--now', self.ACL_UNIT], False)
        if self.state(self.ACL_UNIT)['Active'] or self.state(self.ACL_UNIT)['Enabled']:
            raise ValueError('WireGuard unit did not stop.')
        if any(v['ifname'] == WG_INTERFACE for v in wg_links()):
            if not self.regular(WG_CONFIG, True).exists(): raise ValueError('An unknown interface remains.')
            wg_down(wg_normalize(json.loads(self.regular(WG_CONFIG).read_text())))

    def activate(self, c):
        self.command(['systemctl', 'daemon-reload'])
        self.command(['systemctl', 'enable', '--now', self.ACL_UNIT])

    def rollback_check(self, backup):
        journal, paths = super().rollback_check(backup)
        if any(v['ifname'] == WG_INTERFACE for v in wg_links()):
            c = wg_normalize(json.loads(self.regular(WG_CONFIG).read_text()))
            wg_runtime_check(c)
        return journal, paths

    def rollback_prepare(self, backup):
        super().rollback_prepare(backup)
        if self.journal(backup)['Original']['Files']:
            # Removal deletes the key directory. tar's implicit parents would
            # otherwise use its process umask instead of the required 0700.
            directory = self.path(WG_DIRECTORY)
            if directory.is_symlink(): raise ValueError('Linked WireGuard recovery directory.')
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if directory.stat().st_mode & 0o077: raise ValueError('WireGuard recovery directory permissions changed.')

    def apply(self, c, expected, action, backup):
        if action not in ('Apply', 'Remove'): raise ValueError('Invalid WireGuard mutation action.')
        journal, _ = self.rollback_check(backup)
        if action == 'Remove':
            previous = self.read()
            if previous['Hash'] != expected: raise ValueError('WireGuard resources changed after review.')
            files = {}
        else:
            if expected != 'Absent' or journal['Original']['Files']: raise ValueError('WireGuard cannot overwrite an existing tunnel.')
            files = self.material(c)
        paths = sorted(set(journal['Original']['Files']) | set(journal.get('Applied', {}).get('Files', {})) | set(files))
        journal['Applied'] = {'Files': {p: digest(files[p]) if p in files else None for p in paths}, 'Table': None}
        journal['Applied']['Files'].update({p + '.may-new': digest(content) for p, content in files.items()})
        self.write_journal(self.path(str(backup)), journal)
        if action == 'Remove': self.stop(journal['Original']['Files'])
        for path in paths:
            if path in files: self.write(path, files[path])
            elif self.regular(path, True).exists(): self.regular(path).unlink()
        if files: self.activate(c)
        else:
            self.command(['systemctl', 'daemon-reload'])
            if self.path(WG_DIRECTORY).exists(): self.path(WG_DIRECTORY).rmdir()
        return self.read()

    def rollback_complete(self, backup):
        journal = self.journal(backup)
        if journal['Original']['Files']:
            c = wg_normalize(json.loads(self.regular(WG_CONFIG).read_text()))
            self.command(['systemctl', 'daemon-reload'])
            original = journal['OriginalUnits'][self.ACL_UNIT]
            self.command(['systemctl', 'enable' if original['Enabled'] else 'disable', self.ACL_UNIT])
            if original['Active']: self.command(['systemctl', 'start', self.ACL_UNIT])
            observed = self.read()
            if observed['Files'] != journal['Original']['Files'] or observed['Units'] != journal['OriginalUnits']: raise ValueError('WireGuard recovery did not restore its original state.')
        else:
            self.command(['systemctl', 'daemon-reload'])
            if self.path(WG_DIRECTORY).exists(): self.path(WG_DIRECTORY).rmdir()
            if self.read()['Hash'] != 'Absent': raise ValueError('WireGuard recovery is incomplete.')
        journal['Recovering'] = False; self.write_journal(self.path(str(backup)), journal)


def wireguard_host_main():
    host = WireGuardHost(archived_hash=os.environ.get('VPS_PARAM_WIREGUARD_EXPECTED_HASH'))
    action = sys.argv[1]
    if action == 'read':
        if os.environ.get('VPS_PARAM_CANDIDATE_JSON'):
            value = host.preflight(json.loads(os.environ['VPS_PARAM_CANDIDATE_JSON']))
        else: value = host.read()
        print('VPSDEPLOY_WIREGUARD_STATE_B64=' + base64.b64encode(encoded({k: v for k, v in value.items() if k not in ('Files', 'Table')} ).encode()).decode())
    elif action == 'verify':
        if host.read()['Hash'] != sys.argv[2]: raise ValueError('WireGuard archive differs.')
    elif action == 'snapshot': host.snapshot(Path(sys.argv[2]), os.environ['VPS_PARAM_WIREGUARD_EXPECTED_HASH'])
    elif action == 'paths': print('\n'.join(host.read()['Files']))
    elif action == 'key':
        public = host.prepare_key(Path(os.environ['VPS_PARAM_EXPECTED_TRANSACTION']))
        print('VPSDEPLOY_WIREGUARD_PUBLIC_B64=' + base64.b64encode(public.encode()).decode())
    elif action == 'apply': host.apply(json.loads(os.environ['VPS_PARAM_CONFIG_JSON']), os.environ['VPS_PARAM_WIREGUARD_EXPECTED_HASH'], os.environ['VPS_PARAM_ACTION'], Path(os.environ['VPS_PARAM_EXPECTED_TRANSACTION']))
    elif action == 'rollback-check': host.rollback_check(Path(sys.argv[2]))
    elif action == 'rollback-prepare': host.rollback_prepare(Path(sys.argv[2]))
    elif action == 'rollback-complete': host.rollback_complete(Path(sys.argv[2]))
    elif action in ('proof-start', 'proof-stop', 'proof'):
        task, port, nonce = (os.environ['VPS_PARAM_' + k] for k in ('PROOF_ID', 'PROOF_PORT', 'PROOF_NONCE'))
        if not re.fullmatch('[a-f0-9]{32}', task): raise ValueError('Invalid proof task.')
        c = wg_load(); wg_proof_parameters(c['LocalAddress'], c['PeerAddress'], port, nonce)
        unit = 'may-wg-check-' + task + '.service'
        if action == 'proof-start':
            host.command(['systemd-run', '--quiet', '--collect', '--unit=' + unit, '--property=Type=exec', '--property=RuntimeMaxSec=20', '--property=MemoryMax=48M', '--property=CPUQuota=10%', '--property=User=nobody', '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict', '--property=ProtectHome=yes', '--property=PrivateTmp=yes', '/usr/bin/python3', WG_PROGRAM, 'serve', c['LocalAddress'], c['PeerAddress'], port, nonce])
            for attempt in range(30):
                with socket.socket() as ready:
                    ready.settimeout(0.1)
                    if ready.connect_ex((c['LocalAddress'], int(port))) == 0:
                        break
                if not host.state(unit)['Active']: raise ValueError('Proof responder failed to start.')
                time.sleep(0.1)
            else: raise ValueError('Proof responder startup exceeded its bound.')
        elif action == 'proof-stop':
            command = host.command(['systemctl', 'show', unit, '-p', 'ExecStart', '--value'], False).stdout
            if command and (WG_PROGRAM not in command or nonce not in command or c['LocalAddress'] not in command): raise ValueError('Unknown proof unit identity.')
            host.command(['systemctl', 'stop', unit], False)
            if host.state(unit)['Active']: raise ValueError('Proof unit still active.')
        else:
            value = wg_probe(c, port, nonce)
            print('VPSDEPLOY_WIREGUARD_PROOF_B64=' + base64.b64encode(encoded(value).encode()).decode())
    else: raise ValueError('Unknown WireGuard component operation.')


if __name__ == '__main__':
    try: wireguard_host_main()
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('WireGuard component operation failed; no credentials printed.') from None
