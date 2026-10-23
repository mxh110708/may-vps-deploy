#!/usr/bin/env bash
# Limit maintenance and recovery to the application's inet/filter table.
mxh_firewall() {
  python3 - "$@" <<'PY'
import hashlib, ipaddress, json, os, re, subprocess, sys, tarfile
from pathlib import Path
action = sys.argv[1]
config = Path('/etc/nftables.conf')
def regular(path):
    if path.is_symlink() or not path.is_file() or any(p.is_symlink() for p in path.parents):
        raise SystemExit('Linked or missing firewall file.')
def table(text):
    match = re.search(r'(?ms)^table inet filter\s*\{(?!\s*\}).*\}\s*$', text)
    if not match: raise SystemExit('Unsupported managed firewall layout.')
    prefix = '\n'.join(line for line in text[:match.start()].splitlines() if line.strip() and not line.startswith('#'))
    if prefix not in ('', 'flush ruleset', 'table inet filter {}\nflush table inet filter'):
        raise SystemExit('Unmanaged firewall commands; review required.')
    return match.group()
def canonical(text):
    text = re.sub(r'(?m)^\s*#.*$', '', table(text))
    text = re.sub(r'priority filter\b', 'priority 0', text)
    text = re.sub(r'ip protocol 1\b', 'ip protocol icmp', text)
    text = re.sub(r'ip6 nexthdr 58\b', 'ip6 nexthdr ipv6-icmp', text)
    def states(match):
        known = {1: 'invalid', 2: 'established', 4: 'related'}
        values = [known.get(int(value, 16), value) for value in match[1].split(',')]
        expression = values[0] if len(values) == 1 else '{ '+', '.join(values)+' }'
        return 'ct state '+expression+' '+match[2]
    text = re.sub(r'ct state (0x[0-9a-f]+(?:,0x[0-9a-f]+)*) (accept|drop)', states, text)
    text = re.sub(r'ct state (established,related|related,established)', 'ct state { established, related }', text)
    if any(value != 'lo' for value in re.findall(r'"([^"\n]*)"', text)): raise SystemExit('Unsupported firewall string expression.')
    def address(match):
        try: return str(ipaddress.ip_address(match.group()))
        except ValueError: return match.group()
    text = re.sub(r'[0-9a-fA-F]*:[0-9a-fA-F:]+', address, text)
    def members(match):
        values = [v.strip().strip('"') for v in match.group(1).split(',')]
        return ','.join(sorted(values))
    text = re.sub(r'\{\s*([\w.:, -]+)\s*\}', members, text)
    # Only adjacent accept rules are interchangeable. Never move a rule across
    # a drop, a chain boundary or the privileged loopback exception.
    def sortable(line): return re.search(r'\baccept\s*$', line) and not re.search(r'\biifname\b', line)
    lines, block = [], []
    def flush():
        ports, other = set(), []
        for line in block:
            match = re.fullmatch(r'tcp dport ([0-9, ]+) accept', line)
            if match: ports.update(int(p) for p in match[1].split(','))
            else: other.append(line)
        if ports: other.append('tcp dport '+','.join(map(str, sorted(ports)))+' accept')
        lines.extend(sorted(other)); block.clear()
    for line in (line.strip() for line in text.splitlines() if line.strip()):
        if sortable(line): block.append(line)
        else: flush(); lines.append(line)
    flush(); text = '\n'.join(lines)
    return re.sub(r'[\s;"\']+', '', text)
def runtime():
    value = subprocess.run(['nft', '-s', '-nn', 'list', 'table', 'inet', 'filter'], capture_output=True, text=True, check=True).stdout
    return canonical(value)
def identity():
    regular(config)
    return {'File': hashlib.sha256(config.read_bytes()).hexdigest(), 'Table': hashlib.sha256(runtime().encode()).hexdigest()}
def matches(state):
    current = identity()
    return all(current[key] in (state['Original'][key], state.get('Applied', {}).get(key)) for key in current)
def scoped(text):
    return '#!/usr/sbin/nft -f\n# Managed by May VPS Deploy.\ntable inet filter {}\nflush table inet filter\n\n' + table(text)

def baseline_identity():
    if config.exists(): regular(config)
    elif config.is_symlink() or any(p.is_symlink() for p in config.parents): raise SystemExit('Linked firewall configuration.')
    tables = json.loads(subprocess.run(['nft', '-j', 'list', 'tables'], capture_output=True, text=True, check=True).stdout)
    present = any(item.get('table', {}).get('family') == 'inet' and item.get('table', {}).get('name') == 'filter' for item in tables['nftables'])
    return {'File': hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None,
            'Table': hashlib.sha256(runtime().encode()).hexdigest() if present else None}

def baseline_matches(state):
    current = baseline_identity()
    return state.get('Version') == 2 and state.get('Kind') == 'Deployment' and all(current[key] in (state['Original'][key], state.get('BeforeApply', {}).get(key), state.get('Applied', {}).get(key)) for key in current)

def baseline_action():
    root = Path(sys.argv[2])
    if not re.fullmatch(r'/root/vps-deploy-transaction-baselines/[a-f0-9]{32}', str(root)) or root.is_symlink() or any(p.is_symlink() for p in root.parents): raise SystemExit('Invalid deployment firewall scope.')
    regular(root/'baseline.complete')
    statefile = root/'firewall-state.json'
    if action == 'deployment-intent':
        candidate = Path(sys.argv[3]); regular(candidate)
        current = baseline_identity()
        if not statefile.exists():
            if current['Table'] is not None: raise SystemExit('A firewall appeared after fresh-machine audit; refusing to replace it.')
            regular(root/'files.tar.gz')
            with tarfile.open(root/'files.tar.gz') as archive:
                matches = [member for member in archive.getmembers() if member.name == 'etc/nftables.conf']
                if len(matches) > 1 or matches and not matches[0].isfile(): raise SystemExit('Invalid initial firewall snapshot.')
                original = hashlib.sha256(archive.extractfile(matches[0]).read()).hexdigest() if matches else None
            if current['File'] != original:
                # APT may add its default conffile after the baseline on a
                # minimal VPS. Accept only the package's untouched conffile.
                conffiles = subprocess.run(['dpkg-query', '-W', '-f=${Conffiles}', 'nftables'], capture_output=True, text=True, check=True).stdout
                md5 = re.findall(r'^ /etc/nftables\.conf ([a-f0-9]{32})(?:\s|$)', conffiles, re.M)
                if original is not None or current['File'] is None or len(md5) != 1 or hashlib.md5(config.read_bytes()).hexdigest() != md5[0]: raise SystemExit('Initial firewall configuration changed externally.')
            state = {'Version': 2, 'Kind': 'Deployment', 'Original': {'File': original, 'Table': None}, 'BeforeApply': current}
        else:
            regular(statefile); state = json.loads(statefile.read_text())
            if not baseline_matches(state): raise SystemExit('Deployment firewall changed externally.')
        content = scoped(candidate.read_text()); candidate.write_bytes(content.encode())
        state['Applied'] = {'File': hashlib.sha256(content.encode()).hexdigest(), 'Table': hashlib.sha256(canonical(content).encode()).hexdigest()}
        temporary = statefile.with_suffix('.new')
        if temporary.exists() or temporary.is_symlink(): raise SystemExit('Firewall intent path occupied.')
        with temporary.open('x') as output: json.dump(state, output)
        os.chmod(temporary, 0o600); os.replace(temporary, statefile)
    elif action in ('deployment-check', 'deployment-clear'):
        regular(statefile); state = json.loads(statefile.read_text())
        if not baseline_matches(state): raise SystemExit('Deployment firewall changed externally; restore refused.')
        if action == 'deployment-clear' and baseline_identity()['Table'] is not None:
            subprocess.run(['nft', 'delete', 'table', 'inet', 'filter'], check=True, capture_output=True)
    else: raise SystemExit('Unknown deployment firewall operation.')

if action.startswith('deployment-'):
    baseline_action(); raise SystemExit(0)
def verify_archive():
    if 'VPS_PARAM_TCP_PORTS' not in os.environ: return
    ports = [int(p) for p in os.environ['VPS_PARAM_TCP_PORTS'].split(',')]
    if len(ports) < 2 or any(not 1 <= p <= 65535 for p in ports): raise SystemExit('Invalid archived firewall ports.')
    rules = ['iifname "lo" accept', 'ct state invalid drop', 'ct state established,related accept', 'tcp dport { '+','.join(map(str, ports))+' } accept']
    udp = [int(p) for p in os.environ.get('VPS_PARAM_UDP_PORTS', '').split(',') if p]
    if any(not 1 <= p <= 65535 for p in udp): raise SystemExit('Invalid archived UDP ports.')
    if udp: rules.append('udp dport { '+','.join(map(str, udp))+' } accept')
    restricted = os.environ.get('VPS_PARAM_RESTRICTED_PORT', '')
    if restricted:
        if not restricted.isdigit() or not 1 <= int(restricted) <= 65535: raise SystemExit('Invalid restricted port.')
        for key, prefix, family in [('ALLOWED_IPV4S', 'ip', 4), ('ALLOWED_IPV6S', 'ip6', 6)]:
            values = [ipaddress.ip_address(p) for p in os.environ.get('VPS_PARAM_'+key, '').split(',') if p]
            if any(p.version != family for p in values): raise SystemExit('Invalid trusted family.')
            if values:
                for protocol in ('tcp', 'udp'): rules.append(prefix+' saddr { '+','.join(map(str, values))+' } '+protocol+' dport '+restricted+' accept')
    rules += ['udp sport 67 udp dport 68 accept', 'udp sport 547 udp dport 546 accept', 'ip protocol icmp accept', 'ip6 nexthdr ipv6-icmp accept']
    expected = 'table inet filter {\n  chain input {\n type filter hook input priority 0;\n policy drop;\n'+'\n'.join(rules)+'\n}\nchain forward {\n type filter hook forward priority 0; policy drop;\n}\nchain output {\n type filter hook output priority 0; policy accept;\n}\n}'
    if canonical(config.read_text()) != canonical(expected): raise SystemExit('Firewall differs from the managed archive; review required.')
if action == 'check':
    regular(config)
    verify_archive()
    if canonical(config.read_text()) != runtime(): raise SystemExit('Managed firewall runtime has drifted; review required.')
    print('VPSDEPLOY_FIREWALL_SCOPE_OK')
elif action == 'snapshot':
    destination = Path(sys.argv[2]); regular(config)
    verify_archive()
    if canonical(config.read_text()) != runtime(): raise SystemExit('Managed firewall runtime has drifted; review required.')
    destination.write_text(json.dumps({'Version': 1, 'Original': identity()}))
elif action == 'intent':
    statefile, candidate = map(Path, sys.argv[2:]); regular(statefile); regular(candidate)
    state = json.loads(statefile.read_text())
    if not matches(state): raise SystemExit('Firewall changed after review.')
    content = scoped(candidate.read_text()); candidate.write_bytes(content.encode())
    state['Applied'] = {'File': hashlib.sha256(content.encode()).hexdigest(), 'Table': hashlib.sha256(canonical(content).encode()).hexdigest()}
    statefile.write_text(json.dumps(state))
elif action == 'restore':
    statefile, backup, output = map(Path, sys.argv[2:]); regular(statefile); regular(backup)
    state = json.loads(statefile.read_text())
    if not matches(state): raise SystemExit('Firewall changed externally; restore refused.')
    if hashlib.sha256(backup.read_bytes()).hexdigest() != state['Original']['File']: raise SystemExit('Firewall backup changed.')
    output.write_bytes(scoped(backup.read_text()).encode())
else:
    raise SystemExit('Unknown firewall operation.')
PY
}
