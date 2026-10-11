#!/usr/bin/env bash
# Included in the private remote payload; also copied into the owned rollback snapshot.
mxh_network() {
  python3 - "$@" <<'PY'
import base64, json, os, re, stat, subprocess, sys
from pathlib import Path

action = sys.argv[1]
root = Path(sys.argv[2])
if not re.fullmatch(r'/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle', str(root)):
    raise SystemExit('Invalid network snapshot scope.')
keys = ('net.core.default_qdisc', 'net.ipv4.tcp_congestion_control', 'net.ipv4.tcp_rmem',
        'net.ipv4.tcp_wmem', 'net.core.rmem_max', 'net.core.wmem_max', 'net.ipv4.tcp_moderate_rcvbuf')
files = ('/usr/local/libexec/mxh-network-queue', '/etc/systemd/system/mxh-network-queue.service')

def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()

def regular(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit('Network file is not a regular owned file.')

def canonical(queues):
    return [{key: q[key] for key in ('kind', 'handle', 'parent', 'root', 'options') if key in q} for q in queues]

def queues(device):
    return canonical(json.loads(run(['tc', '-j', 'qdisc', 'show', 'dev', device])))

def restore_args(device, q):
    kind = q['kind']
    if kind not in ('fq', 'fq_codel', 'pfifo_fast'):
        raise SystemExit('Existing traffic shaping requires manual review; it will not be overwritten.')
    args = ['tc', 'qdisc', 'replace', 'dev', device]
    args += ['root'] if q.get('root') else ['parent', q['parent']]
    if q.get('handle') and q['handle'] != '0:':
        args += ['handle', q['handle']]
    args += [kind]
    values = q.get('options') or {}
    allowed = {'fq_codel': {'limit', 'flows', 'quantum', 'target', 'interval', 'memory_limit', 'ecn', 'drop_batch'},
               'pfifo_fast': {'bands', 'priomap', 'multiqueue'},
               'fq': {'limit', 'flow_limit', 'buckets', 'orphan_mask', 'quantum', 'initial_quantum',
                      'maxrate', 'low_rate_threshold', 'refill_delay', 'pacing', 'horizon', 'horizon_drop'}}[kind]
    if any(k not in allowed for k in values):
        raise SystemExit('Unsupported queue options; refusing to discard them.')
    if kind == 'pfifo_fast':
        # sch_generic.c reports fixed bands/priomap; q_fifo.c has no option
        # parser. q_prio.c also prints the absent multiqueue flag as false.
        # Restore this built-in layout without passing read-only tc metadata.
        mapping = [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]
        if ('bands' in values and (type(values['bands']) is not int or values['bands'] != 3)
                or 'priomap' in values and (not isinstance(values['priomap'], list)
                    or any(type(x) is not int for x in values['priomap']) or values['priomap'] != mapping)
                or 'multiqueue' in values and values['multiqueue'] is not False):
            raise SystemExit('Unsupported pfifo_fast layout; refusing to discard it.')
        return args
    for name, value in values.items():
        if name == 'ecn': args += ['ecn' if value else 'noecn']
        elif name == 'pacing': args += ['pacing' if value else 'nopacing']
        elif name == 'horizon_drop': args += ['horizon_drop' if value else 'horizon_cap']
        elif name == 'priomap':
            if not isinstance(value, list) or len(value) != 16 or any(type(x) is not int or x < 0 or x > 2 for x in value):
                raise SystemExit('Invalid priority mapping.')
            args += ['priomap'] + list(map(str, value))
        else:
            if type(value) not in (int, float) or value < 0:
                raise SystemExit('Invalid queue option.')
            suffix = 'us' if name in ('target', 'interval', 'refill_delay', 'horizon') else 'bit' if name in ('maxrate', 'low_rate_threshold') else ''
            # iproute2 reports rates in bytes/s; tc expects bit/s.
            number = int(value*8) if suffix == 'bit' else round(value) if suffix == 'us' else int(value)
            args += [name, str(number)+suffix]
    return args

def same_queue(actual, expected):
    if actual.get('kind') != expected.get('kind') or bool(actual.get('root')) != bool(expected.get('root')) or actual.get('parent') != expected.get('parent'):
        return False
    # The kernel assigns a handle when the original default had handle 0:.
    if expected.get('handle', '0:') != '0:' and actual.get('handle') != expected['handle']:
        return False
    a, b = actual.get('options') or {}, expected.get('options') or {}
    if set(a) != set(b): return False
    for name, value in b.items():
        if name in ('target', 'interval', 'refill_delay', 'horizon') and type(value) in (int, float) and type(a[name]) in (int, float):
            if abs(a[name]-value) > 1.001: return False
        elif a[name] != value: return False
    return True

def targets(device, current):
    roots = [q for q in current if q.get('root')]
    if len(roots) != 1:
        raise SystemExit('Network root queue is ambiguous.')
    if roots[0]['kind'] == 'mq':
        leaves = [q for q in current if not q.get('root') and q.get('parent') != 'ffff:fff1']
        if not leaves:
            raise SystemExit('Missing multiqueue leaves.')
        for q in leaves:
            if q['kind'] != 'fq': restore_args(device, q)
        return leaves
    if roots[0]['kind'] != 'fq': restore_args(device, roots[0])
    return roots

statefile = root/'network-state.json'
regular(statefile)
if action in ('snapshot', 'preflight'):
    devices = []
    for family in ('-4', '-6'):
        for route in json.loads(run(['ip', '-j', family, 'route', 'show', 'default'])):
            name = route.get('dev', '')
            if re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name) and name not in devices:
                devices.append(name)
    if not devices: raise SystemExit('No default interface is available.')
    state = {'Version': 1, 'Sysctl': {key: run(['sysctl', '-n', key]) for key in keys}, 'Devices': [], 'Files': {}}
    for name in devices:
        current = queues(name); selected = targets(name, current)
        state['Devices'].append({'Name': name, 'Queues': current, 'Targets': selected})
    for name in files:
        path = Path(name)
        for parent in path.parents:
            if parent.is_symlink(): raise SystemExit('Linked network persistence directory.')
        regular(path)
        if path.exists():
            content = path.read_bytes()
            if b'# Managed by MXH VPS Deploy.' not in content[:256]:
                raise SystemExit('Unmanaged network persistence file.')
            state['Files'][name] = {'Content': base64.b64encode(content).decode(), 'Mode': stat.S_IMODE(path.stat().st_mode)}
        else: state['Files'][name] = None
    state['UnitEnabled'] = subprocess.run(['systemctl', 'is-enabled', '--quiet', 'mxh-network-queue.service'], capture_output=True).returncode == 0
    state['UnitActive'] = subprocess.run(['systemctl', 'is-active', '--quiet', 'mxh-network-queue.service'], capture_output=True).returncode == 0
    cap = re.search(r'^CapEff:\s*([a-fA-F0-9]+)', Path('/proc/self/status').read_text(), re.M)
    if not cap or not int(cap.group(1), 16) & (1 << 12): raise SystemExit('Network administration is unavailable in this virtualization.')
    if action == 'preflight':
        print('VPSDEPLOY_NETWORK_PREFLIGHT_OK'); raise SystemExit(0)
    with statefile.open('x') as f:
        json.dump(state, f, separators=(',', ':'))
    os.chmod(statefile, 0o600)
elif action in ('apply', 'restore', 'verify', 'ensure'):
    state = json.loads(statefile.read_text())
    if state.get('Version') != 1 or set(state['Sysctl']) != set(keys):
        raise SystemExit('Invalid saved network runtime state.')
    if action == 'restore':
        if set(state.get('Files', {})) != set(files): raise SystemExit('Invalid persistence snapshot.')
        for name in files:
            path = Path(name); regular(path)
            for parent in path.parents:
                if parent.is_symlink(): raise SystemExit('Linked persistence directory.')
            if path.exists() and b'# Managed by MXH VPS Deploy.' not in path.read_bytes()[:256]:
                raise SystemExit('Persistence ownership changed.')
        for key, value in state['Sysctl'].items():
            if not re.fullmatch(r'[a-zA-Z0-9_ \t]+', value): raise SystemExit('Invalid saved sysctl value.')
    for item in state['Devices']:
        name = item['Name']
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name): raise SystemExit('Invalid saved interface.')
        current = queues(name)
        if action in ('apply', 'ensure'):
            if action == 'apply' and current != item['Queues']: raise SystemExit('Queue changed since snapshot.')
            for q in item['Targets'] if action == 'apply' else targets(name, current):
                if q['kind'] == 'fq': continue
                args = ['tc', 'qdisc', 'replace', 'dev', name] + (['root'] if q.get('root') else ['parent', q['parent']]) + ['fq']
                run(args)
        elif action == 'restore':
            # Only our fq replacement (or the unmodified original) can be restored.
            for q in item['Targets']:
                match = [now for now in current if bool(now.get('root')) == bool(q.get('root')) and now.get('parent') == q.get('parent')]
                if len(match) != 1 or (match[0]['kind'] != 'fq' and not same_queue(match[0], q)):
                    raise SystemExit('Queue ownership changed; refusing to overwrite it.')
                if q['kind'] == 'fq' and match[0] != q:
                    raise SystemExit('Existing fq was changed externally; refusing to overwrite it.')
                if not same_queue(match[0], q): run(restore_args(name, q))
            restored = queues(name)
            for q in item['Targets']:
                match = [now for now in restored if bool(now.get('root')) == bool(q.get('root')) and now.get('parent') == q.get('parent')]
                if len(match) != 1 or not same_queue(match[0], q):
                    raise SystemExit('Runtime queue restore was not confirmed.')
        else:
            selected = targets(name, current)
            if not selected or any(q['kind'] != 'fq' for q in selected):
                raise SystemExit('fq is not active on the selected interface.')
    if action == 'restore':
        for key, value in state['Sysctl'].items():
            if key not in keys or not re.fullmatch(r'[a-zA-Z0-9_ \t]+', value): raise SystemExit('Invalid saved sysctl value.')
            run(['sysctl', '-w', key+'='+value])
            if run(['sysctl', '-n', key]).split() != value.split(): raise SystemExit('Runtime restore was not confirmed.')
        subprocess.run(['systemctl', 'disable', '--now', 'mxh-network-queue.service'], capture_output=True, check=False)
        if set(state.get('Files', {})) != set(files): raise SystemExit('Invalid persistence snapshot.')
        for name, original in state['Files'].items():
            path = Path(name); regular(path)
            if path.exists() and b'# Managed by MXH VPS Deploy.' not in path.read_bytes()[:256]:
                raise SystemExit('Persistence ownership changed.')
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(base64.b64decode(original['Content'], validate=True)); os.chmod(path, original['Mode'])
        run(['systemctl', 'daemon-reload'])
        if state['UnitEnabled']: run(['systemctl', 'enable', 'mxh-network-queue.service'])
        if state['UnitActive']: run(['systemctl', 'start', 'mxh-network-queue.service'])
    print('VPSDEPLOY_NETWORK_RUNTIME_'+action.upper()+'_OK')
else:
    raise SystemExit('Unknown network runtime operation.')
PY
}
