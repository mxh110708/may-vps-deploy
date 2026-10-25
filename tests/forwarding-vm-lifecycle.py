"""Explicit disposable Debian/KVM integration test; never invoked by normal app startup.

Requires a cloud-init marker matching the VM's DMI UUID. It changes real systemd,
nftables and network namespaces inside that disposable VM, never on the controller.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
STATE = Path('/opt/may-round11/lifecycle.json')
NETNS = 'may-round11-client'


def command(args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=30)


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def network():
    if command(['ip', 'netns', 'list']).stdout.find(NETNS) >= 0:
        command(['ip', 'netns', 'del', NETNS])
    command(['ip', 'link', 'del', 'may11host'], check=False)
    command(['ip', 'netns', 'add', NETNS])
    command(['ip', 'link', 'add', 'may11host', 'type', 'veth', 'peer', 'name', 'may11peer'])
    command(['ip', 'link', 'set', 'may11peer', 'netns', NETNS])
    for address in ['192.0.2.1/24', '2001:db8:11::1/64']:
        command(['ip', 'address', 'add', address, 'dev', 'may11host', 'nodad'])
    command(['ip', 'link', 'set', 'may11host', 'up'])
    for address in ['192.0.2.2/24', '192.0.2.3/24', '2001:db8:11::2/64', '2001:db8:11::3/64']:
        command(['ip', '-n', NETNS, 'address', 'add', address, 'dev', 'may11peer', 'nodad'])
    command(['ip', '-n', NETNS, 'link', 'set', 'may11peer', 'up'])
    command(['ip', '-n', NETNS, 'link', 'set', 'lo', 'up'])


def probe(transport, family='IPv4', denied=False, port=None):
    address = '192.0.2.1' if family == 'IPv4' else '2001:db8:11::1'
    source = ('192.0.2.' if family == 'IPv4' else '2001:db8:11::') + ('3' if denied else '2')
    port = port or (55001 if transport == 'tcp' else 55002)
    code = """import socket,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[2] else socket.AF_INET, socket.SOCK_STREAM if sys.argv[1]=='tcp' else socket.SOCK_DGRAM)
s.settimeout(1);s.bind((sys.argv[3],0));s.connect((sys.argv[2],int(sys.argv[4])));data=b'may-forwarded-lifecycle';s.sendall(data);answer=s.recv(4096);assert answer==data
"""
    response = command(['ip', 'netns', 'exec', NETNS, 'python3', '-c', code, transport, address, source, str(port)], check=False)
    if (response.returncode == 0) == denied:
        raise AssertionError('Unexpected forwarding/whitelist result: ' + transport + ' ' + family + ' denied=' + str(denied) + ' ' + response.stderr[-600:])


def snapshot(host, index):
    backup = Path('/root/vps-deploy-backups/20261023-' + str(index).zfill(6) + '/protocol-lifecycle')
    backup.mkdir(parents=True)
    host.snapshot(backup)
    with tarfile.open(backup / 'protocol-files.tar.gz', 'w:gz') as archive:
        for name in host.read()['Files']:
            archive.add(name, arcname=name.lstrip('/'))
    return backup


def restore(host, backup):
    host.rollback_prepare(backup)
    with tarfile.open(backup / 'protocol-files.tar.gz') as archive:
        for member in archive.getmembers():
            path = Path('/') / member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())
            os.chmod(path, member.mode)
    host.rollback_complete(backup)


def apply(host, configuration, index, remove=False):
    before = host.read()
    backup = snapshot(host, index)
    host.apply(configuration, before['Hash'], 'Remove' if remove else 'Apply', backup)
    return backup


def resource(unit):
    pid = int(command(['systemctl', 'show', unit, '-p', 'MainPID', '--value']).stdout.strip())
    if not pid:
        return {'pid': 0, 'rss_kib': 0, 'pss_kib': 0}
    status = Path('/proc/' + str(pid) + '/status').read_text()
    rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith('VmRSS:'))
    smaps = Path('/proc/' + str(pid) + '/smaps_rollup').read_text()
    pss = next(int(line.split()[1]) for line in smaps.splitlines() if line.startswith('Pss:'))
    return {'pid': pid, 'rss_kib': rss, 'pss_kib': pss}


def setup_echo():
    script = ROOT / 'echo.py'
    script.write_text("""import socket,threading,time
def tcp_client(client):
    with client:
        while True:
            data=client.recv(65536)
            if not data:return
            client.sendall(data)
def tcp():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',49100));s.listen()
    while True:
        client,_=s.accept();threading.Thread(target=tcp_client,args=(client,),daemon=True).start()
def udp():
    s=socket.socket(type=socket.SOCK_DGRAM);s.bind(('127.0.0.1',49101))
    while True:
        data,address=s.recvfrom(65536);s.sendto(data,address)
threading.Thread(target=tcp,daemon=True).start();threading.Thread(target=udp,daemon=True).start()
while True:time.sleep(60)
""")
    Path('/etc/systemd/system/may-round11-echo.service').write_text('[Unit]\nDescription=Disposable May forwarding fixture\n[Service]\nExecStart=/usr/bin/python3 ' + str(script) + '\n[Install]\nWantedBy=multi-user.target\n')
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', 'may-round11-echo.service'])
    time.sleep(.4)


def run(stage):
    tcp, udp = module('tcp-forwarding'), module('udp-forwarding')
    hosts = {'tcp': tcp.Host(), 'udp': udp.Host()}
    network()
    checks = []
    if stage == 'before-reboot':
        if any(host.read()['Hash'] != 'Absent' for host in hosts.values()):
            raise RuntimeError('Preexisting forwarding found; refusing to adopt it')
        setup_echo()
        sentinel = Path('/etc/may-round11-sentinel')
        sentinel.write_text('preserve-other-components\n')
        command(['nft', 'add', 'table', 'inet', 'may_round11_sentinel'])
        configurations = {}
        for index, (transport, host) in enumerate(hosts.items(), 1):
            rule = {'Id': ('1' if transport == 'tcp' else '2') * 32, 'Name': 'Disposable ' + transport, 'Enabled': True, 'ListenFamily': 'DualStack', 'ListenPort': 55001 if transport == 'tcp' else 55002, 'TargetAddress': '127.0.0.1', 'TargetPort': 49100 if transport == 'tcp' else 49101, 'AllowedSources': ['192.0.2.2/32', '2001:db8:11::2/128'], 'Validation': {'Type': 'Ssh' if transport == 'tcp' else 'Echo'}}
            if transport == 'udp':
                rule.update(SessionTimeoutSeconds=10, MaximumSessions=4)
            config = host.normalize({'Version': 1, 'Rules': [rule]})
            configurations[transport] = config
            apply(host, config, index)
            for family in ['IPv4', 'IPv6']:
                probe(transport, family)
                probe(transport, family, denied=True)
            checks.append(transport + '-install-dual-stack-whitelist')
        baseline = {name: host.read()['Hash'] for name, host in hosts.items()}
        # Real stop/start and target changes followed by component-only recovery.
        for index, (transport, host) in enumerate(hosts.items(), 10):
            original = configurations[transport]
            disabled = copy.deepcopy(original); disabled['Rules'][0]['Enabled'] = False
            backup = apply(host, disabled, index)
            probe(transport, denied=True)
            restore(host, backup)
            probe(transport)
            if host.read()['Hash'] != baseline[transport]:
                raise AssertionError('Recovery changed the original owned resources')
            other = 'udp' if transport == 'tcp' else 'tcp'
            if hosts[other].read()['Hash'] != baseline[other]:
                raise AssertionError('Recovery changed the other transport component')
            checks.append(transport + '-disable-restore-isolation')
        STATE.write_text(json.dumps({'configurations': configurations, 'hashes': baseline}))
        print(json.dumps({'stage': stage, 'checks': checks, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
    else:
        saved = json.loads(STATE.read_text())
        # nftables runtime tables are not persistent by themselves. Recreate only
        # the unrelated fixture table before testing this boot's scoped removal.
        if command(['nft', 'list', 'table', 'inet', 'may_round11_sentinel'], check=False).returncode:
            command(['nft', 'add', 'table', 'inet', 'may_round11_sentinel'])
        for name, host in hosts.items():
            if host.read()['Hash'] != saved['hashes'][name]:
                raise AssertionError('Owned forwarding did not survive a real reboot')
            probe(name)
            probe(name, 'IPv6')
            checks.append(name + '-real-reboot')
        units = {name: host.unit_name(saved['configurations'][name]['Rules'][0], 'service') for name, host in hosts.items()}
        active = {name: resource(unit) for name, unit in units.items()}
        if any(item['pid'] == 0 for item in active.values()):
            raise AssertionError('Socket activation did not start a real worker')
        ticks = {name: int(Path('/proc/' + str(item['pid']) + '/stat').read_text().split()[13]) + int(Path('/proc/' + str(item['pid']) + '/stat').read_text().split()[14]) for name, item in active.items()}
        time.sleep(2)
        cpu = {name: (sum(int(value) for value in Path('/proc/' + str(item['pid']) + '/stat').read_text().split()[13:15]) - ticks[name]) / os.sysconf('SC_CLK_TCK') for name, item in active.items()}
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and any(resource(unit)['pid'] for unit in units.values()):
            time.sleep(2)
        idle = {name: resource(unit) for name, unit in units.items()}
        if any(item['pid'] for item in idle.values()):
            raise AssertionError('Idle forwarding workers did not exit')
        for name, host in hosts.items():
            if host.read()['Hash'] != saved['hashes'][name]:
                raise AssertionError('Idle worker exit broke the listener identity')
            probe(name)
            checks.append(name + '-idle-exit-and-reactivation')
        for index, (name, host) in enumerate(hosts.items(), 20):
            apply(host, {'Version': 1, 'Rules': []}, index, remove=True)
            if host.read()['Hash'] != 'Absent':
                raise AssertionError('Owned component was not completely removed')
            checks.append(name + '-remove')
        if Path('/etc/may-round11-sentinel').read_text() != 'preserve-other-components\n' or command(['nft', 'list', 'table', 'inet', 'may_round11_sentinel']).returncode:
            raise AssertionError('Unrelated file or nftables table was changed')
        command(['systemctl', 'is-active', 'ssh'])
        command(['ip', 'netns', 'del', NETNS]); command(['ip', 'link', 'del', 'may11host'], check=False)
        print(json.dumps({'stage': stage, 'checks': checks, 'resources': {'active_workers': active, 'cpu_seconds_over_two_seconds': cpu, 'idle_workers': idle}, 'ssh_preserved': True, 'unrelated_resources_preserved': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-id', required=True)
    parser.add_argument('--stage', choices=['before-reboot', 'after-reboot'], required=True)
    arguments = parser.parse_args()
    if os.geteuid() != 0 or Path('/etc/may-round11-fixture').read_text().strip().lower() != arguments.fixture_id.lower() or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != arguments.fixture_id.lower() or Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise SystemExit('This test requires its explicitly identified disposable KVM guest')
    if not any(line in Path('/etc/os-release').read_text().splitlines() for line in ['VERSION_ID="12"', 'VERSION_ID="13"']):
        raise SystemExit('Debian 12/13 guest required')
    run(arguments.stage)
