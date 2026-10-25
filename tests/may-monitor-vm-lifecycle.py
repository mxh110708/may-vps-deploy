"""Opt-in disposable QEMU fixture only. Never accepts an arbitrary SSH host."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid


BASE = Path('/opt/may-round13')
spec = importlib.util.spec_from_file_location('may_lifecycle', BASE / 'scripts/may-monitor-lifecycle.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
checks = []


def check(value, label):
    if not value:
        raise AssertionError(label)
    checks.append(label)


def resource(lifecycle):
    pid = int(lifecycle.system('show', lifecycle.unit, '-p', 'MainPID', '--value').stdout.strip())
    text = Path('/proc/' + str(pid) + '/stat').read_text().split(') ', 1)[1].split()
    memory = dict(line.split(':', 1) for line in Path('/proc/' + str(pid) + '/smaps_rollup').read_text().splitlines() if ':' in line)
    return {'cpu_seconds': (int(text[11]) + int(text[12])) / os.sysconf('SC_CLK_TCK'), 'rss_kib': int(memory['Rss'].split()[0]), 'pss_kib': int(memory['Pss'].split()[0])}


def observe(lifecycles, seconds, hook=lambda: None):
    first = [resource(life) for life in lifecycles]; samples = [[] for _ in lifecycles]; start = time.monotonic()
    while time.monotonic() - start < seconds:
        hook()
        for life, bucket in zip(lifecycles, samples): bucket.append(resource(life))
        time.sleep(3)
    elapsed = time.monotonic() - start; result = {}
    for life, initial, bucket in zip(lifecycles, first, samples):
        last = resource(life)
        result[life.role] = {'seconds': round(elapsed, 2), 'cpu_one_core_percent': round((last['cpu_seconds'] - initial['cpu_seconds']) / elapsed * 100, 3), 'rss_mib_peak': round(max(v['rss_kib'] for v in bucket) / 1024, 2), 'pss_mib_peak': round(max(v['pss_kib'] for v in bucket) / 1024, 2)}
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-id', required=True); parser.add_argument('--stage', choices=('before-reboot', 'after-reboot'), required=True); args = parser.parse_args()
    check(os.geteuid() == 0 and Path('/etc/may-round13-fixture').read_text().strip() == args.fixture_id and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == args.fixture_id, 'disposable-marker-and-DMI')
    host = driver.Host(); server = driver.Lifecycle(host, 'Server'); agent = driver.Lifecycle(host, 'Agent')
    source = (BASE / 'scripts/may-monitor-lifecycle.py').read_text(); state_file = BASE / 'state.private.json'
    manifest = json.loads((BASE / 'assets.json').read_text())
    def begin(life):
        task = uuid.uuid4().hex; life.begin(task, life.inspect()['Hash'], source); return task
    def apply(life, action, cfg=None, secrets=None, artifact=None, commit=True):
        task = begin(life)
        asset = None
        if artifact:
            asset = manifest[artifact]; shutil.copyfile(BASE / artifact, life.backup_path(task) / 'artifact')
        result = life.apply(task, action, cfg or {}, secrets or {}, asset)
        if commit: life.finish(task)
        return task, result
    if args.stage == 'after-reboot':
        check(server.inspect()['Active'] and agent.inspect()['Active'], 'May-services-survive-reboot')
        for life in (server, agent): host.verify_process(life.unit, life.binary)
        check(Path('/var/lib/komari-round13-sentinel').read_text() == 'retained', 'legacy-data-survives-reboot')
        print(json.dumps({'stage': args.stage, 'checks': checks})); return
    check(server.inspect()['Hash'] == 'Absent' and agent.inspect()['Hash'] == 'Absent', 'fresh-May-scope')
    sentinel = Path('/var/lib/komari-round13-sentinel'); sentinel.write_text('retained')
    legacy = Path('/etc/systemd/system/komari-round13-sentinel.service')
    legacy.write_text('[Unit]\nDescription=Isolated legacy stand-in\n[Service]\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n')
    host.run(['systemctl', 'daemon-reload']); host.run(['systemctl', 'enable', '--now', legacy.name])
    legacy_pid = host.run(['systemctl', 'show', legacy.name, '-p', 'MainPID', '--value']).stdout.strip()
    before_legacy = driver.digest(legacy)
    secrets = {'SetupToken': 'fixture-' + uuid.uuid4().hex, 'AdminPassword': 'Fixture-Pass1-' + uuid.uuid4().hex}
    with socket.socket() as port:
        port.bind(('127.0.0.1', 0)); config = {'Port': port.getsockname()[1], 'Username': 'fixture'}
    apply(server, 'Install', config, secrets, 'server-rc1.tar.gz')
    check(server.inspect()['Version'] == '0.1.0-rc.1', 'real-RC1-server-install-and-bootstrap')
    old_log_size = Path('/var/lib/may-monitor-server/logs/service.log').stat().st_size
    old_task, upgraded = apply(server, 'Upgrade', config, secrets, 'server-rc2.tar.gz')
    check(upgraded['Version'] == '0.1.0-rc.2', 'RC1-to-RC2-upgrade')
    with Path('/var/lib/may-monitor-server/logs/service.log').open('rb') as stream:
        stream.seek(old_log_size); check(secrets['SetupToken'].encode() not in stream.read(), 'operator-setup-token-not-in-RC2-service-log')
    api = 'http://127.0.0.1:' + str(config['Port'])
    def request(path, body=None, headers=None):
        request = urllib.request.Request(api + path, data=driver.canonical(body) if body is not None else None, headers={'Content-Type': 'application/json', **(headers or {})})
        with urllib.request.urlopen(request, timeout=10) as response: return json.load(response)
    login = request('/api/login', {'username': 'fixture', 'password': secrets['AdminPassword']})
    cookie = 'session_token=' + login['data']['set-cookie']['session_token']
    node = request('/api/admin/client/add', {'name': 'disposable-agent'}, {'Cookie': cookie})
    credentials = node.get('data', node); token = credentials['token']; client_id = credentials['uuid']
    agent_secrets = {'AgentToken': token}
    apply(agent, 'Install', {'Endpoint': api}, agent_secrets, 'agent-rc1')
    check(agent.inspect()['Configuration']['ClientUUID'] == client_id, 'agent-credential-confirmed-with-paired-server')
    read_token = 'may_read_' + __import__('base64').urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    import datetime
    authorization = {'Sha256': hashlib.sha256(read_token.encode()).hexdigest(), 'Clients': [client_id], 'ExpiresAt': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat()}
    apply(server, 'ConfigureRead', {'ReadAuthorization': authorization})
    def snapshot(): return request('/api/integration/v1/snapshot', headers={'Authorization': 'Bearer ' + read_token})
    for attempt in range(30):
        snap = snapshot()
        if snap['nodes'] and snap['nodes'][0]['online'] and snap['nodes'][0]['metrics'] is not None: break
        time.sleep(1)
    check(snap['nodes'][0]['uuid'] == client_id and snap['nodes'][0]['online'] and snap['nodes'][0]['metrics'] is not None, 'real-agent-telemetry-and-scoped-read')
    results = {'steady_with_agent_and_read': observe([server, agent], 60, snapshot)}
    apply(agent, 'Disable')
    for attempt in range(20):
        if not snapshot()['nodes'][0]['online']: break
        time.sleep(.5)
    check(not snapshot()['nodes'][0]['online'], 'disconnect-not-reported-online')
    results['server_without_agent'] = observe([server], 15, snapshot)
    apply(agent, 'Enable')
    for attempt in range(30):
        if snapshot()['nodes'][0]['online']: break
        time.sleep(1)
    check(snapshot()['nodes'][0]['online'], 'agent-reconnects-after-service-enable')
    backup_task = begin(server); consistent = server.finish(backup_task)
    check(consistent['Phase'] == 'Committed', 'consistent-live-database-backup')
    # A stopped service stays stopped across upgrade; repeated version is refused
    # before changes, then cancellation releases ownership without restoring data.
    apply(server, 'Disable'); pending = begin(server); shutil.copyfile(BASE / 'server-rc2.tar.gz', server.backup_path(pending) / 'artifact')
    try: server.apply(pending, 'Upgrade', config, secrets, manifest['server-rc2.tar.gz'])
    except ValueError: pass
    else: raise AssertionError('repeated-upgrade-was-accepted')
    check(server.finish(pending, True)['Phase'] == 'RolledBack' and not server.inspect()['Active'], 'repeated-upgrade-refused-without-enabling')
    apply(server, 'Enable')
    task, _ = apply(server, 'Disable', commit=False)
    rolled = server.finish(task, True)
    check(rolled['Phase'] == 'RolledBack' and server.inspect()['Active'], 'cancellation-restores-server-state')
    # Restore the upgrade's RC1 before-state, with the current database preserved
    # under the restore transaction. Then return to the paired RC2 server.
    original = server.transaction(old_task)[1]
    _, restored = apply(server, 'Restore', {'RestoreTask': old_task, 'RestoreSha256': original['BackupSha256']})
    check(restored['Version'] == '0.1.0-rc.1', 'selected-database-and-binary-restore')
    apply(server, 'Upgrade', config, secrets, 'server-rc2.tar.gz')
    check(driver.digest(legacy) == before_legacy and sentinel.read_text() == 'retained' and host.run(['systemctl', 'show', legacy.name, '-p', 'MainPID', '--value']).stdout.strip() == legacy_pid, 'legacy-files-and-process-unchanged')
    state_file.write_text(json.dumps({'config': config, 'secrets': secrets, 'results': results})); state_file.chmod(0o600)
    print(json.dumps({'stage': args.stage, 'checks': checks, 'resources': results}))


if __name__ == '__main__':
    main()
