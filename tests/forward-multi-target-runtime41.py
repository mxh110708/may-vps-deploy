"""Real systemd and TCP/UDP policies, exclusively in an identity-pinned QA VM."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tarfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
LAB = Path('/root/may-multi41')
ENDPOINTS = [('127.0.0.1', 32110), ('::1', 32111), ('127.0.0.1', 32112)]


def command(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=35)
    if check and result.returncode: raise RuntimeError('QA command failed: ' + args[0] + ' ' + result.stderr[-500:])
    return result


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def target_daemon():
    def enabled(index): return str(index) not in (LAB / 'disabled').read_text().split()
    def tcp(index):
        address, port = ENDPOINTS[index]
        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.bind((address, port)); listener.listen()
            def serve(peer):
                try:
                    if not enabled(index): return
                    peer.settimeout(60); peer.sendall(('SSH-2.0-Multi41-' + str(index) + '\r\n').encode())
                    while True:
                        data = peer.recv(65536)
                        if not data: return
                        peer.sendall(data)
                except OSError: pass
                finally: peer.close()
            while True:
                peer, _ = listener.accept(); threading.Thread(target=serve, args=(peer,), daemon=True).start()
    def udp(index):
        address, port = ENDPOINTS[index]
        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind((address, port))
            while True:
                data, peer = listener.recvfrom(65535)
                if data.startswith(b'APP41:'):
                    with (LAB / 'packets.jsonl').open('a') as file: file.write(json.dumps(dict(index=index, payload=data.hex(), source=peer[0])) + '\n')
                if enabled(index): listener.sendto(data, peer)
    for i in range(3):
        threading.Thread(target=tcp, args=(i,), daemon=True).start(); threading.Thread(target=udp, args=(i,), daemon=True).start()
    threading.Event().wait()


def config(transport, driver):
    rules = []
    for i, strategy in enumerate(('RoundRobin', 'SourceIpHash')):
        rule = dict(Id=format(10 + i, '032x'), Name='QA multi41 ' + strategy, Enabled=True, ListenFamily='DualStack', ListenPort=32150 + i,
                    TargetAddress=ENDPOINTS[0][0], TargetPort=ENDPOINTS[0][1], AllowedSources=['127.0.0.0/8', '::1/128'], Validation=dict(Type='Ssh' if transport == 'TCP' else 'Echo'),
                    TargetGroup=dict(Version=2, Strategy=strategy, AdditionalTargets=[dict(Id=format(j + 1, '032x'), Address=address, Port=port) for j, (address, port) in enumerate(ENDPOINTS[1:])],
                                     Health=dict(Type='Ssh' if transport == 'TCP' else 'Echo'), IntervalSeconds=5, TimeoutSeconds=1, FailureThreshold=2, RecoveryThreshold=2, RecoveryHoldSeconds=10))
        if transport == 'UDP': rule.update(SessionTimeoutSeconds=10, MaximumSessions=64)
        rules.append(rule)
    return driver.normalize(dict(Version=1, Rules=rules))


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-id', required=True); parser.add_argument('--after-reboot', action='store_true'); parser.add_argument('--target-daemon', action='store_true'); args = parser.parse_args()
    if os.geteuid() != 0 or Path('/etc/may-multi41-fixture').read_text().strip() != args.fixture_id or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.fixture_id:
        raise RuntimeError('Disposable VM identity mismatch; no mutations executed.')
    if args.target_daemon: return target_daemon()
    LAB.mkdir(mode=0o700, exist_ok=True); (LAB / 'disabled').write_text('')
    target_unit = 'may-multi41-targets.service'
    if not args.after_reboot:
        Path('/etc/systemd/system/' + target_unit).write_text('[Unit]\nDescription=Disposable multi-target acceptance servers\n[Service]\nExecStart=/usr/bin/python3 ' + str(Path(__file__).resolve()) + ' --fixture-id ' + args.fixture_id + ' --target-daemon\n[Install]\nWantedBy=multi-user.target\n')
        command(['systemctl', 'daemon-reload']); command(['systemctl', 'enable', '--now', target_unit])
    else: assert command(['systemctl', 'is-active', target_unit]).stdout.strip() == 'active'
    tcp, udp = load('tcp-forwarding'), load('udp-forwarding')
    hosts, configs = [], []
    until = time.monotonic() + 5
    while time.monotonic() < until:
        try:
            with socket.create_connection(ENDPOINTS[0], .2) as peer:
                if peer.recv(128).startswith(b'SSH-'): break
        except OSError: time.sleep(.05)
    else: raise AssertionError('QA target daemon did not start.')
    for transport, driver in [('TCP', tcp), ('UDP', udp)]:
        host = driver.Host(); expected = config(transport, driver)
        if args.after_reboot:
            observed = host.read(); assert observed['Configuration'] == expected
        else:
            assert host.read()['Hash'] == 'Absent'
            files = host.material(expected, host.proxy())
            for path, content in files.items(): host.write(path, content)
            host.activate(expected)
        hosts.append(host); configs.append(expected)
    def wait(healthy, seconds=30):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            observations = [h.read()['TargetGroups'] for h in hosts]
            if all(len(values) == 2 and all(v.get('Fresh') and v.get('Healthy') == healthy for v in values) for values in observations): return observations
            # Workers intentionally exit after 60 idle seconds. Re-activate the
            # QA listeners before requiring a fresh observation of an idle rule.
            for transport, values in zip(('TCP', 'UDP'), observations):
                for index, value in enumerate(values):
                    if value.get('State') != 'NotRunning': continue
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'TCP' else socket.SOCK_DGRAM) as trigger:
                            trigger.settimeout(.3)
                            if transport == 'TCP': trigger.connect(('127.0.0.1', 32150 + index))
                            else: trigger.sendto(b'QA-idle-activation', ('127.0.0.1', 32150 + index))
                    except OSError: pass
            time.sleep(.2)
        raise AssertionError('QA health did not converge: ' + json.dumps(observations))
    def tcp_client(policy=0, source='127.0.0.1', ipv6=False):
        peer = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET); peer.settimeout(3); peer.bind((source, 0)); peer.connect(('::1' if ipv6 else '127.0.0.1', 32150 + policy))
        banner = bytearray()
        while not banner.endswith(b'\n'):
            part = peer.recv(1)
            if not part: raise AssertionError('Missing selected target banner.')
            banner.extend(part)
        return peer, int(banner.decode().strip().rsplit('-', 1)[1])
    def udp_client(source='127.0.0.1', ipv6=False):
        peer = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM); peer.settimeout(3); peer.bind((source, 0)); return peer
    def datagram(peer, policy=0, expect=True, payload=None):
        payload = payload or b'APP41:' + secrets.token_hex(16).encode()
        peer.sendto(payload, ('::1' if peer.family == socket.AF_INET6 else '127.0.0.1', 32150 + policy))
        if expect: assert peer.recv(65535) == payload
        else:
            peer.settimeout(.3)
            try: peer.recv(128)
            except socket.timeout: pass
            else: raise AssertionError('All-failed UDP still forwarded.')
            finally: peer.settimeout(3)
        entries = [json.loads(line) for line in (LAB / 'packets.jsonl').read_text().splitlines()] if (LAB / 'packets.jsonl').exists() else []
        matches = [v for v in entries if v['payload'] == payload.hex()]
        if expect: assert len(matches) == 1
        return matches[0]['index'] if matches else None
    connections = []; associations = []; checks = []
    try:
        # Trigger socket activation after reboot and wait for all first health rounds.
        for i in range(2):
            p, _ = tcp_client(i); p.close()
            p = udp_client(); datagram(p, i); p.close()
        wait([True] * 3)
        for host, driver, transport in zip(hosts, (tcp, udp), ('TCP', 'UDP')):
            proof = driver.probe_groups(host, transport)
            assert all(len(g['Targets']) == 3 and len({t['TargetId'] for t in g['Targets']}) == 3 and all(t['Passed'] for t in g['Targets']) for g in proof['Groups'])
        sequence = []
        for _ in range(6): p, target = tcp_client(); sequence.append(target); p.close()
        assert sequence[:3] == sequence[3:] and set(sequence[:3]) == {0, 1, 2}
        old, old_target = tcp_client(); connections.append(old)
        udp_sequence = []
        for _ in range(6):
            p = udp_client(); associations.append(p); selected = datagram(p); udp_sequence.append(selected); assert datagram(p) == selected
        assert udp_sequence[:3] == udp_sequence[3:] and set(udp_sequence[:3]) == {0, 1, 2}
        checks.extend(['real-tcp-round-robin-three-targets', 'real-udp-round-robin-and-session-pin', 'ipv6-target-and-listener'])
        hash_before = {}; hash_udp_before = {}
        for source in ['127.0.0.' + str(i) for i in range(1, 17)] + ['::1']:
            ipv6 = source == '::1'; selected = []
            for _ in range(2): p, target = tcp_client(1, source, ipv6); p.close(); selected.append(target)
            assert selected[0] == selected[1]; hash_before[source] = selected[0]
            selected = []
            for _ in range(2): p = udp_client(source, ipv6); selected.append(datagram(p, 1)); p.close()
            assert selected[0] == selected[1]; hash_udp_before[source] = selected[0]
        assert len(set(hash_before.values())) == 3 and len(set(hash_udp_before.values())) == 3
        baseline = LAB / 'hash-baseline.json'
        if args.after_reboot: assert json.loads(baseline.read_text()) == dict(tcp=hash_before, udp=hash_udp_before)
        else: baseline.write_text(json.dumps(dict(tcp=hash_before, udp=hash_udp_before)))
        checks.append('real-source-ip-hash-ipv4-ipv6-restart-stable')
        # Keep an active UDP association while its chosen target is removed.
        pinned = udp_client('127.0.0.40'); associations.append(pinned); pinned_target = datagram(pinned)
        (LAB / 'disabled').write_text(str(pinned_target)); wait([i != pinned_target for i in range(3)])
        for _ in range(4): p, target = tcp_client(); p.close(); assert target != pinned_target
        assert datagram(pinned) != pinned_target
        old.sendall(b'unchanged-established-stream'); assert old.recv(128) == b'unchanged-established-stream'
        for source, selected in hash_before.items():
            p, current = tcp_client(1, source, source == '::1'); p.close()
            assert current == selected if selected != pinned_target else current != pinned_target
        checks.extend(['consecutive-failure-removal', 'unrelated-hash-flows-unchanged', 'old-tcp-stream-not-migrated', 'new-udp-datagram-reallocated-without-replay'])
        (LAB / 'disabled').write_text(''); started = time.monotonic(); wait([True] * 3); assert time.monotonic() - started >= 9.5
        checks.append('real-continuous-recovery-hold')
        for p in associations: p.close()
        associations.clear()
        # Expiry creates a new association; there is no persistent per-client table.
        time.sleep(11)
        p = udp_client(); associations.append(p); first = datagram(p); time.sleep(11); second = datagram(p); assert first != second
        checks.append('udp-idle-expiry-reallocates')
        # Memory/session limits preserve existing associations instead of evicting them.
        for p in associations: p.close()
        associations.clear(); time.sleep(11)
        for _ in range(64): p = udp_client(); associations.append(p); datagram(p)
        extra = udp_client(); associations.append(extra); assert datagram(extra, expect=False) is None; datagram(associations[0])
        checks.append('udp-session-cap-preserves-established')
        (LAB / 'disabled').write_text('0 1 2'); wait([False] * 3)
        blocked = socket.create_connection(('127.0.0.1', 32150), timeout=3); blocked.settimeout(3)
        try:
            try: assert blocked.recv(1) == b''
            except ConnectionResetError: pass
        finally: blocked.close()
        p = udp_client(); associations.append(p); assert datagram(p, expect=False) is None
        checks.append('all-failed-no-direct-fallback')
        (LAB / 'disabled').write_text(''); wait([True] * 3)
        # Real scoped snapshots restore a changed policy and its exact worker bytes.
        originals = []
        for host, driver, cfg in zip(hosts, (tcp, udp), configs):
            before = host.read(); originals.append(before['Hash']); snapshot = Path('/root/vps-deploy-backups/20261124-' + ('120000' if driver is tcp else '120001') + '/protocol-lifecycle'); snapshot.mkdir(parents=True, exist_ok=True)
            host.snapshot(snapshot, before['Hash'])
            with tarfile.open(snapshot / 'protocol-files.tar.gz', 'w:gz') as archive:
                for name in before['Files']: archive.add(host.path(name), arcname=name.lstrip('/'))
            changed = copy.deepcopy(cfg); changed['Rules'][0]['TargetGroup']['Strategy'] = 'SourceIpHash'
            host.apply(changed, before['Hash'], 'Apply', snapshot)
            host.rollback_prepare(snapshot)
            with tarfile.open(snapshot / 'protocol-files.tar.gz') as archive:
                for member in archive.getmembers():
                    path = host.path('/' + member.name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(archive.extractfile(member).read()); path.chmod(member.mode)
            host.rollback_complete(snapshot)
            assert host.read()['Hash'] == before['Hash']
        checks.append('real-scoped-snapshot-policy-and-worker-restore')
        if args.after_reboot:
            for host, driver, original in zip(hosts, (tcp, udp), originals):
                snapshot = Path('/root/vps-deploy-backups/20261124-' + ('120000' if driver is tcp else '120001') + '/protocol-lifecycle')
                host.apply(dict(Version=1, Rules=[]), original, 'Remove', snapshot); assert host.read()['Hash'] == 'Absent'
            command(['systemctl', 'disable', '--now', target_unit]); checks.append('component-removal-after-reboot')
        print(json.dumps(dict(passed=True, afterReboot=args.after_reboot, checks=checks, productionChanged=False)))
    finally:
        for p in connections + associations: p.close()


if __name__ == '__main__': main()
