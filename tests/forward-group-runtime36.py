"""Linux socket-activation and unprivileged primary/standby runtime acceptance."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import test_forward_target_groups as tests


class DatagramTarget:
    def __init__(self, family=socket.AF_INET):
        self.socket = socket.socket(family, socket.SOCK_DGRAM); self.socket.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0)); self.socket.settimeout(.1)
        self.endpoint = self.socket.getsockname()[:2]; self.enabled = True; self.stop = threading.Event(); self.received = 0
        def run():
            while not self.stop.is_set():
                try: data, peer = self.socket.recvfrom(65535)
                except socket.timeout: continue
                except OSError: break
                self.received += 1
                if self.enabled:
                    try: self.socket.sendto(data, peer)
                    except OSError: break
        self.thread = threading.Thread(target=run, daemon=True); self.thread.start()
    def close(self): self.stop.set(); self.socket.close(); self.thread.join(2)


class Runtime:
    def __init__(self, root, rule, transport):
        self.rule, self.transport = copy.deepcopy(rule), transport
        self.directory = root / (transport.lower() + '-' + secrets.token_hex(4)); self.directory.mkdir(mode=0o755)
        self.runtime = self.directory / 'runtime'; self.runtime.mkdir(mode=0o700)
        self.credentials = self.directory / 'credentials'; self.credentials.mkdir(mode=0o700)
        self.config = self.credentials / 'forward-config'; self.config.write_text(json.dumps({'Version': 1, 'Rules': [rule]})); self.config.chmod(0o400)
        if os.getuid() == 0:
            nobody = pwd.getpwnam('nobody'); self.uid, self.gid = nobody.pw_uid, nobody.pw_gid
            for path in [self.runtime, self.credentials, self.config]: os.chown(path, self.uid, self.gid)
        else: self.uid, self.gid = os.getuid(), os.getgid()
        driver = tests.TCP if transport == 'TCP' else tests.UDP
        material = driver.material({'Version': 1, 'Rules': [rule]}, '/usr/lib/systemd/systemd-socket-proxyd' if transport == 'TCP' else '/usr/bin/python3')
        self.worker = self.directory / 'worker.py'; self.worker.write_text(material[driver.GROUP_WORKER]); self.worker.chmod(0o644)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'TCP' else socket.SOCK_DGRAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); self.listener.bind(('127.0.0.1', 0))
        if transport == 'TCP': self.listener.listen()
        self.endpoint = self.listener.getsockname()
        wrapper = self.directory / 'activate.py'
        wrapper.write_text('import os,runpy,sys\nfd=int(sys.argv[1]);os.dup2(fd,3)\nif fd!=3:os.close(fd)\nos.environ["LISTEN_FDS"]="1";os.environ["LISTEN_PID"]=str(os.getpid())\nuid,gid=int(sys.argv[2]),int(sys.argv[3])\nif os.getuid()==0:os.setgroups([]);os.setgid(gid);os.setuid(uid)\nsys.argv=sys.argv[4:];runpy.run_path(sys.argv[0],run_name="__main__")\n')
        wrapper.chmod(0o644)
        environment = dict(os.environ, RUNTIME_DIRECTORY=str(self.runtime))
        self.log = (self.directory / 'worker.log').open('wb')
        self.process = subprocess.Popen([sys.executable, '-I', str(wrapper), str(self.listener.fileno()), str(self.uid), str(self.gid), str(self.worker), '--config', str(self.config), '--rule', rule['Id'], '--transport', transport], pass_fds=(self.listener.fileno(),), env=environment, stdout=self.log, stderr=subprocess.STDOUT)
        self.listener.close()

    def status(self):
        if self.process.poll() is not None: raise AssertionError('Runtime worker exited: ' + (self.directory / 'worker.log').read_text())
        path = self.runtime / 'group-status.json'
        return json.loads(path.read_text()) if path.exists() else None

    def wait(self, selected, seconds=26):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            value = self.status()
            if value is not None and value['Selected'] == selected: return value
            time.sleep(.08)
        raise AssertionError('Target selection did not converge within bound.')

    def close(self):
        self.process.terminate()
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=5)
        self.log.close()
        assert self.process.poll() is not None


def tcp_probe(endpoint):
    client = socket.create_connection(endpoint, timeout=3); client.settimeout(3)
    banner = bytearray()
    while not banner.endswith(b'\n'):
        part = client.recv(1)
        if not part: raise AssertionError('Missing forwarded service banner.')
        banner.extend(part)
    payload = secrets.token_bytes(64); client.sendall(payload)
    assert client.recv(128) == payload
    return client, bytes(banner)


def tcp_case(root):
    primary = tests.Target(banner=b'SSH-2.0-Primary\r\n'); backup = tests.Target(banner=b'SSH-2.0-Standby\r\n')
    runtime = None; old = None
    try:
        rule = tests.rule(); rule['TargetAddress'], rule['TargetPort'] = primary.endpoint
        rule['TargetGroup']['BackupAddress'], rule['TargetGroup']['BackupPort'] = backup.endpoint
        rule = tests.TCP.normalize({'Version': 1, 'Rules': [rule]})['Rules'][0]
        runtime = Runtime(root, rule, 'TCP'); initial = runtime.wait(0)
        old, banner = tcp_probe(runtime.endpoint); assert b'Primary' in banner
        primary.enabled = False; changed = runtime.wait(1)
        assert changed['Failures'][0] >= 2
        client, banner = tcp_probe(runtime.endpoint); client.close(); assert b'Standby' in banner
        old.sendall(b'old-stream'); assert old.recv(128) == b'old-stream'
        primary.enabled = True
        first = None; until = time.monotonic() + 28
        while time.monotonic() < until:
            value = runtime.status()
            if value['Successes'][0] > 0 and first is None: first = value['AtUnix']
            if value['Selected'] == 0:
                assert value['Successes'][0] >= 2 and first is not None and value['AtUnix'] - first >= 9.9
                break
            time.sleep(.08)
        else: raise AssertionError('Stable recovery did not return to primary.')
        client, banner = tcp_probe(runtime.endpoint); client.close(); assert b'Primary' in banner
        primary.enabled = False; backup.enabled = False; runtime.wait(None)
        with socket.create_connection(runtime.endpoint, timeout=3) as client:
            client.settimeout(3)
            try: reply = client.recv(1)
            except ConnectionResetError: reply = b''
            assert reply == b''
        assert old is not None; old.close(); old = None
        return {'transport': 'TCP', 'actual_socket_activation': True, 'unprivileged_uid': runtime.uid, 'primary_then_standby': True, 'failure_confirmations': True, 'existing_stream_preserved': True, 'real_monotonic_hold': True, 'all_failed_closed': True, 'runtime_credential_mode': oct(runtime.config.stat().st_mode & 0o777)}
    finally:
        if old: old.close()
        if runtime: runtime.close()
        primary.close(); backup.close()


def udp_case(root):
    primary, backup = DatagramTarget(), DatagramTarget(socket.AF_INET6)
    runtime = None
    try:
        rule = tests.rule('Echo'); rule['TargetAddress'], rule['TargetPort'] = primary.endpoint
        rule['TargetGroup']['BackupAddress'], rule['TargetGroup']['BackupPort'] = backup.endpoint
        rule = tests.UDP.normalize({'Version': 1, 'Rules': [rule]})['Rules'][0]
        runtime = Runtime(root, rule, 'UDP'); runtime.wait(0)
        def roundtrip():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3); payload = secrets.token_bytes(32); client.sendto(payload, runtime.endpoint)
                assert client.recv(64) == payload
        roundtrip(); primary.enabled = False; changed = runtime.wait(1)
        assert changed['Failures'][0] >= 2
        roundtrip(); assert backup.received >= 2
        backup.enabled = False; runtime.wait(None)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.3); client.sendto(b'no-fallback', runtime.endpoint)
            try: client.recv(128)
            except socket.timeout: pass
            else: raise AssertionError('Unavailable UDP group forwarded unexpectedly.')
        return {'transport': 'UDP', 'actual_socket_activation': True, 'unprivileged_uid': runtime.uid, 'ipv6_standby_real_datagrams': True, 'response_health': True, 'all_failed_closed': True}
    finally:
        if runtime: runtime.close()
        primary.close(); backup.close()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True); parser.add_argument('--case', choices=['TCP', 'UDP', 'all'], default='all'); args = parser.parse_args()
    if sys.platform != 'linux': raise SystemExit('Linux socket activation is required.')
    with tempfile.TemporaryDirectory(prefix='may-round36-') as directory:
        root = Path(directory); root.chmod(0o755); cases = []
        if args.case in ['TCP', 'all']: cases.append(tcp_case(root))
        if args.case in ['UDP', 'all']: cases.append(udp_case(root))
        result = {'SyntheticOnly': True, 'Cases': cases, 'OwnedProcessesStopped': True, 'ProductionChanged': False}
        Path(args.output).write_text(json.dumps(result, indent=2)); print(json.dumps(result))


if __name__ == '__main__': main()
