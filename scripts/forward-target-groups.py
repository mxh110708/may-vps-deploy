"""Explicit two-target failover, bounded probes and monotonic recovery policy."""
import hashlib
import base64
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import threading
import time


def normalize_group(rule, transport='TCP'):
    value = rule.get('TargetGroup')
    if value is None:
        if 'TargetGroup' in rule: raise ValueError('Null target groups are not supported.')
        return None
    fields = {'Version', 'BackupAddress', 'BackupPort', 'Health', 'IntervalSeconds',
              'TimeoutSeconds', 'FailureThreshold', 'RecoveryThreshold', 'RecoveryHoldSeconds', 'AutoReturn'}
    if not isinstance(value, dict) or set(value) != fields or type(value['Version']) is not int or value['Version'] != 1:
        raise ValueError('Unsupported explicit primary/standby group.')
    backup = ipaddress.ip_address(value['BackupAddress'])
    if backup.is_unspecified or backup.is_multicast or backup.version == 4 and backup.packed[0] >= 224 or getattr(backup, 'ipv4_mapped', None) or '%' in str(backup):
        raise ValueError('A unicast standby address is required.')
    for key, low, high in [('BackupPort', 1, 65535), ('IntervalSeconds', 5, 300), ('TimeoutSeconds', 1, 10),
                           ('FailureThreshold', 2, 10), ('RecoveryThreshold', 2, 10), ('RecoveryHoldSeconds', 10, 600)]:
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError('Invalid failover policy bounds.')
    if value['IntervalSeconds'] < 2 * value['TimeoutSeconds'] or type(value['AutoReturn']) is not bool:
        raise ValueError('Probe interval must contain both bounded probes.')
    if (str(backup), value['BackupPort']) == (rule['TargetAddress'], rule['TargetPort']):
        raise ValueError('Primary and standby endpoints must differ.')
    kind = rule['Validation']['Type']
    health = value['Health']
    if not isinstance(health, dict):
        raise ValueError('An explicit health probe is required.')
    if transport == 'TCP':
        allowed = {'Tls': 'Tls', 'Ssh': 'Ssh', 'Proxy': 'Connect'}
        expected = allowed.get(kind)
        if expected is None or health != ({'Type': 'Tls', 'ServerName': rule['Validation']['ServerName']} if kind == 'Tls' else {'Type': expected}):
            raise ValueError('Health probe must match the declared TCP service; proxy health is reachability only.')
    elif transport == 'UDP':
        if kind not in ('Dns', 'Echo') or health != rule['Validation']:
            raise ValueError('UDP target groups require DNS or echo response health, not opaque encrypted datagrams.')
    else:
        raise ValueError('Unsupported forwarding transport.')
    return dict(value, BackupAddress=str(backup), Health=dict(health))


def group_targets(rule):
    return [(rule['TargetAddress'], rule['TargetPort']),
            (rule['TargetGroup']['BackupAddress'], rule['TargetGroup']['BackupPort'])]


def group_fingerprint(rule):
    def canonical(value):
        if isinstance(value, dict): return 'o{' + '|'.join(base64.b64encode(key.encode()).decode() + ':' + canonical(value[key]) for key in sorted(value)) + '}'
        if isinstance(value, list): return 'a[' + '|'.join(canonical(v) for v in value) + ']'
        if isinstance(value, str): return 's' + base64.b64encode(value.encode()).decode()
        if type(value) is bool: return 'b1' if value else 'b0'
        if type(value) is int: return 'i' + str(value)
        if value is None: return 'n'
        raise ValueError('Unsupported group fingerprint value.')
    return hashlib.sha256(canonical(rule).encode()).hexdigest()


class FailoverPolicy:
    """One snapshot per round; never replay traffic or use wall time for holds."""
    def __init__(self, group, clock=time.monotonic):
        self.group, self.clock = group, clock
        self.healthy = [False, False]
        self.successes = [0, 0]
        self.failures = [0, 0]
        self.since = [None, None]
        self.selected = None
        self.initial = True

    def observe(self, results):
        if len(results) != 2 or any(type(v) is not bool for v in results):
            raise ValueError('Two explicit health outcomes are required.')
        now = self.clock()
        for index, success in enumerate(results):
            self.successes[index] = min(10, self.successes[index] + 1) if success else 0
            self.failures[index] = 0 if success else min(10, self.failures[index] + 1)
            if success and self.since[index] is None:
                self.since[index] = now
            if not success:
                self.since[index] = None
            if self.initial:
                self.healthy[index] = success
            elif self.failures[index] >= self.group['FailureThreshold']:
                self.healthy[index] = False
            elif self.successes[index] >= self.group['RecoveryThreshold']:
                self.healthy[index] = True
        if self.selected is None or not self.healthy[self.selected]:
            self.selected = next((i for i in (0, 1) if self.healthy[i]), None)
        elif self.selected == 1 and self.group['AutoReturn'] and self.healthy[0] and self.successes[0] >= self.group['RecoveryThreshold']:
            if self.since[0] is not None and now - self.since[0] >= self.group['RecoveryHoldSeconds']:
                self.selected = 0
        self.initial = False
        return self.selected

    def snapshot(self):
        return {'Selected': self.selected, 'Healthy': list(self.healthy), 'Successes': list(self.successes),
                'Failures': list(self.failures), 'State': 'Unavailable' if self.selected is None else 'Primary' if self.selected == 0 else 'Standby'}


def dns_query(name, kind):
    header = os.urandom(2) + b'\x01\x00\x00\x01' + b'\0' * 6
    labels = b''.join(bytes([len(v)]) + v.encode('ascii') for v in name.lower().split('.'))
    return header + labels + b'\0' + struct.pack('!HH', 1 if kind == 'A' else 28, 1)


def dns_matches(query, answer):
    if len(answer) < len(query) or len(answer) > 4096 or answer[:2] != query[:2] or answer[12:len(query)] != query[12:]:
        return False
    flags, questions, records = struct.unpack('!HHH', answer[2:8])
    if flags & 0xfa0f != 0x8000 or questions != 1 or not 1 <= records <= 64:
        return False
    wanted = struct.unpack('!H', query[-4:-2])[0]
    offset = len(query)
    for _ in range(records):
        for _ in range(128):
            if offset >= len(answer): return False
            length = answer[offset]; offset += 1
            if length == 0: break
            if length & 0xc0 == 0xc0:
                if offset >= len(answer) or ((length & 0x3f) << 8 | answer[offset]) >= len(answer): return False
                offset += 1; break
            if length > 63 or offset + length > len(answer): return False
            offset += length
        else: return False
        if offset + 10 > len(answer): return False
        kind, cls, _, length = struct.unpack('!HHIH', answer[offset:offset + 10]); offset += 10
        if offset + length > len(answer): return False
        if kind == wanted and cls == 1 and length == (4 if kind == 1 else 16): return True
        offset += length
    return False


def health_probe(rule, endpoint, transport='TCP', context=None, proxy_header=None):
    """Probe exactly this target; no DNS address lookup, fallback or TLS bypass."""
    group = rule['TargetGroup']; health = group['Health']; timeout = group['TimeoutSeconds']
    deadline = time.monotonic() + timeout
    target, port = endpoint
    family = socket.AF_INET6 if ipaddress.ip_address(target).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM if transport == 'TCP' else socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout); sock.connect((target, port))
            if transport == 'UDP':
                request = dns_query(health['QueryName'], health['QueryType']) if health['Type'] == 'Dns' else b'MAY-HEALTH-' + os.urandom(24)
                sock.send(request)
                for _ in range(16):
                    sock.settimeout(max(.001, deadline - time.monotonic()))
                    answer = sock.recv(4097)
                    if dns_matches(request, answer) if health['Type'] == 'Dns' else request == answer:
                        return True
                    if time.monotonic() >= deadline: break
                return False
            if rule.get('ProxyProtocol'):
                if proxy_header is None: return False
                sock.sendall(proxy_header(rule['ProxyProtocol'], sock.getsockname(), sock.getpeername()))
            sock.settimeout(max(.001, deadline - time.monotonic()))
            if health['Type'] == 'Connect': return True
            if health['Type'] == 'Tls':
                ctx = context or ssl.create_default_context()
                if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname: return False
                with ctx.wrap_socket(sock, server_hostname=health['ServerName']): return True
            data = bytearray()
            while len(data) < 4096:
                sock.settimeout(max(.001, deadline - time.monotonic()))
                part = sock.recv(min(512, 4096 - len(data)))
                if not part: return False
                data.extend(part)
                if any(line.startswith(b'SSH-2.0-') and 9 <= len(line) <= 256 for line in bytes(data).split(b'\n')[:-1]): return True
                if time.monotonic() >= deadline: break
    except (OSError, ValueError, ssl.SSLError):
        return False
    return False


class TargetMonitor:
    def __init__(self, rule, transport='TCP', status=None, probe=None):
        self.rule, self.transport, self.status = rule, transport, status
        self.targets = group_targets(rule); self.policy = FailoverPolicy(rule['TargetGroup'])
        self.probe = probe or (lambda target: health_probe(rule, target, transport))
        self.lock, self.stop = threading.Lock(), threading.Event()
        self.thread = None
        self.sampled = None

    def round(self):
        outcomes = [bool(self.probe(target)) for target in self.targets]
        with self.lock:
            self.policy.observe(outcomes)
            self.sampled = time.monotonic()
            value = dict(self.policy.snapshot(), RuleId=self.rule['Id'], Fingerprint=group_fingerprint(self.rule),
                         AtUnix=time.time(), ProbeType=self.rule['TargetGroup']['Health']['Type'], LastResults=outcomes)
        if self.status is not None:
            path = Path(self.status); temporary = path.with_name(path.name + '.tmp')
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as stream: json.dump(value, stream, separators=(',', ':'))
                os.replace(temporary, path)
            finally:
                try: temporary.unlink()
                except FileNotFoundError: pass
        return value

    def start(self):
        self.round()
        def loop():
            interval = self.rule['TargetGroup']['IntervalSeconds']; next_at = time.monotonic() + interval
            while not self.stop.wait(max(0, next_at - time.monotonic())):
                self.round()
                next_at = max(next_at + interval, time.monotonic())
        self.thread = threading.Thread(target=loop, name='may-forward-health', daemon=True); self.thread.start()

    def selected(self):
        with self.lock:
            if self.sampled is None or time.monotonic() - self.sampled > 2 * self.rule['TargetGroup']['IntervalSeconds'] + 2 * self.rule['TargetGroup']['TimeoutSeconds'] + 5: return None
            selected = self.policy.selected
            return self.targets[selected] if selected is not None else None

    def healthy(self, endpoint):
        with self.lock:
            if self.sampled is None or time.monotonic() - self.sampled > 2 * self.rule['TargetGroup']['IntervalSeconds'] + 2 * self.rule['TargetGroup']['TimeoutSeconds'] + 5: return False
            return endpoint in self.targets and self.policy.healthy[self.targets.index(endpoint)]

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(2 * self.rule['TargetGroup']['TimeoutSeconds'] + 1)


def group_status(rule, path, now=None):
    path = Path(path); now = time.time() if now is None else now
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8192:
        return {'Id': rule['Id'], 'Fresh': False, 'State': 'NotRunning'}
    try:
        value = json.loads(path.read_text())
        fresh = value['RuleId'] == rule['Id'] and value['Fingerprint'] == group_fingerprint(rule) and 0 <= now - value['AtUnix'] <= 2 * rule['TargetGroup']['IntervalSeconds'] + 2 * rule['TargetGroup']['TimeoutSeconds'] + 5
        if not fresh: return {'Id': rule['Id'], 'Fresh': False, 'State': 'Stale'}
        return dict(value, Id=rule['Id'], Fresh=True)
    except (OSError, KeyError, TypeError, ValueError):
        return {'Id': rule['Id'], 'Fresh': False, 'State': 'Unknown'}


def probe_groups(host, transport='TCP', proxy_header=None):
    before = host.read()
    groups = []
    for rule in (before.get('Configuration') or {}).get('Rules', []):
        if not rule['Enabled'] or 'TargetGroup' not in rule: continue
        checks = [{'Index': index, 'Address': endpoint[0], 'Port': endpoint[1],
                   'Passed': health_probe(rule, endpoint, transport, proxy_header=proxy_header)} for index, endpoint in enumerate(group_targets(rule))]
        groups.append({'RuleId': rule['Id'], 'RuleFingerprint': group_fingerprint(rule), 'HealthType': rule['TargetGroup']['Health']['Type'], 'Targets': checks, 'AtUnix': time.time()})
    after = host.read()
    if before['Hash'] != after['Hash']: raise ValueError('Forwarding changed during group probe.')
    return {'ConfigurationHash': before['Hash'], 'Groups': groups}


def target_group_program():
    return ('FORWARD_GROUP_SOURCE = ' + repr(FORWARD_GROUP_SOURCE) + '\nTCP_PROXY_WORKER_SOURCE = ' + repr(TCP_PROXY_WORKER_SOURCE) +
            '\nUDP_WORKER_SOURCE = ' + repr(UDP_WORKER_SOURCE) + '\n' + FORWARD_GROUP_WORKER_SOURCE)


def target_group_service(rule, config, transport):
    prefix = 'may-' + transport.lower() + '-forward-' + rule['Id']
    return ('# Managed by May VPS Deploy ' + transport + ' forwarding.\n[Unit]\nDescription=May bounded primary standby forwarding\nBindsTo=' + prefix + '.socket\nAfter=' + prefix + '.socket\n\n[Service]\nType=simple\n' +
            'LoadCredential=forward-config:' + config + '\nExecStart=/usr/bin/python3 -I /etc/may-' + transport.lower() + '-forward/group-worker.py --config %d/forward-config --rule ' + rule['Id'] + ' --transport ' + transport +
            '\nDynamicUser=yes\nRuntimeDirectory=' + prefix + '\nRuntimeDirectoryMode=0750\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_INET AF_INET6\nCapabilityBoundingSet=\nMemoryMax=96M\nLimitNOFILE=' + ('2048' if transport == 'UDP' else '1024') + '\nTimeoutStopSec=10s\n')
