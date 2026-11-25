"""Socket-activated primary/standby worker; embedded sources are snapshot pinned."""
import argparse
import json
import os
from pathlib import Path
import socket
import sys

if 'FORWARD_GROUP_SOURCE' not in globals():
    FORWARD_GROUP_SOURCE = Path(__file__).with_name('forward-target-groups.py').read_text(encoding='utf-8')
exec(compile(FORWARD_GROUP_SOURCE, 'forward-target-groups.py', 'exec'))
if 'TCP_PROXY_WORKER_SOURCE' not in globals():
    TCP_PROXY_WORKER_SOURCE = Path(__file__).with_name('tcp-proxy-worker.py').read_text(encoding='utf-8')
exec(compile(TCP_PROXY_WORKER_SOURCE.split('\nif __name__ ==', 1)[0], 'tcp-proxy-worker.py', 'exec'))
tcp_group_run = run
proxy_group_header = header
if 'UDP_WORKER_SOURCE' not in globals():
    UDP_WORKER_SOURCE = Path(__file__).with_name('udp-forward-worker.py').read_text(encoding='utf-8')
exec(compile(UDP_WORKER_SOURCE.split('\nif __name__ ==', 1)[0], 'udp-forward-worker.py', 'exec'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--rule', required=True)
    parser.add_argument('--transport', choices=('TCP', 'UDP'), default='TCP')
    args = parser.parse_args()
    config_path = Path(args.config)
    if config_path.is_symlink() or config_path.stat().st_size > 1024 * 1024:
        raise ValueError('Untrusted forwarding group configuration.')
    config = json.loads(config_path.read_text())
    matches = [r for r in config['Rules'] if r['Id'] == args.rule and r['Enabled']]
    if len(matches) != 1:
        raise ValueError('Owned enabled forwarding group is required.')
    rule = matches[0]
    rule['TargetGroup'] = normalize_group(rule, args.transport)
    if rule['TargetGroup'] is None:
        raise ValueError('Explicit target group is required.')
    count = int(os.environ.pop('LISTEN_FDS', '0'))
    if os.environ.pop('LISTEN_PID', '') != str(os.getpid()) or count not in (1, 2):
        raise ValueError('Owned socket activation is required.')
    os.environ.pop('LISTEN_FDNAMES', None)
    listeners = [socket.socket(fileno=fd) for fd in range(3, 3 + count)]
    runtime = Path(os.environ.get('RUNTIME_DIRECTORY', '/run/may-' + args.transport.lower() + '-forward-' + rule['Id']))
    if not runtime.is_absolute() or not runtime.is_dir() or runtime.is_symlink():
        raise ValueError('Owned systemd runtime directory is required.')
    monitor = TargetMonitor(rule, args.transport, runtime / 'group-status.json',
                            probe=lambda endpoint: health_probe(rule, endpoint, args.transport, proxy_header=proxy_group_header))
    proxy_probe = None
    try:
        if rule['TargetGroup']['Health']['Type'] == 'Proxy':
            credential = Path(os.environ['CREDENTIALS_DIRECTORY']) / 'proxy-health'
            if credential.is_symlink() or credential.stat().st_size > 262144: raise ValueError('Invalid private probe credential.')
            document = json.loads(credential.read_text())
            entry = document['Rules'][rule['Id']]
            if entry['RuleFingerprint'] != group_fingerprint(rule) or entry['NodeFingerprint'] != rule['Validation']['NodeFingerprint']: raise ValueError('Probe credential source drift.')
            proxy_probe = ProxyProbe(rule, document, runtime)
            proxy_probe.start()
            monitor.probe = proxy_probe.probe
            monitor.details = lambda: copy.deepcopy(proxy_probe.evidence)
        if args.transport == 'TCP' and any(s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or not s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) for s in listeners):
            raise ValueError('Invalid group activation listener.')
        monitor.start()
        if args.transport == 'TCP':
            tcp_group_run(listeners, rule['TargetAddress'], rule['TargetPort'], rule.get('ProxyProtocol'), source_selector=monitor.selected, receive=rule.get('ProxyReceive'))
        else:
            Relay(listeners, (rule['TargetAddress'], rule['TargetPort']), rule['SessionTimeoutSeconds'], rule['MaximumSessions'],
                  allowed=rule['AllowedSources'], source_selector=monitor.selected, target_healthy=monitor.healthy).run()
    finally:
        monitor.close()
        if proxy_probe is not None: proxy_probe.close()
        for listener in listeners: listener.close()


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError):
        print('Owned forwarding target group failed; inspect component state.', file=sys.stderr)
        sys.exit(1)
