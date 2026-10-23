"""Owned TCP socket activation, ACLs and transaction recovery. No controller daemon."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tarfile


CONFIG = '/etc/may-tcp-forward/config.json'
ACL = '/etc/may-tcp-forward/whitelist.nft'
ACL_UNIT = 'may-tcp-forward-firewall.service'
TABLE = 'may_tcp_forward'
HEADER = '# Managed by May VPS Deploy TCP forwarding.\n'


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def normalize(value):
    if not isinstance(value, dict) or set(value) != {'Version', 'Rules'} or type(value['Version']) is not int or value['Version'] != 1 or not isinstance(value['Rules'], list) or len(value['Rules']) > 16:
        raise ValueError('Unsupported TCP forwarding configuration.')
    ids, ports, result = set(), set(), []
    for rule in value['Rules']:
        fields = {'Id', 'Name', 'Enabled', 'ListenFamily', 'ListenPort', 'TargetAddress', 'TargetPort', 'AllowedSources', 'Validation'}
        if not isinstance(rule, dict) or set(rule) != fields:
            raise ValueError('Unsupported TCP forwarding rule.')
        if not re.fullmatch('[a-f0-9]{32}', rule['Id']) or rule['Id'] in ids:
            raise ValueError('Invalid or duplicate forwarding identity.')
        ids.add(rule['Id'])
        if not isinstance(rule['Name'], str) or not 1 <= len(rule['Name']) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in rule['Name']):
            raise ValueError('Invalid forwarding name.')
        if type(rule['Enabled']) is not bool or rule['ListenFamily'] not in ('IPv4', 'IPv6', 'DualStack'):
            raise ValueError('Invalid forwarding listener.')
        for key in ('ListenPort', 'TargetPort'):
            if type(rule[key]) is not int or not 1 <= rule[key] <= 65535:
                raise ValueError('Invalid forwarding port.')
        if rule['ListenPort'] in ports:
            raise ValueError('Duplicate forwarding port.')
        ports.add(rule['ListenPort'])
        target = ipaddress.ip_address(rule['TargetAddress'])
        if target.is_unspecified or target.is_multicast or getattr(target, 'ipv4_mapped', None) or '%' in str(target):
            raise ValueError('A unicast target address is required.')
        if not isinstance(rule['AllowedSources'], list) or not 1 <= len(rule['AllowedSources']) <= 32:
            raise ValueError('Explicit source addresses or networks are required.')
        networks = []
        for source in rule['AllowedSources']:
            network = ipaddress.ip_network(source, strict=False)
            if '%' in source or getattr(network.network_address, 'ipv4_mapped', None):
                raise ValueError('Invalid allowed source.')
            networks.append(str(network))
        check = rule['Validation']
        kind = check.get('Type') if isinstance(check, dict) else None
        if kind == 'Tls':
            name = check.get('ServerName', '')
            if set(check) != {'Type', 'ServerName'} or len(name) > 253 or '.' not in name or not all(re.fullmatch('[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in name.split('.')):
                raise ValueError('Invalid TLS validation hostname.')
        elif kind == 'Ssh':
            if set(check) != {'Type'}:
                raise ValueError('Unsupported SSH validation options.')
        elif kind == 'Proxy':
            if set(check) != {'Type', 'SchemeId', 'NodeId', 'NodeFingerprint'} or not all(re.fullmatch('[a-f0-9]{32}', check[k]) for k in ('SchemeId', 'NodeId')) or not re.fullmatch('[a-f0-9]{64}', check['NodeFingerprint']):
                raise ValueError('Invalid proxy validation reference.')
        else:
            raise ValueError('Application-level validation is required.')
        result.append(dict(rule, TargetAddress=str(target), AllowedSources=sorted(set(networks))))
    return {'Version': 1, 'Rules': result}


def unit_name(rule, suffix):
    return 'may-tcp-forward-' + rule['Id'] + '.' + suffix


def unit_path(name):
    if name != ACL_UNIT and not re.fullmatch(r'may-tcp-forward-[a-f0-9]{32}\.(socket|service)', name):
        raise ValueError('Unowned forwarding unit.')
    return '/etc/systemd/system/' + name


def listeners(rule):
    families = ('IPv4', 'IPv6') if rule['ListenFamily'] == 'DualStack' else (rule['ListenFamily'],)
    return [(socket.AF_INET if f == 'IPv4' else socket.AF_INET6, '0.0.0.0' if f == 'IPv4' else '::', rule['ListenPort']) for f in families]


def material(config, proxy):
    files = {CONFIG: encoded(config) + '\n'}
    lines = [HEADER.rstrip(), 'table inet ' + TABLE + ' {}', 'flush table inet ' + TABLE,
             'table inet ' + TABLE + ' {', ' chain input {', '  type filter hook input priority -10; policy accept;', '  iifname "lo" accept']
    for rule in config['Rules']:
        name = unit_name(rule, 'socket')
        files[unit_path(name)] = HEADER + '[Unit]\nDescription=May TCP forward socket\nBindsTo=' + ACL_UNIT + '\nAfter=' + ACL_UNIT + '\n\n[Socket]\n' + ''.join('ListenStream=' + (address if family == socket.AF_INET else '[' + address + ']') + ':' + str(port) + '\n' for family, address, port in listeners(rule)) + 'BindIPv6Only=ipv6-only\nAccept=no\nNoDelay=true\n\n[Install]\nWantedBy=sockets.target\n'
        # socket-proxyd splits at the last colon; brackets are not removed by
        # the Debian-supported resolver and would become part of the hostname.
        target = rule['TargetAddress']
        files[unit_path(unit_name(rule, 'service'))] = HEADER + '[Unit]\nDescription=May TCP forward worker\nBindsTo=' + name + '\nAfter=' + name + '\n\n[Service]\nType=notify\nExecStart=' + proxy + ' --connections-max=256 --exit-idle-time=60s ' + target + ':' + str(rule['TargetPort']) + '\nDynamicUser=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nCapabilityBoundingSet=\nTimeoutStopSec=10s\n'
        if not rule['Enabled']:
            continue
        for version, family in ((4, 'ip'), (6, 'ip6')):
            sources = [s for s in rule['AllowedSources'] if ipaddress.ip_network(s).version == version]
            if sources:
                lines.append('  tcp dport ' + str(rule['ListenPort']) + ' ' + family + ' saddr { ' + ', '.join(sources) + ' } accept')
        lines.append('  tcp dport ' + str(rule['ListenPort']) + ' drop')
    lines += [' }', '}']
    files[ACL] = '\n'.join(lines) + '\n'
    files[unit_path(ACL_UNIT)] = HEADER + '[Unit]\nDescription=May TCP forwarding source whitelist\nAfter=nftables.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f ' + ACL + '\nExecStop=/usr/sbin/nft delete table inet ' + TABLE + '\n\n[Install]\nWantedBy=multi-user.target\n'
    return files


def canonical_table(text):
    text = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    text = re.sub(r'table inet ' + TABLE + r'\s*\{\s*\}\s*', '', text)
    text = re.sub(r'flush table inet ' + TABLE + r'\s*', '', text)
    def network(match):
        try:
            net = ipaddress.ip_network(match.group(), strict=False)
            return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
        except ValueError:
            return match.group()
    text = re.sub(r'(?:[0-9a-fA-F]*:[0-9a-fA-F:]+|(?:\d{1,3}\.){3}\d{1,3})(?:/\d+)?', network, text)
    text = re.sub(r'\{\s*([\w.:/, -]+)\s*\}', lambda m: ','.join(sorted(p.strip().strip('"') for p in m[1].split(','))), text)
    return re.sub(r'[\s;"\']+', '', text)


if 'ForwardHost' not in globals():
    exec(compile(Path(__file__).with_name('forwarding-host.py').read_text(), 'forwarding-host.py', 'exec'))


class Host(ForwardHost):
    PREFIX = 'may-tcp-forward'
    JOURNAL = 'tcp-forward-state.json'
    DIRECTORY = '/etc/may-tcp-forward'
    CONFIG, ACL, ACL_UNIT, TABLE = CONFIG, ACL, ACL_UNIT, TABLE
    EXTRA_FILES = ()
    ARCHIVED_PROGRAMS = ()
    SOCKET_TYPE = socket.SOCK_STREAM
    normalize, material = staticmethod(normalize), staticmethod(material)
    unit_name, unit_path = staticmethod(unit_name), staticmethod(unit_path)
    canonical_table, listeners = staticmethod(canonical_table), staticmethod(listeners)

    def proxy(self):
        for candidate in ('/usr/lib/systemd/systemd-socket-proxyd', '/lib/systemd/systemd-socket-proxyd'):
            if self.path(candidate).is_file():
                return candidate
        raise ValueError('Missing systemd-socket-proxyd; install systemd first.')


def main():
    action = sys.argv[1]
    host = Host()
    if action == 'read':
        value = host.read()
        if os.environ.get('VPS_PARAM_CANDIDATE_JSON'):
            host.preflight(normalize(json.loads(os.environ['VPS_PARAM_CANDIDATE_JSON'])))
        import base64
        print('VPSDEPLOY_TCP_FORWARD_STATE_B64=' + base64.b64encode(encoded(value).encode()).decode())
    elif action == 'snapshot':
        host.snapshot(Path(sys.argv[2]), os.environ['VPS_PARAM_TCP_FORWARD_EXPECTED_HASH'])
    elif action == 'verify':
        if host.read()['Hash'] != sys.argv[2]:
            raise ValueError('TCP forwarding resources differ from the reviewed hash.')
    elif action == 'paths':
        for path in host.read()['Files']:
            print(path.lstrip('/'))
    elif action == 'apply':
        op = os.environ['VPS_PARAM_ACTION']
        if op not in ('Apply', 'Remove'):
            raise ValueError('Unsupported forwarding operation.')
        configuration = normalize(json.loads(os.environ['VPS_PARAM_CONFIG_JSON']))
        if op == 'Remove' and configuration['Rules'] or op == 'Apply' and not configuration['Rules']:
            raise ValueError('Forwarding action does not match its configuration.')
        host.apply(configuration, os.environ['VPS_PARAM_EXPECTED_HASH'], op, Path(os.environ['VPS_PARAM_EXPECTED_TRANSACTION']))
    elif action == 'rollback-check':
        host.rollback_check(Path(sys.argv[2]))
    elif action == 'rollback-prepare':
        host.rollback_prepare(Path(sys.argv[2]))
    elif action == 'rollback-complete':
        host.rollback_complete(Path(sys.argv[2]))
    else:
        raise ValueError('Unknown forwarding command.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        # Hostnames and rule names are private; do not dump payloads or tracebacks.
        print('TCP forwarding check failed; resources were not adopted or overwritten. Inspect component ownership, ports and recovery status.', file=sys.stderr)
        sys.exit(1)
