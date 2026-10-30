"""Independent UDP forwarding driver for the shared owned-resource host."""
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys

if 'ForwardHost' not in globals():
    exec(compile(Path(__file__).with_name('forwarding-host.py').read_text(), 'forwarding-host.py', 'exec'))
if 'UDP_WORKER_SOURCE' not in globals():
    UDP_WORKER_SOURCE = Path(__file__).with_name('udp-forward-worker.py').read_text()

CONFIG = '/etc/may-udp-forward/config.json'
ACL = '/etc/may-udp-forward/whitelist.nft'
WORKER = '/etc/may-udp-forward/worker.py'
ACL_UNIT = 'may-udp-forward-firewall.service'
TABLE = 'may_udp_forward'
HEADER = '# Managed by May VPS Deploy UDP forwarding.\n'


def normalize(value):
    if not isinstance(value, dict) or set(value) != {'Version', 'Rules'} or type(value['Version']) is not int or value['Version'] != 1 or not isinstance(value['Rules'], list) or len(value['Rules']) > 16:
        raise ValueError('Unsupported UDP forwarding configuration.')
    ids, ports, result = set(), set(), []
    for rule in value['Rules']:
        fields = {'Id', 'Name', 'Enabled', 'ListenFamily', 'ListenPort', 'TargetAddress', 'TargetPort', 'AllowedSources', 'Validation', 'SessionTimeoutSeconds', 'MaximumSessions'}
        if not isinstance(rule, dict) or set(rule) != fields or not re.fullmatch('[a-f0-9]{32}', rule['Id']) or rule['Id'] in ids:
            raise ValueError('Invalid or duplicate UDP rule.')
        ids.add(rule['Id'])
        if not isinstance(rule['Name'], str) or not 1 <= len(rule['Name']) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in rule['Name']):
            raise ValueError('Invalid UDP rule name.')
        if type(rule['Enabled']) is not bool or rule['ListenFamily'] not in ('IPv4', 'IPv6', 'DualStack'):
            raise ValueError('Invalid UDP listener.')
        for key, low, high in [('ListenPort', 1, 65535), ('TargetPort', 1, 65535), ('SessionTimeoutSeconds', 10, 600), ('MaximumSessions', 1, 1024)]:
            if type(rule[key]) is not int or not low <= rule[key] <= high:
                raise ValueError('Invalid UDP port or session limits.')
        if rule['ListenPort'] in ports:
            raise ValueError('Duplicate UDP port.')
        ports.add(rule['ListenPort'])
        target = ipaddress.ip_address(rule['TargetAddress'])
        if target.is_unspecified or target.is_multicast or getattr(target, 'ipv4_mapped', None) or '%' in str(target):
            raise ValueError('A unicast UDP target is required.')
        if not isinstance(rule['AllowedSources'], list) or not 1 <= len(rule['AllowedSources']) <= 32:
            raise ValueError('Explicit UDP source addresses or networks are required.')
        sources = []
        for source in rule['AllowedSources']:
            network = ipaddress.ip_network(source, strict=False)
            if '%' in source or getattr(network.network_address, 'ipv4_mapped', None):
                raise ValueError('Invalid UDP source.')
            sources.append(str(network))
        check = rule['Validation']
        if not isinstance(check, dict):
            raise ValueError('UDP application validation is required.')
        if check.get('Type') == 'TcpChain':
            parts = check.get('FrontInstance', '').split('/')
            if set(check) != {'Type', 'ChainId', 'FrontInstance'} or not isinstance(check.get('ChainId'), str) or not re.fullmatch('[a-f0-9]{32}', check['ChainId']) or len(parts) != 3 or parts[2] != 'May-VPS-Deploy' or any(not re.fullmatch(r'[^\W_][\w. -]{0,63}', p) or p.endswith(('.', ' ')) for p in parts[:2]):
                raise ValueError('Invalid UDP chain reference.')
        elif check.get('Type') == 'Echo':
            if set(check) != {'Type'}:
                raise ValueError('Unexpected UDP echo options.')
        elif check.get('Type') in ('Dns', 'Shadowsocks'):
            name = check.get('QueryName', '')
            fields = {'Type', 'QueryName', 'QueryType'}
            if check['Type'] == 'Shadowsocks':
                fields |= {'SchemeId', 'NodeId', 'NodeFingerprint', 'ResolverAddress', 'ResolverPort'}
                for field, size in [('SchemeId', 32), ('NodeId', 32), ('NodeFingerprint', 64)]:
                    if not isinstance(check.get(field), str) or not re.fullmatch('[a-f0-9]{'+str(size)+'}', check[field]):
                        raise ValueError('Invalid UDP proxy source reference.')
                resolver = ipaddress.ip_address(check.get('ResolverAddress', ''))
                if resolver.is_unspecified or resolver.is_multicast or getattr(resolver, 'ipv4_mapped', None) or '%' in str(resolver) or type(check.get('ResolverPort')) is not int or not 1 <= check['ResolverPort'] <= 65535:
                    raise ValueError('Invalid UDP proxy DNS destination.')
                check = dict(check, ResolverAddress=str(resolver))
                rule = dict(rule, Validation=check)
            if set(check) != fields or check.get('QueryType') not in ('A', 'AAAA') or not isinstance(name, str) or len(name) > 253 or '.' not in name or not all(re.fullmatch('[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in name.split('.')):
                raise ValueError('Invalid UDP DNS validation query.')
        else:
            raise ValueError('Unsupported UDP application validation.')
        result.append(dict(rule, TargetAddress=str(target), AllowedSources=sorted(set(sources))))
    return {'Version': 1, 'Rules': result}


def unit_name(rule, suffix):
    return 'may-udp-forward-' + rule['Id'] + '.' + suffix


def unit_path(name):
    if name != ACL_UNIT and not re.fullmatch(r'may-udp-forward-[a-f0-9]{32}\.(socket|service)', name):
        raise ValueError('Unowned UDP forwarding unit.')
    return '/etc/systemd/system/' + name


def listeners(rule):
    families = ('IPv4', 'IPv6') if rule['ListenFamily'] == 'DualStack' else (rule['ListenFamily'],)
    return [(socket.AF_INET if f == 'IPv4' else socket.AF_INET6, '0.0.0.0' if f == 'IPv4' else '::', rule['ListenPort']) for f in families]


def material(config, python):
    files = {CONFIG: encoded(config) + '\n', WORKER: UDP_WORKER_SOURCE}
    lines = [HEADER.rstrip(), 'table inet ' + TABLE + ' {}', 'flush table inet ' + TABLE,
             'table inet ' + TABLE + ' {', ' chain input {', '  type filter hook input priority -10; policy accept;', '  iifname "lo" accept']
    for rule in config['Rules']:
        name = unit_name(rule, 'socket')
        files[unit_path(name)] = HEADER + '[Unit]\nDescription=May UDP forward socket\nBindsTo=' + ACL_UNIT + '\nAfter=' + ACL_UNIT + '\n\n[Socket]\n' + ''.join('ListenDatagram=' + (address if family == socket.AF_INET else '[' + address + ']') + ':' + str(port) + '\n' for family, address, port in listeners(rule)) + 'BindIPv6Only=ipv6-only\nReceiveBuffer=256K\n\n[Install]\nWantedBy=sockets.target\n'
        files[unit_path(unit_name(rule, 'service'))] = HEADER + '[Unit]\nDescription=May UDP forward worker\nBindsTo=' + name + '\nAfter=' + name + '\n\n[Service]\nType=simple\nExecStart=' + python + ' -I ' + WORKER + ' --target ' + rule['TargetAddress'] + ' --port ' + str(rule['TargetPort']) + ' --timeout ' + str(rule['SessionTimeoutSeconds']) + ' --maximum ' + str(rule['MaximumSessions']) + ' --allowed ' + ','.join(rule['AllowedSources']) + '\nDynamicUser=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_INET AF_INET6\nCapabilityBoundingSet=\nLimitNOFILE=2048\nRestart=on-failure\nRestartSec=2s\nTimeoutStopSec=10s\n'
        if rule['Enabled']:
            for version, family in ((4, 'ip'), (6, 'ip6')):
                sources = [s for s in rule['AllowedSources'] if ipaddress.ip_network(s).version == version]
                if sources:
                    lines.append('  udp dport ' + str(rule['ListenPort']) + ' ' + family + ' saddr { ' + ', '.join(sources) + ' } accept')
            lines.append('  udp dport ' + str(rule['ListenPort']) + ' drop')
    lines += [' }', '}']
    files[ACL] = '\n'.join(lines) + '\n'
    files[unit_path(ACL_UNIT)] = HEADER + '[Unit]\nDescription=May UDP forwarding source whitelist\nDefaultDependencies=no\nAfter=nftables.service\nBefore=sockets.target shutdown.target\nConflicts=shutdown.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f ' + ACL + '\nExecStop=/usr/sbin/nft delete table inet ' + TABLE + '\n\n[Install]\nWantedBy=multi-user.target\n'
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


class Host(ForwardHost):
    PREFIX, DIRECTORY = 'may-udp-forward', '/etc/may-udp-forward'
    JOURNAL = 'udp-forward-state.json'
    CONFIG, ACL, ACL_UNIT, TABLE = CONFIG, ACL, ACL_UNIT, TABLE
    EXTRA_FILES, SOCKET_TYPE = (WORKER,), socket.SOCK_DGRAM
    ARCHIVED_PROGRAMS = (WORKER,)
    normalize, material = staticmethod(normalize), staticmethod(material)
    unit_name, unit_path = staticmethod(unit_name), staticmethod(unit_path)
    canonical_table, listeners = staticmethod(canonical_table), staticmethod(listeners)

    def proxy(self):
        if not self.path('/usr/bin/python3').is_file():
            raise ValueError('Python 3 is required for UDP forwarding.')
        return '/usr/bin/python3'


def main():
    host, action = Host(archived_hash=os.environ.get('VPS_PARAM_UDP_FORWARD_EXPECTED_HASH') or os.environ.get('VPS_PARAM_EXPECTED_HASH') or os.environ.get('VPS_PARAM_ARCHIVED_HASH')), sys.argv[1]
    if action == 'read':
        value = host.read()
        if os.environ.get('VPS_PARAM_CANDIDATE_JSON'):
            host.preflight(normalize(json.loads(os.environ['VPS_PARAM_CANDIDATE_JSON'])))
        import base64
        print('VPSDEPLOY_UDP_FORWARD_STATE_B64=' + base64.b64encode(encoded(value).encode()).decode())
    elif action == 'snapshot':
        host.snapshot(Path(sys.argv[2]), os.environ['VPS_PARAM_UDP_FORWARD_EXPECTED_HASH'])
    elif action == 'verify':
        if host.read()['Hash'] != sys.argv[2]:
            raise ValueError('UDP forwarding resources differ from the reviewed hash.')
    elif action == 'paths':
        for path in host.read()['Files']:
            print(path.lstrip('/'))
    elif action == 'apply':
        op = os.environ['VPS_PARAM_ACTION']
        configuration = normalize(json.loads(os.environ['VPS_PARAM_CONFIG_JSON']))
        if op not in ('Apply', 'Remove') or op == 'Remove' and configuration['Rules'] or op == 'Apply' and not configuration['Rules']:
            raise ValueError('Invalid UDP forwarding operation.')
        host.apply(configuration, os.environ['VPS_PARAM_EXPECTED_HASH'], op, Path(os.environ['VPS_PARAM_EXPECTED_TRANSACTION']))
    elif action in ('rollback-check', 'rollback-prepare', 'rollback-complete'):
        getattr(host, action.replace('-', '_'))(Path(sys.argv[2]))
    else:
        raise ValueError('Unknown UDP forwarding command.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('UDP forwarding check failed; resources were not adopted or overwritten. Inspect ownership, UDP ports and recovery status.', file=sys.stderr)
        sys.exit(1)
