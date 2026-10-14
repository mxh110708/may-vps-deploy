#!/usr/bin/env bash
set -euo pipefail
action="${VPS_PARAM_ACTION:-Observe}"
[[ "$action" == Observe || "$action" == Outbound ]] || exit 1
python3 - <<'PY'
import base64, hashlib, ipaddress, json, os, re, subprocess, time
from pathlib import Path

def command(args, seconds=8):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=seconds, check=False)
        return p.stdout.strip() if p.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''

def read(path):
    try:
        return Path(path).read_text()
    except OSError:
        return ''

def cpu():
    line = read('/proc/stat').splitlines()[0].split()[1:]
    return [int(x) for x in line[:8]]

a = cpu(); time.sleep(.5); b = cpu(); total = max(1, sum(b)-sum(a))
memory = re.search(r'^MemTotal:\s+(\d+)', read('/proc/meminfo'), re.M)
devices = []
for family in ('-4', '-6'):
    try:
        routes = json.loads(command(['ip', '-j', family, 'route', 'show', 'default']) or '[]')
    except ValueError:
        routes = []
    for route in routes:
        device = route.get('dev', '')
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', device) or any(x['Name'] == device for x in devices):
            continue
        try:
            queues = json.loads(command(['tc', '-j', 'qdisc', 'show', 'dev', device]) or '[]')
        except ValueError:
            queues = []
        stats = {key: int(read('/sys/class/net/'+device+'/statistics/'+key).strip() or '0')
                 for key in ('rx_bytes', 'tx_bytes', 'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors')}
        devices.append({'Name': device, 'Mtu': read('/sys/class/net/'+device+'/mtu').strip(),
                        'Queues': queues, 'Counters': stats})
sysctls = {}
for key in ('net.core.default_qdisc', 'net.ipv4.tcp_congestion_control', 'net.ipv4.tcp_available_congestion_control',
            'net.ipv4.tcp_rmem', 'net.ipv4.tcp_wmem', 'net.core.rmem_max', 'net.core.wmem_max', 'net.ipv4.tcp_moderate_rcvbuf'):
    sysctls[key] = command(['sysctl', '-n', key])
version = read('/sys/module/tcp_bbr/version').strip()
# The loaded module is authoritative. A module on disk may belong to a different running build.
bbr = 'v3' if version == '3' else 'v1' if version == '1' else 'VersionUnverified'
runtime_bbr = {'BbrVersion': bbr, 'BbrVersionEvidence': 'LoadedModule' if version else 'Unavailable'}
if os.environ.get('VPS_BBR_PROGRAM'):
    exec(os.environ['VPS_BBR_PROGRAM'])
    runtime_bbr = bbr_runtime()
tcp = {}
snmp = read('/proc/net/snmp').splitlines()
for index in range(len(snmp)-1):
    if snmp[index].startswith('Tcp:') and snmp[index+1].startswith('Tcp:'):
        tcp = dict(zip(snmp[index].split()[1:], map(int, snmp[index+1].split()[1:])))
port = os.environ.get('VPS_PARAM_TCP_PORT', '')
peer = os.environ.get('VPS_PARAM_TCP_PEER_ADDRESS') or os.environ.get('SSH_CONNECTION', '').split(' ')[0]
family = os.environ.get('VPS_PARAM_TCP_FAMILY', '')
rtts = []
sockets = []
upstream = os.environ.get('VPS_PARAM_UPSTREAM_ADDRESS', '')
upstream_port = os.environ.get('VPS_PARAM_UPSTREAM_PORT', '')
if upstream:
    try:
        upstream = str(ipaddress.ip_address(upstream))
        if not re.fullmatch(r'[0-9]{1,5}', upstream_port) or not 1 <= int(upstream_port) <= 65535:
            raise ValueError()
    except ValueError:
        raise SystemExit('Invalid upstream socket selector.')

def endpoint(value):
    host, number = value.rsplit(':', 1)
    address = ipaddress.ip_address(host.strip('[]'))
    if address.version == 6:
        address = address.ipv4_mapped or address
    return str(address), int(number)

targets = set()
if not upstream:
    for host in ('speed.cloudflare.com', 'fsn1-speed.hetzner.com'):
        for row in command(['getent', 'ahosts', host], 3).splitlines():
            try:
                targets.add(str(ipaddress.ip_address(row.split()[0])))
            except (ValueError, IndexError):
                pass
if re.fullmatch(r'[0-9]{1,5}', port):
    # Extended socket cookies distinguish a reused tuple from the old connection.
    # -O keeps each socket on one line on iproute2 in supported Debian releases.
    output = command(['ss', '-HtinOe', 'state', 'established', '( sport = :'+port+' or dport = :'+(upstream_port or '443')+' )'])
    for line in output.splitlines()[:2048]:
        fields = line.split()
        try:
            # ss with a state filter omits the state column; accept both layouts.
            offset = 1 if fields[0] == 'ESTAB' else 0
            local_ip, local_port = endpoint(fields[offset+2])
            remote_ip, remote_port = endpoint(fields[offset+3])
            inbound = local_port == int(port) and bool(peer) and remote_ip == str(ipaddress.ip_address(peer)) and (not family or ipaddress.ip_address(remote_ip).version == (6 if family == 'IPv6' else 4))
            outbound = remote_ip == upstream and remote_port == int(upstream_port) if upstream else remote_port == 443 and remote_ip in targets
            if not inbound and not outbound:
                continue
            cookie = re.search(r'\bsk:([0-9a-fA-F]+)\b', line)
            inode = re.search(r'\bino:(\d+)\b', line)
            if not cookie or not inode:
                continue
            sample = {'Identity': hashlib.sha256((fields[offset+2]+'|'+fields[offset+3]+'|'+cookie.group(1)+'|'+inode.group(1)).encode()).hexdigest(),
                      'Leg': 'ToUser' if inbound else 'ToNextHop'}
            for name, pattern in (('RttMs', r'\brtt:([0-9.]+)/'), ('DataSegmentsOut', r'\bdata_segs_out:(\d+)\b'),
                                  ('BytesSent', r'\bbytes_sent:(\d+)\b'),
                                  ('TotalRetrans', r'\bretrans:\d+/(\d+)\b'), ('BusyMs', r'\bbusy:([0-9.]+)ms\b'),
                                  ('SendBufferLimitedMs', r'\bsndbuf_limited:([0-9.]+)ms\b')):
                match = re.search(pattern, line)
                if match:
                    sample[name] = float(match.group(1)) if name in ('RttMs', 'BusyMs', 'SendBufferLimitedMs') else int(match.group(1))
            # ss elides retrans:0/0. Only accept that elision when data counters exist.
            if 'DataSegmentsOut' in sample and not re.search(r'\bretrans:', line):
                sample['TotalRetrans'] = 0
            if 'BusyMs' in sample and not re.search(r'\bsndbuf_limited:', line):
                sample['SendBufferLimitedMs'] = 0
            sockets.append(sample)
            if inbound and 'RttMs' in sample:
                rtts.append(sample['RttMs'])
        except (ValueError, IndexError):
            continue
result = {'Kernel': command(['uname', '-r']), 'BootId': read('/proc/sys/kernel/random/boot_id').strip(), 'MemoryKiB': int(memory.group(1)) if memory else 0,
          'Cpu': {'BusyPercent': round(100*(total-(b[3]-a[3])-(b[4]-a[4]))/total, 2),
                  'StealPercent': round(100*(b[7]-a[7])/total, 2)},
          'Sysctl': sysctls, 'BbrVersion': bbr, 'BbrVersionEvidence': 'LoadedModule' if version else 'Unavailable',
          'Devices': devices, 'Tcp': {'RttMs': rtts[:64], 'Scope': 'SelectedPortAndPeerOrNextHop', 'Sockets': sockets[:64], 'Truncated': len(sockets) > 64},
          'Forwarding': {'IPv4': read('/proc/sys/net/ipv4/ip_forward').strip(), 'IPv6': read('/proc/sys/net/ipv6/conf/all/forwarding').strip()},
          'Counters': {'TcpRetransSegs': tcp.get('RetransSegs'), 'TcpOutSegs': tcp.get('OutSegs')},
          'SoftnetDropped': sum(int(line.split()[1], 16) for line in read('/proc/net/softnet_stat').splitlines() if len(line.split()) > 1)}
result.update(runtime_bbr)
if os.environ.get('VPS_PARAM_ACTION') == 'Outbound':
    amount = int(os.environ.get('VPS_PARAM_BYTES', '1048576'))
    if not 65536 <= amount <= 8388608:
        raise SystemExit('Invalid outbound payload budget.')
    # A fixed official endpoint, no arbitrary URL, executable download or system proxy changes.
    output = command(['curl', '-4', '--noproxy', '*', '--fail', '--silent', '--show-error',
                      '--connect-timeout', '5', '--max-time', '15', '--max-filesize', str(amount),
                      '-H', 'Accept-Encoding: identity', '-o', '/dev/null', '-w', '%{size_download} %{time_total} %{speed_download}',
                      'https://speed.cloudflare.com/__down?bytes='+str(amount)], 20)
    values = output.split()
    complete = len(values) == 3 and int(float(values[0])) == amount
    result['Outbound'] = {'Status': 'Complete' if complete else 'Unavailable', 'PayloadBytes': amount,
                          'Mbps': float(values[2])*8/1000000 if complete else 0,
                          'Seconds': float(values[1]) if complete else 0,
                          'Path': 'VpsToCloudflareIPv4'}
    # Independent, bounded HTTPS startup checks diagnose the website-facing side.
    # They do not establish a local NIC bottleneck and never choose a shaping rate.
    targets = []
    for name, url in (('Cloudflare', 'https://speed.cloudflare.com/__down?bytes=1024'),
                      ('Hetzner', 'https://fsn1-speed.hetzner.com/100MB.bin')):
        attempts = []
        for _ in range(3):
            output = command(['curl', '-4', '--noproxy', '*', '--fail', '--silent', '--show-error', '--range', '0-1023',
                              '--connect-timeout', '2', '--max-time', '3', '--max-filesize', '1024', '-o', '/dev/null',
                              '-w', '%{time_starttransfer}', url], 4)
            try:
                seconds = float(output)
                attempts.append({'Complete': seconds > 0, 'Milliseconds': seconds*1000})
            except ValueError:
                attempts.append({'Complete': False})
        targets.append({'Endpoint': name, 'Attempts': attempts})
    result['OutboundStability'] = {'Scope': 'VpsOriginatedHttpsIPv4', 'Targets': targets}
encoded = base64.b64encode(json.dumps(result, separators=(',', ':')).encode()).decode()
print('VPSDEPLOY_NETWORK_AUDIT_B64='+encoded)
PY
