#!/usr/bin/env bash
set -euo pipefail
action="${VPS_PARAM_ACTION:-Observe}"
[[ "$action" == Observe || "$action" == Outbound ]] || exit 1
python3 - <<'PY'
import base64, ipaddress, json, os, re, subprocess, time
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
peer = os.environ.get('SSH_CONNECTION', '').split(' ')[0]
rtts = []
if re.fullmatch(r'[0-9]{1,5}', port):
    output = command(['ss', '-Htin', 'state', 'established', '( sport = :'+port+' )'])
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if 'rtt:' not in line:
            continue
        header = lines[index-1] if index else ''
        # SSH and the proxy may take different routes. Do not substitute other users' RTTs.
        fields = header.split()
        try:
            remote = fields[-1].rsplit(':', 1)[0].strip('[]')
            address = ipaddress.ip_address(remote)
            address = address.ipv4_mapped or address if address.version == 6 else address
            matches = bool(peer) and address == ipaddress.ip_address(peer)
        except (ValueError, IndexError):
            matches = False
        if matches:
            m = re.search(r'\brtt:([0-9.]+)/', line)
            if m:
                rtts.append(float(m.group(1)))
result = {'Kernel': command(['uname', '-r']), 'BootId': read('/proc/sys/kernel/random/boot_id').strip(), 'MemoryKiB': int(memory.group(1)) if memory else 0,
          'Cpu': {'BusyPercent': round(100*(total-(b[3]-a[3])-(b[4]-a[4]))/total, 2),
                  'StealPercent': round(100*(b[7]-a[7])/total, 2)},
          'Sysctl': sysctls, 'BbrVersion': bbr, 'BbrVersionEvidence': 'LoadedModule' if version else 'Unavailable',
          'Devices': devices, 'Tcp': {'RttMs': rtts, 'Scope': 'SelectedInboundAndSshPeer'},
          'Counters': {'TcpRetransSegs': tcp.get('RetransSegs', 0), 'TcpOutSegs': tcp.get('OutSegs', 0)},
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
encoded = base64.b64encode(json.dumps(result, separators=(',', ':')).encode()).decode()
print('VPSDEPLOY_NETWORK_AUDIT_B64='+encoded)
PY
