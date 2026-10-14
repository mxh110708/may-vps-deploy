"""Exercise the actual read-only socket audit with isolated proc/command fixtures."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CODE = (ROOT / 'assets/remote/network-audit.sh').read_text(encoding='utf-8-sig').split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]


class NetworkAuditTests(unittest.TestCase):
    def audit(self, lines='', peer='198.51.100.10', upstream='', snmp=True, action='Observe', family='', probe_peer=''):
        files = {'/proc/stat': 'cpu 100 0 100 800 0 0 0 0\n', '/proc/meminfo': 'MemTotal: 1048576 kB\n',
                 '/proc/sys/kernel/random/boot_id': 'test-boot', '/proc/net/softnet_stat': '0000 0001\n',
                 '/proc/net/snmp': 'Tcp: OutSegs RetransSegs\nTcp: 1000 10\n' if snmp else '',
                 '/proc/sys/net/ipv4/ip_forward': '1', '/proc/sys/net/ipv6/conf/all/forwarding': '0'}
        calls = []
        class ReadPath:
            def __init__(self, value): self.value = str(value)
            def read_text(self):
                if self.value not in files: raise FileNotFoundError(self.value)
                return files[self.value]
        def run(args, **kwargs):
            self.assertLessEqual(kwargs['timeout'], 20)
            calls.append(args)
            out = ''
            if args[0] == 'ip' or args[0] == 'tc': out = '[]'
            elif args[0] == 'ss': out = lines
            elif args[0] == 'getent': out = '203.0.113.30 STREAM speed.cloudflare.com\n203.0.113.31 STREAM fsn1-speed.hetzner.com'
            elif args[0] == 'sysctl': out = '1'
            elif args[0] == 'uname': out = 'test-kernel'
            elif args[0] == 'curl': out = '1048576 1 1048576' if 'size_download' in args[-2] else '.05'
            return subprocess.CompletedProcess(args, 0, out, '')
        env = {'VPS_PARAM_ACTION': action, 'VPS_PARAM_TCP_PORT': '4000', 'SSH_CONNECTION': peer + ' 50000 192.0.2.10 22',
               'VPS_PARAM_TCP_FAMILY': family, 'VPS_PARAM_TCP_PEER_ADDRESS': probe_peer,
               'VPS_PARAM_UPSTREAM_ADDRESS': upstream, 'VPS_PARAM_UPSTREAM_PORT': '5000' if upstream else '', 'VPS_PARAM_BYTES': '1048576'}
        output = io.StringIO()
        with patch('pathlib.Path', ReadPath), patch('subprocess.run', side_effect=run), patch('time.sleep'), patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(output):
            exec(compile(CODE, 'network-audit-fixture', 'exec'), {})
        encoded = next(row.split('=', 1)[1] for row in output.getvalue().splitlines() if row.startswith('VPSDEPLOY_NETWORK_AUDIT_B64='))
        return json.loads(base64.b64decode(encoded)), calls

    @staticmethod
    def socket(remote='198.51.100.10:50000', local='192.0.2.10:4000', cookie='123', counters='data_segs_out:2000 retrans:0/3'):
        return f'0 0 {local} {remote} ino:321 sk:{cookie} cubic rtt:82.5/4.0 {counters} busy:1500ms sndbuf_limited:200ms(15.0%)'

    def test_only_selected_inbound_peer_and_port_count(self):
        audit, calls = self.audit('\n'.join((self.socket(), self.socket(remote='198.51.100.11:50000'), self.socket(local='192.0.2.10:22'))))
        self.assertEqual(len(audit['Tcp']['Sockets']), 1)
        sample = audit['Tcp']['Sockets'][0]
        self.assertEqual((sample['Leg'], sample['DataSegmentsOut'], sample['TotalRetrans']), ('ToUser', 2000, 3))
        self.assertEqual(sample['SendBufferLimitedMs'], 200)
        self.assertEqual(len(sample['Identity']), 64)
        self.assertNotIn('198.51.100.10', json.dumps(sample))
        self.assertEqual(audit['Forwarding']['IPv4'], '1')
        self.assertFalse(any(args[0] in ('systemctl', 'modprobe') for args in calls))

    def test_relay_matches_exact_next_hop_and_not_public_egress(self):
        audit, _ = self.audit('\n'.join((self.socket(remote='203.0.113.20:5000', local='192.0.2.10:55000'), self.socket(remote='203.0.113.30:443', local='192.0.2.10:55001'))), upstream='203.0.113.20')
        self.assertEqual([s['Leg'] for s in audit['Tcp']['Sockets']], ['ToNextHop'])

    def test_ipv6_and_mapped_peers(self):
        audit, _ = self.audit(self.socket(remote='[2001:db8::a]:50000', local='[2001:db8::b]:4000'), peer='2001:db8::a')
        self.assertEqual(len(audit['Tcp']['Sockets']), 1)
        audit, _ = self.audit(self.socket(remote='[::ffff:198.51.100.10]:50000'))
        self.assertEqual(len(audit['Tcp']['Sockets']), 1)

    def test_cookie_required_and_zero_retrans_elision(self):
        audit, _ = self.audit(self.socket(counters='data_segs_out:2000'))
        self.assertEqual(audit['Tcp']['Sockets'][0]['TotalRetrans'], 0)
        audit, _ = self.audit(self.socket().replace('sk:123', ''))
        self.assertEqual(audit['Tcp']['Sockets'], [])

    def test_ipv6_probe_uses_observed_peer_not_ipv4_ssh(self):
        lines = '\n'.join((self.socket(), self.socket(remote='[2001:db8::a]:50000', local='[2001:db8::b]:4000')))
        audit, _ = self.audit(lines, family='IPv6')
        self.assertEqual(audit['Tcp']['Sockets'], [])
        audit, _ = self.audit(lines, family='IPv6', probe_peer='2001:db8::a')
        self.assertEqual(len(audit['Tcp']['Sockets']), 1)
        self.assertEqual(audit['Tcp']['Sockets'][0]['Leg'], 'ToUser')

    def test_missing_global_counters_remain_missing(self):
        audit, _ = self.audit(snmp=False)
        self.assertIsNone(audit['Counters']['TcpRetransSegs'])
        self.assertIsNone(audit['Counters']['TcpOutSegs'])

    def test_outbound_diagnostic_is_bounded_and_multi_target(self):
        audit, calls = self.audit(action='Outbound')
        self.assertEqual(len(audit['OutboundStability']['Targets']), 2)
        self.assertTrue(all(len(t['Attempts']) == 3 for t in audit['OutboundStability']['Targets']))
        curl = [args for args in calls if args[0] == 'curl']
        self.assertEqual(len(curl), 7)
        self.assertTrue(all('--noproxy' in args and '--max-filesize' in args and '--max-time' in args for args in curl))
        self.assertTrue(all(args[-1].startswith(('https://speed.cloudflare.com/', 'https://fsn1-speed.hetzner.com/')) for args in curl))


if __name__ == '__main__': unittest.main()
