"""Application UDP scope, strict datagrams and loopback-only relay behavior."""
import base64
import copy
import importlib.util
import ipaddress
import socket
import threading
from pathlib import Path
import unittest

import test_inbound_policy as policy

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('application_udp', ROOT/'scripts/application-udp-probe.py')
U = importlib.util.module_from_spec(spec); spec.loader.exec_module(U)


def response(query):
    answer = bytearray(query); answer[2:4] = b'\x81\x80'; answer[6:8] = b'\0\1'
    data = ipaddress.ip_address('192.0.2.34' if query[-4:-2] == b'\0\1' else '2001:db8::34').packed
    return bytes(answer) + b'\xc0\x0c' + query[-4:] + b'\0\0\0\x01' + len(data).to_bytes(2, 'big') + data


class Relay:
    def __init__(self, fault=''):
        self.fault = fault; self.error = None; self.datagrams = 0; self.stop = threading.Event()
        self.tcp = socket.socket(); self.tcp.bind(('127.0.0.1', 0)); self.tcp.listen(1); self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(type=socket.SOCK_DGRAM); self.udp.bind(('127.0.0.1', 0)); self.udp.settimeout(0.1)
        self.thread = threading.Thread(target=self.run, daemon=True); self.thread.start()

    def run(self):
        try:
            with self.tcp.accept()[0] as control:
                control.settimeout(3)
                if U.application_udp_exact(control, 3) != b'\5\1\0': raise AssertionError('negotiation')
                control.sendall(b'\5\0'); U.application_udp_exact(control, 10)
                address = b'\xc0\0\2\1' if self.fault == 'outside' else b'\x7f\0\0\1'
                control.sendall(b'\5\0\0\1' + address + self.udp.getsockname()[1].to_bytes(2, 'big'))
                while not self.stop.is_set():
                    try: packet, endpoint = self.udp.recvfrom(8192)
                    except socket.timeout: continue
                    self.datagrams += 1; offset = 10 if packet[3] == 1 else 22
                    if self.fault == 'drop': continue
                    query = packet[offset:]; answer = response(query)
                    # A forged identity before the real reply must not qualify.
                    forged = bytearray(answer); forged[0] ^= 1
                    self.udp.sendto(packet[:offset] + forged, endpoint)
                    self.udp.sendto(packet[:offset] + answer, endpoint)
        except (OSError, ValueError) as error:
            if not self.stop.is_set(): self.error = error

    def __enter__(self): return self
    def __exit__(self, *_):
        self.stop.set(); self.tcp.close(); self.udp.close(); self.thread.join(4)
        if self.thread.is_alive(): raise AssertionError('Owned relay thread remained alive')
        if self.error: raise self.error


class ApplicationUdp(unittest.TestCase):
    def test_real_loopback_datagrams_and_address_families(self):
        for family in ('IPv4', 'IPv6'):
            with self.subTest(family=family), Relay() as relay:
                proof = U.application_udp_probe(relay.port, family)
                self.assertEqual(proof['Scope'], 'NativeOutboundUdpDns')
                self.assertTrue(proof['ResponseMatched']); self.assertGreater(relay.datagrams, 0)
                self.assertEqual(proof['QueryType'], 'A' if family == 'IPv4' else 'AAAA')

    def test_tcp_negotiation_without_udp_is_not_success(self):
        with Relay('drop') as relay:
            with self.assertRaises(ValueError): U.application_udp_probe(relay.port, 'IPv4')
            self.assertEqual(relay.datagrams, 3)

    def test_unowned_relay_refused_before_any_datagram(self):
        with Relay('outside') as relay:
            with self.assertRaises(ValueError): U.application_udp_probe(relay.port, 'IPv4')
            self.assertEqual(relay.datagrams, 0)

    def test_dns_identity_question_and_complete_record_required(self):
        query = b'\x12\x34\x01\0\0\1\0\0\0\0\0\0\x07example\x03com\0\0\1\0\1'
        good = response(query); self.assertTrue(U.application_udp_dns_matches(query, good))
        for mutation in ('identity', 'question', 'truncated', 'tc', 'rcode', 'no-answer', 'class', 'wrong-type', 'pointer'):
            with self.subTest(mutation=mutation):
                bad = bytearray(good)
                if mutation == 'identity': bad[0] ^= 1
                elif mutation == 'question': bad[14] ^= 1
                elif mutation == 'truncated': del bad[-1:]
                elif mutation == 'tc': bad[2] |= 2
                elif mutation == 'rcode': bad[3] |= 3
                elif mutation == 'no-answer': bad[7] = 0
                elif mutation == 'class': bad[len(query)+5] = 2
                elif mutation == 'wrong-type': bad[len(query)+3] = 28
                else: bad[len(query)+1] = 255
                self.assertFalse(U.application_udp_dns_matches(query, bytes(bad)))

    def test_udp_and_both_native_policy_scope(self):
        for network in ('UDP', 'Both'):
            value, config = policy.policy_fixture(); value['Model']['Inbounds'][0]['Routing']['Rules'][0]['Network'] = network
            config['route']['rules'][0]['network'] = 'udp' if network == 'UDP' else ['tcp', 'udp']
            policy.encode(value, config); policy.M.normalize(value)
            paths = policy.namespace['policy_paths'](value['Model'], value['Model']['Inbounds'][0])
            self.assertTrue(all(p['UdpRequired'] for p in paths))
            altered = copy.deepcopy(value); rendered = copy.deepcopy(config); rendered['route']['rules'][0]['network'] = 'tcp'
            policy.encode(altered, rendered)
            with self.assertRaises(ValueError): policy.M.normalize(altered)

    def test_unknown_network_and_overlapping_duplicates_refused(self):
        for bad in ('quic', 'udp', False, None, ['UDP']):
            value, _ = policy.policy_fixture(); value['Model']['Inbounds'][0]['Routing']['Rules'][0]['Network'] = bad
            with self.subTest(network=bad), self.assertRaises(ValueError): policy.M.normalize(value)
        value, config = policy.policy_fixture(); rule = value['Model']['Inbounds'][0]['Routing']['Rules'][0]
        rule['Network'] = 'Both'; duplicate = copy.deepcopy(rule); duplicate['Network'] = 'UDP'; value['Model']['Inbounds'][0]['Routing']['Rules'].append(duplicate)
        with self.assertRaises(ValueError): policy.M.normalize(value)

    def test_protocol_change_requires_fresh_probe_identity(self):
        value, config = policy.policy_fixture(); item = value['Model']['Inbounds'][0]; item['Routing']['Rules'][0]['Network'] = 'UDP'; config['route']['rules'][0]['network'] = 'udp'; policy.encode(value, config)
        paths = policy.namespace['policy_paths'](value['Model'], item)
        self.assertTrue(paths[0]['UdpRequired']); self.assertTrue(paths[1]['UdpRequired'])
        without = copy.deepcopy(paths); without[0].pop('UdpRequired')
        # Request-shape equality in validate_request rejects the former TCP-only
        # path even when its outbound connection parameters did not change.
        host = policy.PolicyOwnership('test_probe_identity_and_drift'); host.setUp()
        try:
            host.apply(value, [policy.A, policy.B]); state = host.host.read()
            for path in without: path['OutboundFingerprint'] = 'f'*64
            request = {'InboundId':policy.A,'ConfigurationSha256':value['Bindings'][0]['Sha256'],'PolicyFingerprint':'a'*64,'Paths':without}
            with self.assertRaises(ValueError): policy.namespace['validate_request'](request, state)
        finally: host.doCleanups()


if __name__ == '__main__': unittest.main()
