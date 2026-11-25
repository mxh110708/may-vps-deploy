"""Round 41 allocation, identity, real loopback sessions and scoped recovery."""
import copy
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import test_forward_target_groups as fixture
import test_forward_proxy_health as proxy_fixture

G, TCP, UDP = fixture.GROUP, fixture.TCP, fixture.UDP


def rule(strategy='RoundRobin', kind='Ssh', count=3):
    value = fixture.rule(kind)
    group = value['TargetGroup']
    for key in ('BackupAddress', 'BackupPort', 'AutoReturn'): group.pop(key)
    group.update(Version=2, Strategy=strategy, AdditionalTargets=[dict(Id=format(i + 1, '032x'), Address='192.0.2.' + str(21 + i), Port=443) for i in range(count - 1)])
    group['IntervalSeconds'] = max(5, count)
    return value


def proxy_rule(udp=False, count=3):
    value = rule(kind='Echo' if udp else 'Ssh', count=count)
    value['Validation'] = proxy_fixture.rule(udp)['Validation']
    value['TargetGroup']['Health'] = dict(Type='Proxy', Consent=True, EgressFamily='IPv4', ExpectedExits={identity: '' for identity in G.group_target_ids(value)})
    return value


class MultiTargets(unittest.TestCase):
    def test_versions_transports_and_all_eight_endpoints(self):
        for count in (2, 3, 8):
            for kind in ('Tls', 'Ssh', 'Dns', 'Echo'):
                value = rule(kind=kind, count=count); driver = UDP if kind in ('Dns', 'Echo') else TCP
                self.assertEqual(driver.normalize(dict(Version=1, Rules=[value]))['Rules'][0], value)
                self.assertEqual(len(G.group_targets(value)), count)
        self.assertEqual(G.normalize_group(fixture.rule())['Version'], 1)

    def test_unknown_fields_weights_duplicates_and_unbounded_work_refused(self):
        edits = [lambda g: g.update(Version=True), lambda g: g.update(Strategy='Weighted'), lambda g: g.update(Weight=2),
                 lambda g: g.update(AdditionalTargets=[]), lambda g: g.update(IntervalSeconds=5, TimeoutSeconds=2),
                 lambda g: g['AdditionalTargets'][0].update(Id='not-an-id'), lambda g: g['AdditionalTargets'][0].update(Port=True),
                 lambda g: g['AdditionalTargets'][0].update(Address='::ffff:192.0.2.21'), lambda g: g['AdditionalTargets'][0].update(Address='0.0.0.0'),
                 lambda g: g['AdditionalTargets'][0].update(Address='target.example.test'), lambda g: g['AdditionalTargets'][1].update(Id=g['AdditionalTargets'][0]['Id']),
                 lambda g: g['AdditionalTargets'][1].update(Address=g['AdditionalTargets'][0]['Address'])]
        for edit in edits:
            value = rule(); edit(value['TargetGroup'])
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)): TCP.normalize(dict(Version=1, Rules=[value]))
        for count in (1, 9):
            with self.assertRaises(ValueError): G.normalize_group(rule(count=count))
        value = rule(); value['TargetGroup']['AdditionalTargets'][0]['Id'] = value['Id']
        with self.assertRaises(ValueError): G.normalize_group(value)
        value = rule(); value['TargetGroup']['AdditionalTargets'][0].update(Address=value['TargetAddress'], Port=value['TargetPort'])
        with self.assertRaises(ValueError): G.normalize_group(value)

    def test_round_robin_only_advances_on_allocation_and_skips_confirmed_failures(self):
        value = rule(); clock = fixture.Clock(); policy = G.MultiTargetPolicy(value, clock)
        self.assertIsNone(policy.choose(('192.0.2.80', 80)))
        policy.observe([True, True, True]); self.assertEqual([policy.choose(None) for _ in range(7)], [0, 1, 2, 0, 1, 2, 0])
        policy.observe([True, False, True]); self.assertTrue(policy.healthy[1])
        policy.observe([True, False, True]); self.assertFalse(policy.healthy[1])
        self.assertEqual([policy.choose(None) for _ in range(4)], [2, 0, 2, 0])
        policy.observe([True, True, True]); clock.advance(5); policy.observe([True, True, True]); self.assertFalse(policy.healthy[1])
        clock.advance(5); policy.observe([True, True, True]); self.assertTrue(policy.healthy[1])
        policy.observe([False] * 3); policy.observe([False] * 3); self.assertIsNone(policy.choose(None))

    def test_recovery_hold_resets_on_interrupted_success_and_never_uses_wall_time(self):
        clock = fixture.Clock(); policy = G.MultiTargetPolicy(rule(), clock); policy.observe([True, False, True])
        policy.observe([True, True, True]); clock.advance(9); policy.observe([True, False, True]); clock.advance(500)
        policy.observe([True, True, True]); policy.observe([True, True, True]); self.assertFalse(policy.healthy[1])
        clock.advance(10); policy.observe([True, True, True]); self.assertTrue(policy.healthy[1])

    def test_hash_stable_across_ports_restart_reorder_and_unrelated_failure(self):
        value = rule('SourceIpHash'); policy = G.MultiTargetPolicy(value); policy.observe([True] * 3)
        other = copy.deepcopy(value); other['TargetGroup']['AdditionalTargets'].reverse()
        reordered = G.MultiTargetPolicy(other); reordered.observe([True] * 3)
        restarted = G.MultiTargetPolicy(value); restarted.observe([True] * 3)
        choices = {}
        for i in range(1, 255):
            source = ('192.0.2.' + str(i), 10000 + i); selected = policy.choose(source); choices[source] = selected
            self.assertEqual(selected, policy.choose((source[0], 65535)))
            self.assertEqual(selected, restarted.choose(source))
            self.assertEqual(policy.ids[selected], reordered.ids[reordered.choose(source)])
            self.assertEqual(selected, policy.choose(('::ffff:' + source[0], 12)))
        self.assertEqual(set(choices.values()), {0, 1, 2})
        policy.observe([True, False, True]); policy.observe([True, False, True])
        for source, selected in choices.items():
            if selected != 1: self.assertEqual(selected, policy.choose(source))
            else: self.assertNotEqual(1, policy.choose(source))
        # IPv6 textual spelling and source ports do not create distinct identities.
        self.assertEqual(policy.choose(('2001:db8::1', 1)), policy.choose(('2001:0db8:0:0:0:0:0:1', 40000)))

    def test_proxy_expectations_are_bound_to_fixed_target_identities(self):
        for udp in (False, True):
            value = proxy_rule(udp); transport = 'UDP' if udp else 'TCP'
            self.assertEqual(G.normalize_group(value, transport), value['TargetGroup'])
            identity = G.group_target_ids(value)[2]; value['TargetGroup']['Health']['ExpectedExits'][identity] = '192.0.2.82'
            self.assertEqual(G.expected_proxy_exit(value, 2), '192.0.2.82')
            value['TargetGroup']['AdditionalTargets'].reverse(); self.assertEqual(G.expected_proxy_exit(value, 1), '192.0.2.82')
            for edit in [lambda h: h.update(Consent=False), lambda h: h['ExpectedExits'].pop(identity), lambda h: h['ExpectedExits'].update(unowned=''), lambda h: h['ExpectedExits'].update({identity: '::1'})]:
                bad = copy.deepcopy(value); edit(bad['TargetGroup']['Health'])
                with self.assertRaises(ValueError): G.normalize_group(bad, transport)

    def test_monitor_stale_or_all_failed_is_closed_and_proof_has_all_identities(self):
        value = rule(); outcomes = [True] * 3
        with tempfile.TemporaryDirectory() as directory:
            monitor = G.TargetMonitor(value, status=Path(directory) / 'status.json', probe=lambda endpoint: outcomes[G.group_targets(value).index(endpoint)])
            monitor.round(); self.assertEqual([monitor.selected() for _ in range(3)], G.group_targets(value))
            self.assertTrue(G.group_status(value, monitor.status)['Fresh'])
            snapshot = json.loads(monitor.status.read_text()); self.assertEqual(snapshot['TargetIds'], G.group_target_ids(value)); self.assertNotIn('Selected', snapshot)
            changed = copy.deepcopy(value); changed['TargetGroup']['Strategy'] = 'SourceIpHash'
            self.assertFalse(G.group_status(changed, monitor.status)['Fresh'])
            monitor.sampled = time.monotonic() - 1000; self.assertIsNone(monitor.selected()); self.assertFalse(monitor.healthy(monitor.targets[0]))
            outcomes[:] = [False] * 3; monitor.round(); monitor.round(); self.assertIsNone(monitor.selected())

    def test_probe_proof_and_address_rewrite_keep_endpoint_identities(self):
        value = rule(); configuration = dict(Version=1, Rules=[value])
        class Host:
            def read(self): return dict(Hash='a' * 64, Configuration=configuration)
        with patch.object(G, 'health_probe', return_value=True): result = G.probe_groups(Host())
        proof = result['Groups'][0]
        self.assertEqual([t['TargetId'] for t in proof['Targets']], G.group_target_ids(value))
        self.assertEqual([(t['Address'], t['Port']) for t in proof['Targets']], G.group_targets(value))
        import test_instance_address
        value = proxy_rule(); identity = G.group_target_ids(value)[2]
        value['TargetGroup']['Health']['ExpectedExits'][identity] = '198.51.100.82'
        changed = test_instance_address.address.rewrite(value, {'192.0.2.22': '192.0.2.23', '198.51.100.82': '198.51.100.83'})
        self.assertEqual(G.group_target_ids(changed), G.group_target_ids(value))
        self.assertEqual(G.group_targets(changed)[2][0], '192.0.2.23')
        self.assertEqual(G.expected_proxy_exit(changed, 2), '198.51.100.83')

    def test_real_three_target_tcp_allocation_and_existing_connection_pin(self):
        targets = [fixture.Target(banner=('SSH-2.0-Target' + str(i) + '\r\n').encode()) for i in range(3)]
        for target in targets: self.addCleanup(target.close)
        value = rule(); value['TargetAddress'], value['TargetPort'] = targets[0].endpoint
        for entry, target in zip(value['TargetGroup']['AdditionalTargets'], targets[1:]): entry.update(Address=target.endpoint[0], Port=target.endpoint[1])
        monitor = G.TargetMonitor(value); monitor.round()
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); endpoint = listener.getsockname()
        stop = threading.Event(); thread = threading.Thread(target=fixture.WORKER.run, args=([listener], *targets[0].endpoint, None), kwargs=dict(stop=stop, source_selector=monitor.selected), daemon=True); thread.start()
        clients = []
        def connect():
            client = socket.create_connection(endpoint, timeout=2); client.settimeout(2); clients.append(client); banner = bytearray()
            while not banner.endswith(b'\n'): banner.extend(client.recv(1))
            return client, bytes(banner)
        try:
            old, banner = connect(); self.assertIn(b'Target0', banner)
            for i in (1, 2, 0, 1, 2): client, banner = connect(); self.assertIn(('Target' + str(i)).encode(), banner); client.close()
            targets[0].enabled = False; monitor.round(); monitor.round()
            for _ in range(4): client, banner = connect(); self.assertNotIn(b'Target0', banner); client.close()
            old.sendall(b'pinned-stream'); self.assertEqual(old.recv(64), b'pinned-stream')
            for target in targets: target.enabled = False
            monitor.round(); monitor.round()
            client = socket.create_connection(endpoint, timeout=2); clients.append(client); client.settimeout(2)
            try: self.assertEqual(client.recv(1), b'')
            except ConnectionResetError: pass
        finally:
            for client in clients: client.close()
            stop.set(); thread.join(3); listener.close(); self.assertFalse(thread.is_alive())

    def test_all_endpoints_use_existing_scope_snapshot_and_loop_checks(self):
        owned = fixture.owned_fixture.ForwardingOwnership(methodName='runTest'); owned.setUp()
        try:
            original = owned.apply(); owned.snapshot(); value = copy.deepcopy(original['Configuration']); value['Rules'][0]['TargetGroup'] = rule(kind='Tls')['TargetGroup']
            applied = owned.host.apply(TCP.normalize(value), original['Hash'], 'Apply', fixture.module_backup())
            self.assertIn(TCP.GROUP_WORKER, applied['Files']); owned.restore(); self.assertEqual(owned.host.read()['Hash'], original['Hash']); self.assertFalse(owned.host.path(TCP.GROUP_WORKER).exists())
            value = rule(kind='Tls'); value['TargetGroup']['AdditionalTargets'][1].update(Address='127.0.0.1', Port=value['ListenPort'])
            with self.assertRaises(ValueError): owned.host.preflight(TCP.normalize(dict(Version=1, Rules=[value])))
        finally: owned.doCleanups()


if __name__ == '__main__': unittest.main()
