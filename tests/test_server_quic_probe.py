"""Finite next-hop probe boundaries; no network or child process is started."""
import copy
from pathlib import Path
import unittest
import uuid

source = (Path(__file__).resolve().parents[1] / 'assets/remote/server-hop-probe.sh').read_text(encoding='utf-8')
source = source.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
namespace = {'__name__': 'probe_boundary_fixture'}
exec(compile(source, 'server-hop-probe', 'exec'), namespace)


class ServerQuicProbeTests(unittest.TestCase):
    def node(self, protocol):
        value = {'tag': 'may-hop-' + 'a' * 16, 'type': protocol, 'server': '192.0.2.20', 'server_port': 24000,
                 'password': 'synthetic-probe-password', 'tls': {'enabled': True, 'server_name': 'next.example.test'}}
        if protocol == 'tuic':
            value.update(uuid=str(uuid.uuid4()), congestion_control='cubic', udp_relay_mode='native', heartbeat='10s', zero_rtt_handshake=False)
        return value

    def check(self, node, role='AnyTlsEntry'):
        namespace['validate']([{'Id': 'a' * 16, 'ExpectedAddress': '198.51.100.22', 'Outbound': node}], role)

    def test_both_quic_protocols_keep_a_finite_supported_scope(self):
        for protocol in ('hysteria2', 'tuic'):
            self.check(self.node(protocol))

    def test_remote_file_detour_network_and_extra_options_are_rejected(self):
        for protocol in ('hysteria2', 'tuic'):
            for key in ('detour', 'network', 'bind_interface', 'certificate_path', 'token'):
                node = self.node(protocol); node[key] = 'unsupported'
                with self.subTest(protocol=protocol, key=key), self.assertRaises(ValueError):
                    self.check(node)

    def test_tls_cannot_read_server_files_or_skip_verification(self):
        for protocol in ('hysteria2', 'tuic'):
            for key, value in (('insecure', True), ('enabled', False), ('certificate_path', '/etc/unrelated'), ('ech', {})):
                node = self.node(protocol); node['tls'][key] = value
                with self.subTest(protocol=protocol, key=key), self.assertRaises(ValueError):
                    self.check(node)

    def test_tuic_v4_and_zero_rtt_are_rejected(self):
        for change in ('uuid', 'token', 'zero_rtt_handshake'):
            node = self.node('tuic')
            if change == 'uuid': node['uuid'] = 'invalid'
            elif change == 'token': node['token'] = 'synthetic-v4'
            else: node['zero_rtt_handshake'] = True
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError)):
                self.check(node)

    def test_xray_hysteria_cannot_inject_extra_masks_or_tls_files(self):
        node = {'tag': 'may-hop-' + 'a' * 16, 'protocol': 'hysteria', 'settings': {'version': 2, 'address': '192.0.2.20', 'port': 24000},
                'streamSettings': {'network': 'hysteria', 'security': 'tls', 'tlsSettings': {'serverName': 'next.example.test', 'allowInsecure': False, 'minVersion': '1.3', 'alpn': ['h3']}, 'hysteriaSettings': {'version': 2, 'auth': 'synthetic-probe-password'}, 'finalmask': {'quicParams': {'congestion': 'bbr'}}}}
        self.check(node, 'RealityEntry')
        for section, key, value in (('tlsSettings', 'certificateFile', '/etc/unrelated'), ('finalmask', 'tcp', []), ('hysteriaSettings', 'masquerade', {})):
            bad = copy.deepcopy(node); bad['streamSettings'][section][key] = value
            with self.subTest(section=section), self.assertRaises(ValueError):
                self.check(bad, 'RealityEntry')


if __name__ == '__main__': unittest.main()
