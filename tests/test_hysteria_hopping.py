"""Bounded nft rendering and ownership checks; no host firewall writes."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
PROGRAM=(ROOT/'assets/remote/firewall-tools.sh').read_text(encoding='utf-8').split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]


def functions(mappings):
    namespace={};output=io.StringIO()
    with mock.patch.dict(os.environ,{'VPS_PARAM_HYSTERIA_REDIRECTS':json.dumps(mappings)}),mock.patch.object(sys,'argv',['firewall','functions']),contextlib.redirect_stdout(output):
        try:exec(compile(PROGRAM,'owned-firewall','exec'),namespace)
        except SystemExit as error:
            if str(error)!='Unknown firewall operation.':raise
    return namespace


class HysteriaHoppingFirewall(unittest.TestCase):
    def render(self,value):
        namespace=functions(value)
        with mock.patch.dict(os.environ,{'VPS_PARAM_HYSTERIA_REDIRECTS':json.dumps(value)}):return namespace['hysteria_redirects']()
    def test_empty_does_not_add_a_chain(self):self.assertEqual(self.render([]),'')
    def test_owned_table_replacement_removes_stale_base_chains(self):
        namespace=functions([])
        text='table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n }\n}\n'
        batch=namespace['scoped'](text)
        self.assertIn('delete table inet filter\n',batch)
        self.assertNotIn('flush ruleset',batch)
        self.assertEqual(namespace['canonical'](text),namespace['canonical'](batch))
    def test_ipv4_maps_only_alternatives_and_keeps_owned_listener(self):
        text=self.render([{'Address':'0.0.0.0','Port':22000,'Ports':[22002,22000,22001]}])
        self.assertIn('type nat hook prerouting priority -100; policy accept;',text)
        self.assertIn('meta nfproto ipv4 udp dport { 22001,22002 } counter redirect to :22000',text)
        self.assertNotIn('tcp',text);self.assertNotIn('ipv6',text)
    def test_ipv6_wildcard_matches_dual_stack_core_listener(self):
        text=self.render([{'Address':'::','Port':22000,'Ports':[22000,22001]}])
        self.assertIn('meta nfproto ipv4',text);self.assertIn('meta nfproto ipv6',text)
    def test_specific_destination_is_not_a_global_redirect(self):
        for address,prefix in [('192.0.2.10','ip'),('2001:db8::10','ip6')]:
            text=self.render([{'Address':address,'Port':22000,'Ports':[22000,22001]}])
            self.assertIn(prefix+' daddr '+address+' udp dport',text)
            self.assertIn('dnat '+prefix+' to '+(address if prefix=='ip' else '['+address+']')+':22000',text)
            self.assertNotIn('redirect to',text)
    def test_bad_or_oversized_maps_fail_before_rendering(self):
        base={'Address':'0.0.0.0','Port':22000,'Ports':[22000,22001]}
        bad=[None,{},[base]*17]
        for field,value in [('Address','127.0.0.1'),('Address','ff00::1'),('Address','fe80::1%eth0'),('Address','0.0.0.0; drop'),('Port',True),('Ports',[22000]),('Ports',[22001,22002]),('Ports',[22000,22000]),('Ports',[22000,True]),('Ports',list(range(22000,22257)))]:
            item=copy.deepcopy(base);item[field]=value;bad.append([item])
        other=copy.deepcopy(base);other['Port']=22001;bad.append([base,other])
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises((SystemExit,TypeError)):self.render(value)
    def test_runtime_names_and_counters_do_not_mask_changed_targets(self):
        mappings=[{'Address':'0.0.0.0','Port':22000,'Ports':[22000,22001]}]
        namespace=functions(mappings);rendered=self.render(mappings)
        config='table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n iifname "lo" accept\n }\n'+rendered+'}\n'
        actual=config.replace('priority -100','priority dstnat').replace('counter redirect','counter packets 12 bytes 1450 redirect')
        self.assertEqual(namespace['canonical'](config),namespace['canonical'](actual))
        self.assertNotEqual(namespace['canonical'](config),namespace['canonical'](actual.replace('redirect to :22000','redirect to :22002')))
        self.assertNotEqual(namespace['canonical'](config),namespace['canonical'](actual.replace('22001','22003')))


if __name__=='__main__':unittest.main()
