import copy
import importlib.util
import json
from pathlib import Path
import unittest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('templates', ROOT / 'scripts/client-template-library.py')
templates = importlib.util.module_from_spec(spec); spec.loader.exec_module(templates)

def document():
    return {'Bases': {'Clash': (ROOT/'templates/client/clash-general.template.yaml').read_text(encoding='utf-8'), 'SingBox': (ROOT/'templates/client/sing-box-general.template.json').read_text(encoding='utf-8')},
            'Layout': json.loads((ROOT/'config/client-layout.default.json').read_text(encoding='utf-8')),
            'Parameters': {'ClashMixedPort': 28080, 'RouteMixedPort': 28081, 'LogLevel': 'warn', 'AllowLan': False, 'ClashIpv6': True, 'Mode': 'global', 'TunMtu': 1400}}

class Templates(unittest.TestCase):
    def test_parameters_deterministic_and_no_source_mutation(self):
        source = document(); original = copy.deepcopy(source); result = templates.render(source)
        self.assertEqual(source, original); self.assertEqual(result, templates.render(source))
        clash = YAML(typ='safe').load(result['Contents']['Clash']); sing = json.loads(result['Contents']['SingBox'])
        self.assertEqual((clash['mixed-port'],clash['log-level'],clash['bind-address']), (28080,'warning','127.0.0.1'))
        self.assertEqual((sing['inbounds'][0]['listen_port'],sing['inbounds'][0]['listen']), (28081,'127.0.0.1'))
        self.assertEqual(sing['inbounds'][1]['mtu'],1400); self.assertEqual(sing['experimental']['clash_api']['default_mode'],'global')
        self.assertTrue(all(d['Status']=='RemoteNotFetched' for d in result['Dependencies']))
    def test_explicit_lan_is_not_a_system_proxy_change(self):
        source=document();source['Parameters']['AllowLan']=True;result=templates.render(source)
        self.assertEqual(json.loads(result['Contents']['SingBox'])['inbounds'][0]['listen'],'0.0.0.0')
        self.assertTrue(YAML(typ='safe').load(result['Contents']['Clash'])['allow-lan'])
    def test_unknown_group_reference_is_rejected(self):
        for fmt in ('Clash','SingBox'):
            source=document()
            if fmt=='Clash': source['Bases'][fmt] += '\nproxy-groups: [{name: unknown, type: select, proxies: [DIRECT]}]\n'
            else:
                base=json.loads(source['Bases'][fmt]);base['route']['final']='unknown';source['Bases'][fmt]=json.dumps(base)
            with self.assertRaises(Exception):templates.render(source)
    def test_fixed_nodes_and_unbundled_paths_rejected(self):
        for fmt in ('Clash','SingBox'):
            source=document()
            if fmt=='Clash':source['Bases'][fmt]='proxies: [{name: static, type: ss, server: example.test}]'
            else:
                base=json.loads(source['Bases'][fmt]);base['route']['rule_set'][0]={'type':'local','tag':'x','format':'binary','path':'../secret'};source['Bases'][fmt]=json.dumps(base)
            with self.assertRaises(ValueError):templates.render(source)
    def test_undefined_rule_provider_and_rule_set_rejected(self):
        source=document();base=YAML(typ='safe').load(source['Bases']['Clash'])
        base['rules'].insert(0,'RULE-SET,undefined-provider,DIRECT')
        import io
        stream=io.StringIO();YAML().dump(base,stream);source['Bases']['Clash']=stream.getvalue()
        with self.assertRaises(ValueError):templates.render(source)
        source=document();base=json.loads(source['Bases']['SingBox'])
        base['route']['rules'].insert(0,{'rule_set':['undefined-set'],'outbound':'DIRECT'})
        source['Bases']['SingBox']=json.dumps(base)
        with self.assertRaises(ValueError):templates.render(source)
    def test_remote_dependency_credentials_never_shown(self):
        source=document();base=json.loads(source['Bases']['SingBox']);base['route']['rule_set'][0]['url']='https://example.test/rules?token=synthetic-only';source['Bases']['SingBox']=json.dumps(base)
        result=templates.render(source);serialized=json.dumps(result['Dependencies'])
        self.assertNotIn('synthetic-only',serialized);self.assertNotIn('token=',serialized)
        for url in ('http://example.test/rules','https://u:p@example.test/rules','file:///tmp/rules'):
            base['route']['rule_set'][0]['url']=url;source['Bases']['SingBox']=json.dumps(base)
            with self.assertRaises(ValueError):templates.render(source)

if __name__=='__main__':unittest.main(verbosity=2)
