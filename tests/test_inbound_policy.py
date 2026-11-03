"""Independent policy scope and finite native-path checks; no production hosts."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_inbound_host as existing

M = existing.M
ROOT = Path(__file__).resolve().parents[1]
namespace = {'__name__': 'inbound_policy_test'}
exec((ROOT/'scripts/inbound-host.py').read_text(encoding='utf-8').split("\nif __name__==",1)[0], namespace)
exec((ROOT/'scripts/inbound-policy-probe.py').read_text(encoding='utf-8'), namespace)
A, B = existing.A, existing.B
DEFAULT, EXTRA = 'c'*32, 'd'*32


def policy_fixture():
    value = existing.payload()
    item = value['Model']['Inbounds'][0]
    item.update(Listener={'Address':value['Bindings'][0]['Address'], 'Port':value['Bindings'][0]['Port']}, UserIds=['e'*32], CertificateId='', OutboundId=DEFAULT, Options={'Method':'2022-blake3-aes-128-gcm'})
    value['Model']['Outbounds'] = [{'Id':DEFAULT,'Name':'default','Kind':'Direct','Family':'IPv4','ExpectedAddress':'','Source':{}}, {'Id':EXTRA,'Name':'extra','Kind':'Proxy','Family':'IPv4','ExpectedAddress':'198.51.100.28','Source':{'SchemeId':'1'*32,'NodeId':'2'*32,'Fingerprint':'3'*64}}]
    snapshot = {'Schema':1,'Id':'policy-test','Name':'test','Revision':'1.0.0','Rules':[{'Kind':'Suffix','Value':'research.example.test'}]}
    item['Routing'] = {'Version':1,'Rules':[{'Kind':'RuleSet','Value':'policy-test','Action':'NextHop','Target':EXTRA,'RuleSet':snapshot}, {'Kind':'Cidr','Value':'203.0.113.0/24','Action':'Reject'}]}
    config = json.loads(existing.base64.b64decode(value['Configurations'][A]))
    config['outbounds'] = [{'type':'direct','tag':'egress'}, {'type':'shadowsocks','tag':'policy-'+EXTRA,'server':'192.0.2.28','server_port':33443,'method':'chacha20-ietf-poly1305','password':'synthetic-only'}]
    config['route'] = {'final':'egress','rules':[{'inbound':[A],'network':'tcp','domain':['research.example.test'],'domain_suffix':['.research.example.test'],'action':'route','outbound':'policy-'+EXTRA}, {'inbound':[A],'network':'tcp','ip_cidr':['203.0.113.0/24'],'action':'reject'}, {'ip_version':6,'action':'reject'}]}
    encode(value, config)
    return value, config


def encode(value, config):
    data=M.encoded(config).encode();value['Configurations'][A]=existing.base64.b64encode(data).decode();value['Bindings'][0]['Sha256']=M.digest(data)


class PolicyOwnership(unittest.TestCase):
    setUp=existing.InboundOwnership.setUp
    snapshot=existing.InboundOwnership.snapshot
    apply=existing.InboundOwnership.apply
    restore=existing.InboundOwnership.restore
    def test_policy_scope_and_restore(self):
        original,_=policy_fixture();self.apply(original,[A,B]);before=self.host.read();changed=copy.deepcopy(original);config=json.loads(existing.base64.b64decode(changed['Configurations'][A]))
        changed['Model']['Inbounds'][0]['Routing']['Rules'][0]['Action']='Reject';changed['Model']['Inbounds'][0]['Routing']['Rules'][0].pop('Target');config['outbounds'].pop();config['route']['rules'][0]['action']='reject';config['route']['rules'][0].pop('outbound');encode(changed,config)
        self.kernel.events.clear();backup,_=self.snapshot(changed,[A]);self.host.apply(backup,changed,before['Hash'],[A]);self.assertNotIn(('stop',M.unit_name(B)),self.kernel.events);self.restore(backup);self.assertEqual(self.host.read()['Hash'],before['Hash']);self.assertNotIn(('start',M.unit_name(B)),self.kernel.events)
    def test_native_rule_guard_and_refs(self):
        for fault in ('udp','wrong-target','fallback','order','extra-output','missing-output','proxy-to-direct','wrong-version','category-command','missing-resource','unknown-policy','duplicate-resource','empty-target','false-target','source-fields','native-type','family'):
            with self.subTest(fault=fault):
                value,config=policy_fixture();item=value['Model']['Inbounds'][0];rules=config['route']['rules']
                if fault=='udp':rules[0]['network']='udp'
                elif fault=='wrong-target':rules[0]['outbound']='egress'
                elif fault=='fallback':config['route']['final']='policy-'+EXTRA
                elif fault=='order':rules.reverse()
                elif fault=='extra-output':config['outbounds'].append({'type':'direct','tag':'unowned'})
                elif fault=='missing-output':config['outbounds'].pop()
                elif fault=='proxy-to-direct':config['outbounds'][1]={'type':'direct','tag':'policy-'+EXTRA}
                elif fault=='wrong-version':item['Routing']['Version']=2
                elif fault=='category-command':item['Routing']['Rules'][0]['RuleSet']['Rules'][0]['command']='echo'
                elif fault=='missing-resource':value['Model']['Outbounds'].pop()
                elif fault=='duplicate-resource':value['Model']['Outbounds'].append(copy.deepcopy(value['Model']['Outbounds'][1]))
                elif fault=='empty-target':item['Routing']['Rules'][0]['Target']=''
                elif fault=='false-target':item['Routing']['Rules'][0]['Target']=False
                elif fault=='source-fields':value['Model']['Outbounds'][1]['Source']={}
                elif fault=='native-type':config['outbounds'][1]['type']='socks'
                elif fault=='family':value['Model']['Outbounds'][1]['Family']='IPv6'
                else:item['Routing']['script']='ignored'
                encode(value,config)
                with self.assertRaises(ValueError):M.normalize(value)
    def test_probe_identity_and_drift(self):
        value,config=policy_fixture();self.apply(value,[A,B]);state=self.host.read();item=value['Model']['Inbounds'][0]
        paths=namespace['policy_paths'](value['Model'],item)
        for path in paths:path['OutboundFingerprint']='f'*64
        request={'InboundId':A,'ConfigurationSha256':value['Bindings'][0]['Sha256'],'PolicyFingerprint':'a'*64,'Paths':paths}
        namespace['validate_request'](request,state)
        for fault in ('hash','missing','target','id','family','inactive'):
            with self.subTest(fault=fault):
                bad=copy.deepcopy(request);observed=copy.deepcopy(state)
                if fault=='hash':bad['ConfigurationSha256']='b'*64
                elif fault=='missing':bad['Paths'].pop()
                elif fault=='target':bad['Paths'][1]['Tag']='egress'
                elif fault=='id':bad['InboundId']=B
                elif fault=='family':bad['Paths'][1]['Family']='IPv6'
                else:observed['Runtime'][A]['Active']=False
                with self.assertRaises((ValueError,KeyError)):namespace['validate_request'](bad,observed)
        calls=[]
        binary=self.host.path(M.core_path(value['Core']));binary.parent.mkdir(parents=True,exist_ok=True);binary.write_bytes(b'isolated-unexecuted-core')
        def probe(binary,xray,source,path):
            calls.append(source['tag']);return {'Id':path['Id'],'Status':'Passed','From':'EntryServer','Scope':'NativeOutboundHttps','Network':'TCP','Egress':'198.51.100.28'}
        with patch.dict(namespace,probe_path=probe):
            result=namespace['run_policy'](self.host,request)
        self.assertEqual(calls,['egress','policy-'+EXTRA]);self.assertEqual(result['PolicyFingerprint'],request['PolicyFingerprint']);self.assertEqual(self.host.read()['Hash'],state['Hash'])
        with patch.object(self.host,'read',side_effect=[state,dict(state,Hash='changed')]),patch.dict(namespace,probe_path=probe):
            with self.assertRaises(ValueError):namespace['run_policy'](self.host,request)


if __name__ == '__main__':
    unittest.main()
