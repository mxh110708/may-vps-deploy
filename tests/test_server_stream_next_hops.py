"""Bounded stream next hops and private probe inputs; no external network."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_server_hops import API


def item(protocol='vless', reality=False, transport=None):
    native = {'tag':'may-hop-0123456789abcdef','type':protocol,'server':'192.0.2.29','server_port':24029,
              'tls':{'enabled':True,'server_name':'next.example.test','min_version':'1.3'}}
    if protocol=='vless': native.update(uuid='11111111-2222-3333-4444-555555555555', packet_encoding='xudp')
    else: native['password']='synthetic-only-password'
    if reality:
        native['flow']='xtls-rprx-vision';native['tls'].pop('min_version')
        native['tls'].update(utls={'enabled':True,'fingerprint':'chrome'}, reality={'enabled':True,'public_key':'A'*43,'short_id':'ab12cd34'})
    if transport:
        native['transport']={'type':'ws','path':'/next-hop/','headers':{'Host':'front.example.test'},'max_early_data':512,'early_data_header_name':'Sec-WebSocket-Protocol'} if transport=='ws' else {'type':'grpc','service_name':'MayNextHop'}
    if protocol=='anytls': native.update(idle_session_check_interval='30s',idle_session_timeout='45s',min_idle_session=1,client_metadata='test')
    return {'Id':'0123456789abcdef','ExpectedAddress':'198.51.100.29','Outbound':native}


def xray(protocol='vless', reality=False):
    value=item(protocol,reality);native=value['Outbound'];security={'serverName':'next.example.test'}
    if reality: security.update(fingerprint='chrome',publicKey='A'*43,shortId='ab12cd34')
    else: security.update(allowInsecure=False,minVersion='1.3',maxVersion='1.3',alpn=['http/1.1'])
    server={'address':native['server'],'port':native['server_port']}
    if protocol=='vless': server['users']=[{'id':native['uuid'],'encryption':'none','flow':'xtls-rprx-vision' if reality else ''}]
    else: server['password']=native['password']
    value['Outbound']={'tag':native['tag'],'protocol':protocol,'settings':{'vnext' if protocol=='vless' else 'servers':[server]},
                       'streamSettings':{'network':'raw','security':'reality' if reality else 'tls','realitySettings' if reality else 'tlsSettings':security}}
    return value


class StreamBoundaries(unittest.TestCase):
    def test_native_protocols_transport_and_sessions(self):
        for protocol in ('vless','trojan','anytls'):
            value=item(protocol);API['validate']([value],'AnyTlsEntry')
            if protocol!='anytls':
                for transport in ('ws','grpc'): API['validate']([item(protocol,transport=transport)],'AnyTlsEntry')
        API['validate']([item(reality=True)],'AnyTlsEntry')
        value=item('anytls');value['Outbound']['tls']['ech']={'enabled':True,'config':['-----BEGIN ECH CONFIGS-----','AAQBAgME','-----END ECH CONFIGS-----']};API['validate']([value],'AnyTlsEntry')
    def test_xray_exact_projection(self):
        for value in (xray(),xray(reality=True),xray('trojan')): API['validate']([value],'RealityEntry')
        for fault in ('socket','disabled-tls','many-users','wrong-encryption','other-transport','private-cert','wrong-reality'):
            with self.subTest(fault=fault):
                value=xray(reality=fault=='wrong-reality');native=value['Outbound'];stream=native['streamSettings']
                if fault=='socket':stream['sockopt']={'mark':1}
                elif fault=='disabled-tls':stream['tlsSettings']['allowInsecure']=True
                elif fault=='many-users':native['settings']['vnext'][0]['users']*=2
                elif fault=='wrong-encryption':native['settings']['vnext'][0]['users'][0]['encryption']='unknown'
                elif fault=='other-transport':stream['network']='ws'
                elif fault=='private-cert':stream['tlsSettings'].update(disableSystemRoot=True,certificates=[{'usage':'verify','certificate':['-----BEGIN '+'PRIVATE KEY-----']}])
                else:stream['realitySettings']['publicKey']='invalid'
                with self.assertRaises(ValueError):API['validate']([value],'RealityEntry')
    def test_no_native_injection_or_tls_relaxation(self):
        for protocol in ('vless','trojan','anytls'):
            for container,field,content in (('root','detour','direct'),('root','network','udp'),('root','certificate_path','/tmp/file'),('tls','insecure',True),('tls','key',['private']),('tls','certificate_path','/tmp/ca'),('tls','enabled',False),('tls','min_version','1.1'),('tls','alpn',[{}])):
                with self.subTest(protocol=protocol,field=field):
                    value=item(protocol);target=value['Outbound'] if container=='root' else value['Outbound']['tls'];target[field]=content
                    with self.assertRaises(ValueError):API['validate']([value],'AnyTlsEntry')
    def test_identity_and_transport_boundaries(self):
        for fault in ('uuid','endpoint','port','vision','header','header-case','path','early','grpc','ech-private','ech-encoding'):
            with self.subTest(fault=fault):
                value=item(transport='ws' if fault in ('header','header-case','path','early') else 'grpc' if fault=='grpc' else None);native=value['Outbound']
                if fault=='uuid':native['uuid']='00000000-0000-0000-0000-000000000000'
                elif fault=='endpoint':native['server']='example.test'
                elif fault=='port':native['server_port']=True
                elif fault=='vision':native.update(flow='xtls-rprx-vision');native['tls']['max_version']='1.2'
                elif fault=='header':native['transport']['headers']['Connection']='upgrade'
                elif fault=='header-case':native['transport']['headers']['host']='other.example.test'
                elif fault=='path':native['transport']['path']='//unexpected'
                elif fault=='early':native['transport']['early_data_header_name']='Host'
                elif fault=='grpc':native['transport']['service_name']='../command'
                elif fault=='ech-private':native['tls']['ech']={'enabled':True,'key':['private']}
                else:native['tls']['ech']={'enabled':True,'config':['-----BEGIN ECH CONFIGS-----','$$$','-----END ECH CONFIGS-----']}
                with self.assertRaises(ValueError):API['validate']([value],'AnyTlsEntry')
    def test_private_document_main_and_bounds(self):
        with tempfile.TemporaryDirectory(prefix='stream-probe-input-') as temp:
            filename=Path(temp).resolve()/'probes.private.json';filename.write_text(json.dumps([item()]),encoding='utf-8');calls=[]
            def probe(binary,role,value): calls.append(value);return {'Id':value['Id'],'Status':'Passed'}
            with patch.dict(os.environ,VPS_PARAM_PROBES_JSON_FILE=str(filename)),patch.dict(API,run_probe=probe),patch('sys.argv',['probe.py','synthetic-unexecuted-core','AnyTlsEntry']),contextlib.redirect_stdout(io.StringIO()):
                API['main']()
                self.assertEqual(len(calls),1)
                filename.write_bytes(b' '*1048577)
                with self.assertRaises(ValueError):API['main']()
                self.assertEqual(len(calls),1)
    def test_core_scope_and_duplicate_resources(self):
        for values,role in (([item('anytls')],'RealityEntry'),([item()],'Other'),([item(),copy.deepcopy(item())],'AnyTlsEntry')):
            with self.assertRaises(ValueError):API['validate'](values,role)


if __name__=='__main__':unittest.main()
