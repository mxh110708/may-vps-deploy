"""Owned inbound transactions with isolated files and a fake service manager."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import os
import socket
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('inbound_host',ROOT/'scripts/inbound-host.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
BACKUP=PurePosixPath('/root/vps-deploy-backups/20261025-010101/protocol-lifecycle')
A,B='a'*32,'b'*32


def port():
    for _ in range(100):
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));number=s.getsockname()[1]
            try:
                with socket.socket(type=socket.SOCK_DGRAM) as udp:udp.bind(('127.0.0.1',number))
                return number
            except OSError:pass
    raise RuntimeError('No paired synthetic TCP/UDP port available.')


def payload(ids=(A,B)):
    configs={};bindings=[];inbounds=[]
    for identifier in ids:
        p=port();config={'log':{'level':'warn'},'dns':{'servers':[{'type':'local','tag':'local'}]},'inbounds':[{'type':'shadowsocks','tag':identifier,'listen':'127.0.0.1','listen_port':p,'method':'2022-blake3-aes-128-gcm','password':'synthetic-server-key','users':[{'name':'c'*32,'password':'synthetic-user-key'}]}],'outbounds':[{'type':'direct','tag':'egress'}],'route':{'final':'egress'}}
        data=json.dumps(config).encode();configs[identifier]=base64.b64encode(data).decode();bindings.append({'Id':identifier,'Enabled':True,'Sha256':M.digest(data),'ClientSha256':'e'*64,'Port':p,'Address':'127.0.0.1','Udp':True})
        inbounds.append({'Id':identifier,'Name':'Synthetic '+identifier[:1],'Protocol':'Shadowsocks2022','Enabled':True})
    return {'Version':1,'Model':{'Version':1,'Inbounds':inbounds,'Users':[],'Certificates':[],'Outbounds':[]},'Bindings':bindings,'Configurations':configs,'Core':{'Engine':'sing-box','Version':'1.14.2','Artifact':'sing-box-1.14.2-linux-amd64.tar.gz','Sha256':'d'*64}}


class Kernel:
    def __init__(self,root):self.root=root;self.states={};self.events=[];self.fail_start=''
    def __call__(self,args,**kwargs):
        code=0;out=''
        if args[:3]==['ip','-j','address']:out='[{"addr_info":[{"local":"127.0.0.1"}]}]'
        elif args[0]=='systemctl':
            action=args[1];name=args[-1] if action!='show' else args[2];current=self.states.setdefault(name,{'Enabled':False,'Active':False})
            if action=='is-enabled':code=0 if current['Enabled'] else 1
            elif action=='is-active':code=0 if current['Active'] else 1
            elif action=='show':out='/etc/systemd/system/'+name if 'FragmentPath' in args else ''
            elif action in ('enable','disable'):
                self.events.append((action,name));current['Enabled']=action=='enable'
                if '--now' in args:current['Active']=action=='enable'
                if action=='enable' and name==self.fail_start:code=1;current['Active']=False
            elif action=='start':self.events.append((action,name));current['Active']=True
        return subprocess.CompletedProcess(args,code,out,'synthetic operation failed' if code else '')


class FixtureHost(M.Host):
    def verify_core(self,core):M.core_spec(core)
    def ensure_core(self,core):M.core_spec(core)
    def wait_ready(self,binding):pass


class InboundOwnership(unittest.TestCase):
    def setUp(self):
        (ROOT/'.test-output').mkdir(exist_ok=True);self.temp=tempfile.TemporaryDirectory(prefix='inbound-host-',dir=ROOT/'.test-output' if os.name=='nt' else None);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);(self.root/'etc/systemd/system').mkdir(parents=True);self.kernel=Kernel(self.root);self.host=FixtureHost(self.root,self.kernel);self.index=0
    def snapshot(self,value,affected):
        self.index+=1;backup=PurePosixPath('/root/vps-deploy-backups/20261025-'+str(self.index).zfill(6)+'/protocol-lifecycle');self.host.path(str(backup)).mkdir(parents=True)
        before=self.host.read();self.host.snapshot(backup,before['Hash'],value,affected)
        with tarfile.open(self.host.path(str(backup))/'protocol-files.tar.gz','w:gz') as archive:
            for path in self.host.paths(affected):archive.add(self.host.path(path),arcname=path.lstrip('/'))
        return backup,before
    def apply(self,value,affected):
        backup,before=self.snapshot(value,affected);self.host.apply(backup,value,before['Hash'],affected);return backup,before
    def restore(self,backup):
        self.host.rollback_prepare(backup)
        with tarfile.open(self.host.path(str(backup))/'protocol-files.tar.gz') as archive:
            for member in archive.getmembers():
                path=self.host.path('/'+member.name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(archive.extractfile(member).read());path.chmod(member.mode)
        self.host.rollback_complete(backup)
    def test_edit_one_identity_does_not_restart_other_service(self):
        original=payload();self.apply(original,[A,B]);before_b=self.host.regular(M.config_path(B)).read_bytes();self.kernel.events.clear()
        changed=copy.deepcopy(original);config=json.loads(base64.b64decode(changed['Configurations'][A]));config['inbounds'][0]['users'][0]['password']='rotated-synthetic';data=json.dumps(config).encode();changed['Configurations'][A]=base64.b64encode(data).decode();changed['Bindings'][0]['Sha256']=M.digest(data)
        backup,before=self.apply(changed,[A]);self.assertEqual(self.host.regular(M.config_path(B)).read_bytes(),before_b);self.assertFalse(any(name==M.unit_name(B) for action,name in self.kernel.events));self.restore(backup);self.assertEqual(self.host.read()['Hash'],before['Hash']);self.assertEqual(self.host.state(B),{'Enabled':True,'Active':True})
    def test_name_only_catalogue_change_keeps_services_running(self):
        value=payload();self.apply(value,[A,B]);self.kernel.events.clear();value['Model']['Inbounds'][0]['Name']='new display name';self.apply(value,[]);self.assertEqual(self.kernel.events,[])
    def test_shared_change_cannot_hide_affected_identity(self):
        value=payload();self.apply(value,[A,B]);edited=copy.deepcopy(value)
        for binding in edited['Bindings']:binding['ClientSha256']='f'*64
        with self.assertRaises(ValueError):self.host.preflight(edited,[A])
    def test_stop_enable_remove_and_scope_recovery(self):
        value=payload();self.apply(value,[A,B]);disabled=copy.deepcopy(value);disabled['Bindings'][0]['Enabled']=False;disabled['Model']['Inbounds'][0]['Enabled']=False;backup,before=self.apply(disabled,[A]);self.assertFalse(self.host.state(A)['Active']);self.assertTrue(self.host.state(B)['Active']);self.restore(backup);self.assertEqual(self.host.read()['Hash'],before['Hash'])
        removed=copy.deepcopy(value);removed['Model']['Inbounds']=removed['Model']['Inbounds'][1:];removed['Bindings']=removed['Bindings'][1:];del removed['Configurations'][A];backup,before=self.apply(removed,[A]);self.assertFalse(self.host.path(M.config_path(A)).exists());self.assertTrue(self.host.state(B)['Active']);self.restore(backup);self.assertEqual(self.host.read()['Hash'],before['Hash'])
    def test_partial_activation_failure_restores_only_affected_service(self):
        value=payload();self.apply(value,[A,B]);edited=copy.deepcopy(value);edited['Bindings'][0]['ClientSha256']='f'*64;backup,before=self.snapshot(edited,[A]);self.kernel.fail_start=M.unit_name(A)
        with self.assertRaises(ValueError):self.host.apply(backup,edited,before['Hash'],[A])
        self.kernel.fail_start='';self.kernel.events.clear();self.restore(backup);self.assertEqual(self.host.read()['Hash'],before['Hash']);self.assertFalse(any(name==M.unit_name(B) for action,name in self.kernel.events))
    def test_owned_file_edit_prevents_apply(self):
        value=payload();self.apply(value,[A,B]);self.host.regular(M.config_path(A)).write_bytes(b'unmanaged edit')
        with self.assertRaises(ValueError):self.host.read()
    def test_external_change_blocks_rollback_before_other_writes(self):
        value=payload();self.apply(value,[A,B]);edited=copy.deepcopy(value);edited['Bindings'][0]['ClientSha256']='f'*64;backup,before=self.apply(edited,[A]);file=self.host.regular(M.config_path(B));file.write_bytes(b'external unrelated edit');a=self.host.regular(M.config_path(A)).read_bytes();self.kernel.events.clear()
        with self.assertRaises(ValueError):self.host.rollback_prepare(backup)
        self.assertEqual(self.host.regular(M.config_path(A)).read_bytes(),a);self.assertEqual(self.kernel.events,[])
    def test_unmanaged_namespace_and_overrides_refused(self):
        path=self.host.path('/etc/systemd/system/may-inbound-unknown.service');path.write_text('unmanaged')
        with self.assertRaises(ValueError):self.host.read()
    def test_unknown_identity_blocks_recovery_before_stopping_services(self):
        value=payload();self.apply(value,[A,B]);value['Bindings'][0]['ClientSha256']='f'*64;backup,_=self.apply(value,[A]);self.host.path('/etc/systemd/system/may-inbound-'+('c'*32)+'.service').write_text('unrelated');self.kernel.events.clear()
        with self.assertRaises(ValueError):self.host.rollback_prepare(backup)
        self.assertEqual(self.kernel.events,[])
    def test_snapshot_cannot_restore_an_unreviewed_service_state(self):
        value=payload();self.apply(value,[A,B]);value['Bindings'][0]['ClientSha256']='f'*64;backup,_=self.apply(value,[A]);journal=self.host.journal(backup);journal['OriginalRuntime'][B]={'Enabled':False,'Active':False};self.host.save_journal(backup,journal);self.kernel.events.clear()
        with self.assertRaises(ValueError):self.host.rollback_prepare(backup)
        self.assertEqual(self.kernel.events,[])
    def test_snapshot_scope_and_archive_are_bound(self):
        value=payload();self.apply(value,[A,B]);edited=copy.deepcopy(value);edited['Bindings'][0]['ClientSha256']='f'*64;backup,_=self.apply(edited,[A]);journal=self.host.journal(backup);journal['Applied']['/etc/shadow']='f'*64;self.host.save_journal(backup,journal)
        with self.assertRaises(ValueError):self.host.rollback_check(backup)
    def test_live_listener_conflict_is_detected(self):
        value=payload((A,));port_number=value['Bindings'][0]['Port']
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',port_number));listener.listen()
            with self.assertRaises(OSError):self.host.preflight(value,[A])
    def test_stopped_runtime_requires_explicit_review_scope(self):
        value=payload();self.apply(value,[A,B]);fingerprint=self.host.read()['Hash'];self.kernel.states[M.unit_name(A)]['Active']=False;self.assertEqual(self.host.read()['Hash'],fingerprint)
        with self.assertRaises(ValueError):self.host.preflight(value,[])
        self.apply(value,[A]);self.assertTrue(self.host.state(A)['Active'])
    def test_rendered_binding_tampering_and_duplicate_identity_refused(self):
        value=payload();value['Configurations'][A]=base64.b64encode(b'{}').decode()
        with self.assertRaises(ValueError):M.normalize(value)
        value=payload();value['Bindings'][1]['Id']=A
        with self.assertRaises(ValueError):M.normalize(value)
    def test_secrets_are_not_in_catalogue_or_unit_and_config_is_private(self):
        value=payload();self.apply(value,[A,B]);self.assertNotIn('synthetic-user-key',self.host.regular(M.REGISTRY).read_text());self.assertNotIn('synthetic-user-key',self.host.regular(M.unit_path(A)).read_text());self.assertIn('LoadCredential=',self.host.regular(M.unit_path(A)).read_text())
        if os.name!='nt':self.assertEqual(stat.S_IMODE(self.host.regular(M.config_path(A)).stat().st_mode),0o600)
    def test_verified_core_cache_is_atomic_and_tampering_is_refused(self):
        binary=b'#!synthetic immutable core';memory=io.BytesIO()
        with tarfile.open(fileobj=memory,mode='w:gz') as archive:
            item=tarfile.TarInfo('sing-box-1.14.2/sing-box');item.size=len(binary);archive.addfile(item,io.BytesIO(binary))
        content=memory.getvalue();core=payload()['Core'];core['Sha256']=M.digest(content);host=M.Host(self.root,self.kernel,lambda _:content);host.ensure_core(core);path=host.path(M.core_path(core));self.assertEqual(path.read_bytes(),binary)
        if os.name!='nt':self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode),0o755)
        path.write_bytes(b'unmanaged edit')
        with self.assertRaises(ValueError):host.ensure_core(core)
        self.assertEqual(path.read_bytes(),b'unmanaged edit')
    def test_bad_core_download_never_creates_live_core(self):
        core=payload()['Core'];host=M.Host(self.root,self.kernel,lambda _:b'wrong')
        with self.assertRaises(ValueError):host.ensure_core(core)
        self.assertFalse(host.path(M.core_path(core)).exists())
    def test_xray_archive_and_unit_are_independently_pinned(self):
        memory=io.BytesIO()
        with zipfile.ZipFile(memory,'w') as archive:archive.writestr('xray',b'fixed synthetic Xray')
        content=memory.getvalue();core={'Engine':'xray','Version':'26.3.27','Artifact':'Xray-linux-64.zip','Sha256':M.digest(content)};host=M.Host(self.root,self.kernel,lambda _:content);host.ensure_core(core);host.verify_core(core)
        self.assertEqual(host.regular(M.core_path(core)).read_bytes(),b'fixed synthetic Xray');self.assertIn('/xray run -config %d/config.json',M.unit(A,core));self.assertNotIn(' -c ',M.unit(A,core))
    def test_logical_paths_cannot_escape_synthetic_root(self):
        for path in ('/../root','\\root\\file','/etc/../../root','//root/file','C:\\root'):
            with self.assertRaises(ValueError):self.host.path(path)
    def quic(self):
        value=payload((A,));value['Model']['Inbounds'][0]['Protocol']='Hysteria2';config=json.loads(base64.b64decode(value['Configurations'][A]));config['inbounds'][0]['type']='hysteria2';del config['inbounds'][0]['method'];del config['inbounds'][0]['password'];data=json.dumps(config).encode();value['Configurations'][A]=base64.b64encode(data).decode();value['Bindings'][0]['Sha256']=M.digest(data);return value
    def test_quic_preflight_does_not_require_a_tcp_port(self):
        value=self.quic()
        with socket.socket() as tcp:
            tcp.bind(('127.0.0.1',value['Bindings'][0]['Port']));tcp.listen();self.host.preflight(value,[A])
    def test_occupied_udp_blocks_quic_before_any_write(self):
        value=self.quic()
        with socket.socket(type=socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1',value['Bindings'][0]['Port']))
            with self.assertRaises(OSError):self.host.preflight(value,[A])
        self.assertFalse(self.host.path(M.REGISTRY).exists())
    def test_quic_ready_requires_owned_udp_listener(self):
        value=self.quic();self.apply(value,[A]);binding=value['Bindings'][0]
        def run(args,**kwargs):
            if 'MainPID' in args:return subprocess.CompletedProcess(args,0,'3344','')
            if args[0]=='ss':return subprocess.CompletedProcess(args,0,'UNCONN 0 0 127.0.0.1:'+str(binding['Port'])+' 0.0.0.0:* users:(("sing-box",pid=3344,fd=7))','')
            return self.kernel(args,**kwargs)
        host=M.Host(self.root,run);host.wait_ready(binding)
        def wrong(args,**kwargs):
            result=run(args,**kwargs)
            return subprocess.CompletedProcess(args,result.returncode,result.stdout.replace('pid=3344,','pid=9988,'),result.stderr)
        with patch.object(M.time,'sleep'):
            with self.assertRaises(ValueError):M.Host(self.root,wrong).wait_ready(binding)


if __name__=='__main__':unittest.main()
