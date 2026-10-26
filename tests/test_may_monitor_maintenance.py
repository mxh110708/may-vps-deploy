"""M4 tests use private temporary files and fake accounts/services only."""
import datetime
import json
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import test_may_monitor_lifecycle as base

module=base.module

class MaintenanceLifecycle(base.FixtureLifecycle):
    def verify_agent_credential(self, configuration, secrets):
        if secrets.get('AgentToken') not in self.host.valid_tokens:
            raise ValueError('Synthetic rejected token.')
        configuration['ClientUUID']=self.host.agent_uuid
        configuration['ServerInstanceId']=self.host.server_uuid
        self.host.reports+=1
        now=datetime.datetime.now(datetime.timezone.utc)
        return {'maintenance_schema_version':1,'online':True,'captured_at':now.isoformat(),'report_at':(now-datetime.timedelta(milliseconds=10)).isoformat()}

class MaintenanceTests(unittest.TestCase):
    setUp=base.LifecycleTests.setUp
    tearDown=base.LifecycleTests.tearDown
    begin=base.LifecycleTests.begin
    asset=base.LifecycleTests.asset
    install=base.LifecycleTests.install

    def agent(self):
        self.host.valid_tokens={'synthetic-old-agent-token','synthetic-new-agent-token'};self.host.reports=0
        self.life=MaintenanceLifecycle(self.host,'Agent');task,backup=self.begin()
        self.life.apply(task,'Install',{'Endpoint':'https://monitor.example/'},{'AgentToken':'synthetic-old-agent-token'},self.asset(backup,role='Agent'));self.life.finish(task)
        return {'Endpoint':'https://alias.example/','ClientUUID':self.host.agent_uuid,'ServerInstanceId':self.host.server_uuid,'ReplaceToken':False}

    def test_endpoint_change_preserves_identity_core_and_capabilities(self):
        cfg=self.agent();binary=module.digest(self.host.path(self.life.binary));task,_=self.begin()
        result=self.life.apply(task,'ConfigureAgent',cfg,{});self.life.finish(task)
        self.assertEqual(result['Configuration']['ClientUUID'],self.host.agent_uuid);self.assertEqual(result['Configuration']['Endpoint'],'https://alias.example')
        self.assertEqual(result['ConnectionVerification']['Status'],'Verified');self.assertGreaterEqual(result['ConnectionVerification']['Samples'],3)
        saved=self.host.read_json(self.host.path(self.life.config+'/config.json'))
        self.assertEqual(saved['token'],'synthetic-old-agent-token');self.assertTrue(saved['disable_web_ssh']);self.assertTrue(saved['disable_auto_update']);self.assertFalse(saved['ignore_unsafe_cert'])
        self.assertEqual(module.digest(self.host.path(self.life.binary)),binary);self.assertEqual(result['Version'],'0.1.0-rc.2')

    def test_candidate_rejects_identity_mismatch_before_service_change(self):
        cfg=self.agent();cfg['ServerInstanceId']=str(base.uuid.uuid4());task,_=self.begin();before=self.life.inspect();calls=len(self.host.calls)
        with self.assertRaises(ValueError):self.life.apply(task,'ConfigureAgent',cfg,{})
        self.assertEqual(self.life.inspect(),before);self.assertNotIn(('systemctl','stop',self.life.unit),self.host.calls[calls:]);self.life.finish(task,True)

    def test_wrong_new_token_keeps_original_files(self):
        cfg=self.agent();cfg['ReplaceToken']=True;task,_=self.begin();before=self.life.inspect()
        with self.assertRaises(ValueError):self.life.apply(task,'ConfigureAgent',cfg,{'AgentToken':'synthetic-invalid-agent-token'})
        self.assertEqual(self.life.inspect(),before);self.life.finish(task,True)

    def test_stale_controller_archive_cannot_claim_token_synchronization(self):
        cfg=self.agent();before=self.life.inspect()
        with self.assertRaises(ValueError):self.life.candidate_agent(cfg,{'AgentToken':'synthetic-stale-archived-token'},before)
        self.assertEqual(self.life.inspect(),before)

    def test_unchanged_connection_is_not_restarted(self):
        cfg=self.agent();cfg['Endpoint']='https://monitor.example/';task,_=self.begin();calls=len(self.host.calls)
        with self.assertRaises(ValueError):self.life.apply(task,'ConfigureAgent',cfg,{})
        self.assertNotIn(('systemctl','stop',self.life.unit),self.host.calls[calls:]);self.life.finish(task,True)

    def test_rotation_succeeds_when_old_token_is_revoked(self):
        cfg=self.agent();cfg['ReplaceToken']=True;self.host.valid_tokens.remove('synthetic-old-agent-token');task,_=self.begin()
        result=self.life.apply(task,'ConfigureAgent',cfg,{'AgentToken':'synthetic-new-agent-token'});self.life.finish(task)
        self.assertEqual(result['ConnectionVerification']['Status'],'Verified');self.assertEqual(self.host.read_json(self.host.path(self.life.config+'/config.json'))['token'],'synthetic-new-agent-token')

    def test_revoked_old_token_requires_explicit_repair_not_false_rollback(self):
        cfg=self.agent();cfg['ReplaceToken']=True;task,_=self.begin();self.host.valid_tokens.remove('synthetic-old-agent-token')
        with patch.object(self.life,'wait_agent_reports',side_effect=ValueError('synthetic report failure')):
            with self.assertRaises(ValueError):self.life.apply(task,'ConfigureAgent',cfg,{'AgentToken':'synthetic-new-agent-token'})
        with self.assertRaises(ValueError):self.life.finish(task,True)
        self.assertEqual(self.life.transaction(task)[1]['Phase'],'CredentialRecoveryRequired');self.assertTrue(self.host.path(module.OWNER).exists())
        repaired=self.life.apply(task,'ConfigureAgent',cfg,{'AgentToken':'synthetic-new-agent-token'},repair_expected=self.life.inspect()['Hash'])
        self.assertEqual(repaired['ConnectionVerification']['Status'],'Verified');self.assertEqual(self.life.finish(task)['Phase'],'Committed');self.assertFalse(self.host.path(module.OWNER).exists())

    def test_valid_old_credential_is_verified_after_file_restore(self):
        cfg=self.agent();cfg['ReplaceToken']=True;task,_=self.begin()
        with patch.object(self.life,'wait_agent_reports',side_effect=ValueError('synthetic report failure')):
            with self.assertRaises(ValueError):self.life.apply(task,'ConfigureAgent',cfg,{'AgentToken':'synthetic-new-agent-token'})
        self.assertEqual(self.life.finish(task,True)['Phase'],'RolledBack');self.assertEqual(self.host.read_json(self.host.path(self.life.config+'/config.json'))['token'],'synthetic-old-agent-token')

    def test_nonadvancing_reports_never_pass(self):
        cfg=self.agent();stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        def fixed(configuration,secrets):
            configuration.update(ClientUUID=self.host.agent_uuid,ServerInstanceId=self.host.server_uuid)
            return {'maintenance_schema_version':1,'online':True,'captured_at':stamp,'report_at':stamp}
        with patch.object(self.life,'verify_agent_credential',side_effect=fixed),patch.object(module.time,'monotonic',side_effect=[0,0,1,2,40]):
            with self.assertRaises(ValueError):self.life.wait_agent_reports(cfg,'synthetic-old-agent-token')

    def test_initial_missing_report_waits_for_real_samples(self):
        cfg=self.agent();original=self.life.verify_agent_credential;calls=0
        def initially_missing(configuration,secrets):
            nonlocal calls
            result=original(configuration,secrets);calls+=1
            if calls==1:result['report_at']=None;result['online']=False
            return result
        with patch.object(self.life,'verify_agent_credential',side_effect=initially_missing):
            self.assertEqual(self.life.wait_agent_reports(cfg,'synthetic-old-agent-token')['Status'],'Verified')
        self.assertGreaterEqual(calls,4)

    def test_read_authorization_expiry_and_revocation_are_archived(self):
        self.install();task,_=self.begin();auth={'Sha256':'a'*64,'Clients':[str(base.uuid.uuid4())],'ExpiresAt':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=10)).isoformat()}
        result=self.life.apply(task,'ConfigureRead',{'ReadAuthorization':auth},{});self.life.finish(task)
        self.assertEqual(result['Configuration']['ReadAuthorization'],auth);task,_=self.begin();result=self.life.apply(task,'RevokeRead',{},{});self.life.finish(task)
        self.assertNotIn('ReadAuthorization',result['Configuration']);self.assertFalse(self.host.path(self.life.config+'/read-access.env').exists())

    def test_real_tls_verifies_trust_hostname_and_refuses_redirects(self):
        cfg=self.agent()
        payload={'schema_version':1,'maintenance_schema_version':1,'uuid':self.host.agent_uuid,'server_instance_id':self.host.server_uuid,'server_version':'0.1.0-rc.4'}
        class Handler(http.server.BaseHTTPRequestHandler):
            redirect=False
            def do_POST(inner):
                inner.rfile.read(int(inner.headers['Content-Length']))
                if inner.headers.get('User-Agent') != 'May-VPS-Deploy/May-Monitor':
                    inner.send_response(403);inner.end_headers();return
                if Handler.redirect:
                    inner.send_response(302);inner.send_header('Location','https://example.invalid/');inner.end_headers();return
                raw=json.dumps(payload).encode();inner.send_response(200);inner.send_header('Content-Length',str(len(raw)));inner.end_headers();inner.wfile.write(raw)
            def log_message(*args):pass
        with tempfile.TemporaryDirectory(prefix='may-tls-test-') as directory:
            cert=Path(directory)/'cert.pem';key=Path(directory)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            life=module.Lifecycle(self.host,'Agent');private={'AgentToken':'synthetic-old-agent-token'}
            try:
                candidate={'Endpoint':'https://localhost:'+str(server.server_port)}
                with self.assertRaises(ValueError):life.verify_agent_credential(dict(candidate),private)
                with patch.dict(os.environ,{'SSL_CERT_FILE':str(cert)}):
                    result=life.verify_agent_credential(dict(candidate),private);self.assertEqual(result['uuid'],self.host.agent_uuid)
                    with self.assertRaises(ValueError):life.verify_agent_credential({'Endpoint':'https://127.0.0.1:'+str(server.server_port)},private)
                    Handler.redirect=True
                    with self.assertRaises(ValueError):life.verify_agent_credential(dict(candidate),private)
            finally:server.shutdown();server.server_close();thread.join(3)

if __name__=='__main__':unittest.main(verbosity=2)
