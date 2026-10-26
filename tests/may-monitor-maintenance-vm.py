"""M4/M5 real services, only inside a disposable VM with matching marker and DMI."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid

BASE=Path('/opt/may-m4m5')
checks=[]
def require(value,label):
    if not value:raise AssertionError(label)
    checks.append(label)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fixture-id',required=True);parser.add_argument('--stage',choices=('before-reboot','after-reboot'),required=True);args=parser.parse_args()
    require(os.geteuid()==0 and Path('/etc/may-m4m5-fixture').read_text().strip()==args.fixture_id and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==args.fixture_id,'disposable-marker-and-DMI')
    spec=importlib.util.spec_from_file_location('lifecycle',BASE/'scripts/may-monitor-lifecycle.py');driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
    host=driver.Host();server=driver.Lifecycle(host,'Server');agent=driver.Lifecycle(host,'Agent');source=(BASE/'scripts/may-monitor-lifecycle.py').read_text();assets=json.loads((BASE/'assets.json').read_text())
    saved_file=BASE/'state.private.json'
    if args.stage=='after-reboot':
        saved=json.loads(saved_file.read_text());require(server.inspect()['Configuration']['InstanceId']==saved['origin'] and server.inspect()['Active'] and agent.inspect()['Active'],'managed-services-and-identity-after-reboot')
        cfg=agent.inspect()['Configuration'];private=host.read_json(host.path(agent.config+'/config.json'));agent.wait_agent_reports(cfg,private['token']);require(True,'genuine-advancing-reports-after-reboot');print(json.dumps({'stage':args.stage,'checks':checks}));return
    def change(life,action,config=None,secrets=None,artifact=None,commit=True):
        task=uuid.uuid4().hex;life.begin(task,life.inspect()['Hash'],source)
        if artifact:shutil.copyfile(BASE/artifact,life.backup_path(task)/'artifact')
        result=life.apply(task,action,config or {},secrets or {},assets[artifact] if artifact else None)
        if commit:life.finish(task)
        return task,result
    sentinel=Path('/var/lib/may-m4m5-unrelated');sentinel.write_text('retained')
    with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    secrets={'SetupToken':uuid.uuid4().hex+uuid.uuid4().hex,'AdminPassword':'Fixture-Pass1-'+uuid.uuid4().hex}
    change(server,'Install',{'Port':port,'Username':'fixture'},secrets,'server.tar.gz')
    origin=server.inspect()['Configuration']['InstanceId'];api='http://127.0.0.1:'+str(port);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(path,body=None,headers=None):
        req=urllib.request.Request(api+path,driver.canonical(body) if body is not None else None,{'Content-Type':'application/json',**(headers or {})})
        with opener.open(req,timeout=15) as response:return json.load(response)
    cookie='session_token='+request('/api/login',{'username':'fixture','password':secrets['AdminPassword']})['data']['set-cookie']['session_token']
    node=request('/api/admin/client/add',{'name':'m4-fixture'},{'Cookie':cookie});node=node.get('data',node)
    change(agent,'Install',{'Endpoint':api},{'AgentToken':node['token']},'agent')
    config={'Endpoint':'http://localhost:'+str(port),'ClientUUID':node['uuid'],'ServerInstanceId':origin,'ReplaceToken':False}
    original_binary=driver.digest(host.path(agent.binary));original_unit=driver.digest(host.path('/etc/systemd/system/'+agent.unit))
    _,changed=change(agent,'ConfigureAgent',config)
    require(changed['ConnectionVerification']['Status']=='Verified' and changed['Configuration']['ClientUUID']==node['uuid'],'endpoint-change-genuine-new-reports-same-node')
    require(driver.digest(host.path(agent.binary))==original_binary and driver.digest(host.path('/etc/systemd/system/'+agent.unit))==original_unit,'configure-keeps-version-binary-and-unit')
    before=agent.inspect()['Hash'];bad=dict(config,ReplaceToken=True,ServerInstanceId=str(uuid.uuid4()))
    try:agent.candidate_agent(bad,{'AgentToken':node['token']},agent.inspect())
    except ValueError:pass
    else:raise AssertionError('wrong server accepted')
    require(agent.inspect()['Hash']==before and agent.inspect()['Active'],'wrong-origin-does-not-stop-or-write')
    try:agent.candidate_agent(dict(config,ReplaceToken=True),{'AgentToken':'fixture-invalid-token'},agent.inspect())
    except ValueError:pass
    else:raise AssertionError('wrong token accepted')
    require(agent.inspect()['Hash']==before,'wrong-token-does-not-write')
    def rotate():
        token='fixture-'+uuid.uuid4().hex;request('/api/admin/client/'+node['uuid']+'/edit',{'token':token},{'Cookie':cookie});return token
    fresh=rotate();config['ReplaceToken']=True
    _,changed=change(agent,'ConfigureAgent',config,{'AgentToken':fresh})
    require(changed['ConnectionVerification']['Status']=='Verified','revoked-old-token-rotation-succeeds')
    current=rotate();pending,_=change(agent,'ConfigureAgent',config,{'AgentToken':current},commit=False)
    replacement=rotate() # external credential change makes both old files and new connection invalid
    try:agent.finish(pending,True)
    except ValueError:pass
    else:raise AssertionError('revoked rollback falsely accepted')
    require(agent.transaction(pending)[1]['Phase']=='CredentialRecoveryRequired' and host.path(driver.OWNER).exists(),'revoked-old-token-remains-needs-recovery')
    repaired=agent.apply(pending,'ConfigureAgent',config,{'AgentToken':replacement},repair_expected=agent.inspect()['Hash']);agent.finish(pending)
    require(repaired['ConnectionVerification']['Status']=='Verified' and not host.path(driver.OWNER).exists(),'explicit-repair-verifies-and-commits-original-transaction')
    read='may_read_'+base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    authorization={'Sha256':hashlib.sha256(read.encode()).hexdigest(),'Clients':[node['uuid']],'ExpiresAt':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=1)).isoformat()}
    change(server,'ConfigureRead',{'ReadAuthorization':authorization})
    agent.wait_agent_reports(agent.inspect()['Configuration'],replacement)
    snap=request('/api/integration/v1/snapshot',headers={'Authorization':'Bearer '+read});require(snap['nodes'][0]['online'] and snap['nodes'][0]['metrics'] is not None,'server-restart-reconnect-and-scoped-read')
    change(server,'RevokeRead')
    try:request('/api/integration/v1/snapshot',headers={'Authorization':'Bearer '+read})
    except urllib.error.HTTPError as error:require(error.code==401,'read-revoked-credential-refused')
    else:raise AssertionError('read revocation ineffective')
    task,_=change(agent,'Disable',commit=False);agent.finish(task,True);agent.wait_agent_reports(agent.inspect()['Configuration'],replacement)
    require(agent.inspect()['Active'],'cancel-returns-to-genuine-reporting')
    cfg=host.read_json(host.path(agent.config+'/config.json'));require(cfg['disable_web_ssh'] and cfg['disable_auto_update'] and not cfg['ignore_unsafe_cert'],'capabilities-and-tls-policy-stay-restricted')
    require(sentinel.read_text()=='retained','unrelated-scope-retained')
    saved_file.write_text(json.dumps({'origin':origin}));saved_file.chmod(0o600)
    print(json.dumps({'stage':args.stage,'checks':checks}))

if __name__=='__main__':main()
