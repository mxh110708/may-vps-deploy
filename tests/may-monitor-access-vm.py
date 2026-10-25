"""Round 14 real systemd verification; disposable marker and DMI are mandatory."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid

BASE = Path('/opt/may-round14')
checks = []

def require(value, label):
    if not value: raise AssertionError(label)
    checks.append(label)

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-id',required=True); parser.add_argument('--stage',choices=('before-reboot','after-reboot'),required=True); args = parser.parse_args()
    require(os.geteuid()==0 and Path('/etc/may-round14-fixture').read_text().strip()==args.fixture_id and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==args.fixture_id,'disposable-marker-and-DMI')
    driver = load('current',BASE/'scripts/may-monitor-lifecycle.py'); host = driver.Host(); server = driver.Lifecycle(host,'Server'); agent = driver.Lifecycle(host,'Agent')
    source = (BASE/'scripts/may-monitor-lifecycle.py').read_text(); assets = json.loads((BASE/'assets.json').read_text())
    saved_file = BASE/'state.private.json'
    def change(life,action,config=None,secrets=None,artifact=None,commit=True,program=source):
        task=uuid.uuid4().hex; life.begin(task,life.inspect()['Hash'],program)
        spec=assets[artifact] if artifact else None
        if artifact: shutil.copyfile(BASE/artifact,life.backup_path(task)/'artifact')
        result=life.apply(task,action,config or {},secrets or {},spec)
        if commit: life.finish(task)
        return task,result
    if args.stage=='after-reboot':
        saved=json.loads(saved_file.read_text()); require(server.inspect()['Configuration']['InstanceId']==saved['origin'] and server.inspect()['Active'] and agent.inspect()['Active'],'stable-identity-and-services-after-reboot')
        proof=agent.verify_agent(agent.inspect()['Hash']); require(proof['ServerInstanceId']==saved['origin'],'credential-origin-after-reboot')
        print(json.dumps({'stage':args.stage,'checks':checks})); return
    legacy=load('previous',BASE/'legacy-driver.py'); old_server=legacy.Lifecycle(legacy.Host(),'Server'); old_agent=legacy.Lifecycle(legacy.Host(),'Agent')
    old_source=(BASE/'legacy-driver.py').read_text()
    sentinel=Path('/var/lib/komari-round14-sentinel'); sentinel.write_text('retained')
    unit=Path('/etc/systemd/system/komari-round14-sentinel.service'); unit.write_text('[Unit]\nDescription=Isolated previous monitor stand-in\n[Service]\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n')
    host.run(['systemctl','daemon-reload']); host.run(['systemctl','enable','--now',unit.name]); pid=host.run(['systemctl','show',unit.name,'-p','MainPID','--value']).stdout.strip(); unit_hash=driver.digest(unit)
    with socket.socket() as listener: listener.bind(('127.0.0.1',0)); config={'Port':listener.getsockname()[1],'Username':'fixture'}
    secrets={'SetupToken':'fixture-'+uuid.uuid4().hex,'AdminPassword':'Fixture-Pass1-'+uuid.uuid4().hex}
    change(old_server,'Install',dict(config),secrets,'server-rc2.tar.gz',program=old_source)
    require(not old_server.inspect()['Configuration'].get('InstanceId'),'actual-prior-driver-has-no-origin-id')
    api='http://127.0.0.1:'+str(config['Port']); opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(path,body=None,headers=None):
        req=urllib.request.Request(api+path,driver.canonical(body) if body is not None else None,{'Content-Type':'application/json',**(headers or {})})
        with opener.open(req,timeout=15) as response: return json.load(response)
    login=request('/api/login',{'username':'fixture','password':secrets['AdminPassword']}); cookie='session_token='+login['data']['set-cookie']['session_token']
    node=request('/api/admin/client/add',{'name':'pilot-fixture'},{'Cookie':cookie}); node=node.get('data',node)
    change(old_agent,'Install',{'Endpoint':api},{'AgentToken':node['token']},'agent-rc1',program=old_source)
    agent_hash=agent.inspect()['Hash']; agent_files={name:driver.digest(host.path(name)) for name in agent.files if host.path(name).exists()}
    read_token='may_read_'+base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    import datetime
    authorization={'Sha256':hashlib.sha256(read_token.encode()).hexdigest(),'Clients':[node['uuid']],'ExpiresAt':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=1)).isoformat()}
    change(old_server,'ConfigureRead',{'ReadAuthorization':authorization},program=old_source)
    change(server,'Upgrade',dict(config),secrets,'server-rc3.tar.gz')
    origin=server.inspect()['Configuration']['InstanceId']; require(str(uuid.UUID(origin))==origin,'upgrade-establishes-installation-id')
    proof=agent.verify_agent(agent_hash)
    require(proof['ClientUUID']==node['uuid'] and proof['ServerInstanceId']==origin,'existing-agent-credential-proves-node-and-new-origin')
    require('token' not in proof and 'AgentToken' not in proof and node['token'] not in json.dumps(proof),'credential-proof-does-not-return-token')
    require(agent_files=={name:driver.digest(host.path(name)) for name in agent.files if host.path(name).exists()},'existing-agent-files-not-rewritten')
    def snapshot(): return request('/api/integration/v1/snapshot',headers={'Authorization':'Bearer '+read_token})
    for _ in range(30):
        snap=snapshot()
        if snap['nodes'] and snap['nodes'][0]['online'] and snap['nodes'][0]['metrics']: break
        time.sleep(1)
    require(snap['server_instance_id']==origin and snap['nodes'][0]['uuid']==node['uuid'],'authenticated-snapshot-matches-owned-origin')
    reports=set()
    for _ in range(3):
        snap=snapshot(); reports.add(snap['nodes'][0]['report_at']); require(snap['server_instance_id']==origin and snap['nodes'][0]['online'],'live-sample-origin-and-online'); time.sleep(3)
    require(len(reports)>1,'real-report-timestamps-advance')
    backup=uuid.uuid4().hex; server.begin(backup,server.inspect()['Hash'],source); snapshot_hash=server.transaction(backup)[1]['BackupSha256']; server.finish(backup)
    task,_=change(server,'Disable',commit=False); server.finish(task,True); require(server.inspect()['Configuration']['InstanceId']==origin and server.inspect()['Active'],'cancel-preserves-origin-and-running-state')
    change(server,'Restore',{'RestoreTask':backup,'RestoreSha256':snapshot_hash}); require(server.inspect()['Configuration']['InstanceId']==origin,'component-restore-preserves-origin')
    require(driver.digest(unit)==unit_hash and sentinel.read_text()=='retained' and host.run(['systemctl','show',unit.name,'-p','MainPID','--value']).stdout.strip()==pid,'legacy-monitor-files-and-process-untouched')
    saved_file.write_text(json.dumps({'origin':origin})); saved_file.chmod(0o600)
    print(json.dumps({'stage':args.stage,'checks':checks}))

if __name__=='__main__': main()
