"""Bounded local M6 acceptance with real Server/Agent binaries and a loopback receiver.
No production services, credential imports, proxy switches or external notification channel.
"""
from pathlib import Path
import argparse
import copy,datetime,importlib.util,json,os,shutil,subprocess,threading,time,urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

parser=argparse.ArgumentParser()
parser.add_argument('--server',required=True,type=Path);parser.add_argument('--agent',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
args=parser.parse_args();work=args.output.resolve();work.mkdir(mode=0o700,parents=True)
server_binary=args.server.resolve(strict=True);agent_binary=args.agent.resolve(strict=True)
spec=importlib.util.spec_from_file_location('observation',Path(__file__).with_name('observe_may_monitor.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
binary=work/'server';shutil.copy2(server_binary,binary);binary.chmod(0o755)
fixture=None;watchdog=None;servers=[];checks={};rows=[];guard=threading.Lock();slow=False;reject=False
class Target(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        if slow:time.sleep(1.1)
        self.send_response(200);self.end_headers()
class Receiver(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        raw=self.rfile.read(min(int(self.headers.get('Content-Length','0')),65536));event=json.loads(raw)
        if event['id']!=self.headers.get('X-May-Event-ID'):raise RuntimeError('event identity absent')
        with guard:rows.append({'event':event,'at':time.monotonic()})
        self.send_response(503 if reject else 202);self.end_headers()
def server(handler):
    value=ThreadingHTTPServer(('127.0.0.1',0),handler);servers.append(value);threading.Thread(target=value.serve_forever,daemon=True).start();return 'http://127.0.0.1:'+str(value.server_address[1])
def wait(check,seconds=100,label='condition'):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if check():return
        time.sleep(.5)
    raise RuntimeError('fixture did not reach '+label)
def rpc(method,params=None,expected_error=False,headers=None):
    try:result=fixture.request('/api/rpc2',{'jsonrpc':'2.0','id':1,'method':method,'params':params or {}},headers if headers is not None else {'Cookie':fixture.cookie})
    except urllib.error.HTTPError as failure:
        if expected_error and failure.code in (401,403):return None
        raise
    if expected_error:
        if 'error' not in result:raise RuntimeError('invalid RPC was accepted')
    elif 'error' in result:raise RuntimeError('fixture RPC failed: '+method)
    return result.get('result',result)
def status():return rpc('admin:getMonitoring')
def state(rule='quality'):
    return next((v for v in status()['states'] if v['rule_id']==rule),{})
def events(rule):
    with guard:return [v['event'] for v in rows if v['event']['rule_id']==rule]
try:
    target=server(Target);receiver=server(Receiver)
    fixture=module.Fixture(work,'fixture',binary,agent_binary,2)
    node=fixture.nodes[0]['uuid'];other=fixture.nodes[1]['uuid']
    rpc('admin:editSettings',{'eula_accepted':True})
    probes={}
    for kind,value in [('http',target+'/quality'),('tcp',target.removeprefix('http://')),('icmp','127.0.0.1')]:
        probes[kind]=rpc('admin:addPingTask',{'clients':[node],'default_on':False,'name':'Local '+kind.upper(),'target':value,'type':kind,'interval':10})['task_id']
    def evidence(kind):return rpc('admin:getProbeStatus',{'node':node,'task_id':probes[kind]})
    wait(lambda:all(evidence(k).get('samples') for k in probes),45,'three actual probe types')
    checks['actual_tcp_http_success']=all(evidence(k)['samples'][-1]['status']=='ok' for k in ['http','tcp'])
    icmp=evidence('icmp')['samples'][-1]['status'];checks['actual_icmp_status']=icmp
    if icmp not in ('ok','permission_denied'):raise RuntimeError('loopback ICMP produced an unexpected result')
    rule={'id':'quality','name':'Local HTTP quality','enabled':True,'kind':'latency','nodes':[node],'task_id':probes['http'],'region':'Local fixture','threshold':500,'confirm':2,'recover':2,'window':3,'cooldown_seconds':0}
    policy={'schema':1,'enabled':True,'local_receiver':receiver+'/events','rules':[rule]}
    bad=copy.deepcopy(policy);bad['local_receiver']='https://external.example/events';rpc('admin:setMonitoring',bad,True);checks['external_receiver_rejected']=True
    rpc('admin:setMonitoring',policy)
    slow=True
    wait(lambda:state().get('delivery')=='sent',70,'high-latency notification')
    sample=evidence('http')['samples'][-1]
    if sample['status']!='ok' or sample['value']<1000:raise RuntimeError('high latency became failure or lost its measured value')
    if len(events('quality'))!=1:raise RuntimeError('duplicate incident notification')
    checks['high_latency_retained_and_confirmed']=True
    rule['silence_until']=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat();rpc('admin:setMonitoring',policy);slow=False
    wait(lambda:state().get('phase')=='healthy',65,'silenced recovery')
    if len(events('quality'))!=1:raise RuntimeError('silenced recovery was sent')
    rule.pop('silence_until');rpc('admin:setMonitoring',policy)
    wait(lambda:any(v['kind']=='recovered' for v in events('quality')),25,'recovery after silence')
    checks['maintenance_silence_and_recovery']=True
    rule['confirm']=1;rpc('admin:setMonitoring',policy);reject=True;slow=True
    wait(lambda:state().get('delivery')=='failed',95,'bounded failed delivery')
    attempts=[v for v in events('quality') if v['kind']=='firing'];last_id=attempts[-1]['id']
    if sum(v['id']==last_id for v in attempts)!=3:raise RuntimeError('delivery retry count was not three')
    checks['failed_delivery_retries']=3
    before=len(events('quality'));fixture.stop_server();fixture.start_server();time.sleep(20)
    if state().get('delivery')!='failed' or len(events('quality'))!=before:raise RuntimeError('restart duplicated an exhausted incident')
    checks['restart_preserves_exhausted_incident']=True
    reject=False;slow=False
    old=evidence('http')['revision'];all_tasks=rpc('admin:getAllPingTasks');edited=next(v for v in all_tasks if v['id']==probes['http']);edited['target']=target+'/quality?revision=2';rpc('admin:editPingTask',{'tasks':[edited]})
    payload={'jsonrpc':'2.0','id':1,'method':'agent.pingResult','params':{'task_id':probes['http'],'ping_type':'http','value':2,'status':'ok','revision':old}}
    try:result=fixture.request('/api/clients/v2/rpc',payload,{'X-May-Agent-Token':fixture.nodes[0]['token']})
    except urllib.error.HTTPError as failure:
        if failure.code not in (400,404):raise
        if failure.code==404:raise RuntimeError('verify actual structured report path before acceptance')
    else:
        if 'error' not in result:raise RuntimeError('old probe revision was accepted')
    checks['old_probe_revision_rejected']=True
    snapshot=fixture.request('/api/integration/v1/snapshot',headers={'Authorization':'Bearer '+fixture.read})
    if any(key in json.dumps(snapshot) for key in ['local_receiver','rule_name','silence_until']):raise RuntimeError('scoped snapshot disclosed policy details')
    if 'credential_expires_at' not in snapshot or 'alerts' not in snapshot['nodes'][0]:raise RuntimeError('daily-use snapshot extension missing')
    checks['scoped_alert_counts_and_expiry']=True
    rpc('admin:getMonitoring',headers={'Authorization':'Bearer '+fixture.read},expected_error=True)
    checks['read_token_cannot_administer']=True
    directory=work/'watchdog';directory.mkdir(mode=0o700)
    cfg=directory/'config.json';cfg.write_text(json.dumps({'endpoint':fixture.api,'server_instance_id':fixture.origin,'local_receiver':receiver+'/events','interval_seconds':10,'confirm':2,'recover':1}));cfg.chmod(0o600)
    env={**fixture.env,'MAY_MONITOR_WATCHDOG_READ_TOKEN':fixture.read}
    with (directory/'watchdog.private.log').open('wb') as log:watchdog=subprocess.Popen([str(binary),'watchdog','--config',str(cfg),'--state',str(directory/'state.json')],cwd=directory,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
    def watch_state():
        try:return json.loads((directory/'state.json').read_text())
        except (OSError,ValueError):return {}
    wait(lambda:watch_state().get('armed') is True,20,'independent healthy baseline')
    fixture.stop_server();wait(lambda:any(v['kind']=='firing' for v in events('server_liveness')),40,'independent Server outage')
    fixture.start_server();wait(lambda:any(v['kind']=='recovered' for v in events('server_liveness')),25,'independent Server recovery')
    checks['independent_process_server_loss_and_recovery']=True
    # A private site is enforced separately from the scoped integration token.
    rpc('admin:editSettings',{'private_site':True})
    rpc('common:getNodes',headers={},expected_error=True)
    checks['private_site_not_anonymous']=True
    checks['all']=all(value for value in checks.values());print(json.dumps(checks))
finally:
    if watchdog is not None:module.Fixture.stop(watchdog)
    if fixture is not None:fixture.close()
    for value in servers:value.shutdown();value.server_close()
    checks['owned_processes_closed']=watchdog is None or watchdog.poll() is not None
    if fixture is not None:checks['owned_processes_closed']=checks['owned_processes_closed'] and fixture.process.poll() is not None and all(p is None or p.poll() is not None for p in fixture.agents)
    (work/'checks.json').write_text(json.dumps(checks,indent=2))
