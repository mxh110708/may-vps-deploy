"""Bounded loopback-only M5 observation; owns only processes and data it creates.

No production endpoints, host service changes, credential imports or proxy changes.
The normal run is at least 24 actual hours. A rehearsal never counts as acceptance.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import signal
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def port():
    with socket.socket() as value:value.bind(('127.0.0.1',0));return value.getsockname()[1]


class Fixture:
    def __init__(self,root,label,server,agent,count):
        self.root=root/label;self.root.mkdir(mode=0o700);self.label=label
        self.server_binary=server;self.agent_binary=agent;self.count=count
        self.origin=str(uuid.uuid4());self.setup=uuid.uuid4().hex+uuid.uuid4().hex;self.password='Fixture-Pass1-'+uuid.uuid4().hex
        self.api='http://127.0.0.1:'+str(port());self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));self.process=None;self.agents=[];self.previous={}
        self.env={k:v for k,v in os.environ.items() if not k.startswith('MAY_')};self.env.update(MAY_MONITOR_INSTANCE_ID=self.origin,MAY_MONITOR_SETUP_TOKEN=self.setup)
        try:
            self.start_server()
            self.request('/api/install/complete',{'username':'fixture','password':self.password,'sitename':'May M5 isolated fixture','metric_dsn':'./data/metrics.db'},{'X-May-Setup-Token':self.setup})
            # Initialization asynchronously replaces the install-only router.
            for attempt in range(150):
                try:
                    self.cookie='session_token='+self.request('/api/login',{'username':'fixture','password':self.password})['data']['set-cookie']['session_token'];break
                except urllib.error.HTTPError as error:
                    if error.code not in (404,503) or attempt==149:raise
                    time.sleep(.1)
                except OSError:
                    if attempt==149:raise
                    time.sleep(.1)
            self.request('/api/admin/settings/',{'geo_ip_enabled':False},{'Cookie':self.cookie})
            self.nodes=[]
            for number in range(count):
                value=self.request('/api/admin/client/add',{'name':'fixture-'+str(number)},{'Cookie':self.cookie});self.nodes.append(value.get('data',value))
            self.read='may_read_'+base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
            self.stop_server()
            self.env.update(MAY_MONITOR_READ_TOKEN_SHA256=hashlib.sha256(self.read.encode()).hexdigest(),MAY_MONITOR_READ_CLIENT_UUIDS=','.join(v['uuid'] for v in self.nodes),MAY_MONITOR_READ_EXPIRES_AT=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=2)).isoformat())
            self.start_server();self.start_agent(0)
        except Exception:
            self.close();raise

    def request(self,path,body=None,headers=None):
        raw=json.dumps(body).encode() if body is not None else None
        req=urllib.request.Request(self.api+path,raw,{'Content-Type':'application/json',**(headers or {})})
        with self.opener.open(req,timeout=10) as response:
            raw=response.read(1024*1024+1)
            if len(raw)>1024*1024:raise ValueError('oversized fixture response')
            return json.loads(raw)

    def ready(self):
        for _ in range(150):
            if self.process.poll() is not None:raise RuntimeError('fixture server exited')
            try:
                with self.opener.open(self.api+'/ping',timeout=3) as response:
                    if response.status==200 and response.read(32)==b'pong':return
            except (OSError,ValueError):pass
            try:
                if self.request('/api/install/status').get('data',{}).get('required'):return
            except (OSError,ValueError):pass
            time.sleep(.1)
        raise RuntimeError('fixture server readiness timeout')

    def start_server(self):
        with (self.root/'server.private.log').open('ab') as log:
            self.process=subprocess.Popen([str(self.server_binary),'server','--listen',self.api.removeprefix('http://')],cwd=self.root,env=self.env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        self.ready()

    @staticmethod
    def stop(process):
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=20)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

    def stop_server(self):self.stop(self.process)

    def start_agent(self,number):
        while len(self.agents)<=number:self.agents.append(None)
        directory=self.root/('agent-'+str(number));directory.mkdir(exist_ok=True,mode=0o700)
        config=directory/'config.private.json'
        config.write_text(json.dumps({'endpoint':self.api,'token':self.nodes[number]['token'],'interval':3,'info_report_interval':5,'reconnect_interval':5,'max_retries':-1,'disable_web_ssh':True,'disable_auto_update':True,'ignore_unsafe_cert':False,'month_rotate':1,'custom_ipv4':'127.0.0.1','custom_ipv6':'::1'}));config.chmod(0o600)
        with (directory/'agent.private.log').open('ab') as log:
            self.agents[number]=subprocess.Popen([str(self.agent_binary),'--config',str(config)],cwd=directory,env=self.env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        time.sleep(.2)
        if self.agents[number].poll() is not None:raise RuntimeError('fixture Agent failed to start')

    def resources(self,process):
        if process is None or process.poll() is not None:return {'running':False}
        try:
            raw=Path('/proc',str(process.pid),'stat').read_text().rsplit(')',1)[1].split()
            cpu=(int(raw[11])+int(raw[12]))/os.sysconf('SC_CLK_TCK');rss=int(raw[21])*os.sysconf('SC_PAGE_SIZE');now=time.monotonic()
            previous=self.previous.get(process.pid);self.previous[process.pid]=(now,cpu)
            return {'running':True,'rss_bytes':rss,'cpu_one_core_percent':None if previous is None else max(0,100*(cpu-previous[1])/(now-previous[0])),'threads':int(raw[17])}
        except (OSError,ValueError,IndexError):return {'running':False}

    def sample(self):
        started=sum(v is not None for v in self.agents)
        result={'label':self.label,'started_agents':started,'server':self.resources(self.process),'agents':[self.resources(v) for v in self.agents]}
        # Measure growing stores, not hundreds of extracted immutable web files
        # on every sample. Keep the observer's filesystem overhead bounded.
        stores=[*(self.root/'data').glob('*.db*'),*self.root.glob('agent-*/net_static.json')]
        result['data_bytes']=sum(v.stat().st_size for v in stores if v.is_file())
        try:
            snapshot=self.request('/api/integration/v1/snapshot',headers={'Authorization':'Bearer '+self.read})
            if snapshot['server_instance_id']!=self.origin:raise ValueError('wrong fixture origin')
            capture=datetime.datetime.fromisoformat(snapshot['captured_at'].replace('Z','+00:00'))
            nodes=[v for v in snapshot['nodes'] if v['uuid'] in {n['uuid'] for n in self.nodes[:started]}]
            ages=[(capture-datetime.datetime.fromisoformat(v['report_at'].replace('Z','+00:00'))).total_seconds() for v in nodes if v.get('report_at')]
            result.update(online=sum(v['online'] for v in nodes),fresh=sum(v['online'] and v.get('metrics') is not None and v.get('report_at') and 0<=(capture-datetime.datetime.fromisoformat(v['report_at'].replace('Z','+00:00'))).total_seconds()<=15 for v in nodes),max_report_age_seconds=max(ages,default=None))
        except (OSError,ValueError,KeyError,TypeError):result['read_error']=True
        return result

    def close(self):
        for process in self.agents:self.stop(process)
        self.stop_server()


def main():
    parser=argparse.ArgumentParser()
    for name in ('server-baseline','agent-baseline','server-candidate','agent-candidate','output'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--duration-seconds',type=int,default=86460);parser.add_argument('--agents',type=int,default=5);parser.add_argument('--sample-seconds',type=int,default=30);parser.add_argument('--rehearsal',action='store_true');args=parser.parse_args()
    if not 1<=args.agents<=10 or not 10<=args.sample_seconds<=60 or args.duration_seconds<30 or args.duration_seconds>90000 or not args.rehearsal and args.duration_seconds<86400:raise ValueError('invalid bounded observation parameters')
    root=args.output.resolve()
    if root.exists() or root.is_symlink():raise ValueError('observation requires a new private directory')
    root.mkdir(mode=0o700,parents=True)
    manifest={'schema':1,'status':'Starting','started_at':stamp(),'duration_seconds':args.duration_seconds,'rehearsal':args.rehearsal,'nodes_per_server':args.agents,'network':'loopback only','pid':os.getpid(),'artifacts':{}}
    for name in ('server_baseline','agent_baseline','server_candidate','agent_candidate'):
        file=getattr(args,name).resolve(strict=True);manifest['artifacts'][name]={'path':str(file),'bytes':file.stat().st_size,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
    status_file=root/'status.json'
    def save():
        temp=root/'status.json.tmp';temp.write_text(json.dumps(manifest,indent=2)+'\n');temp.replace(status_file)
    save();fixtures=[];began=time.monotonic();wall=time.time();samples=0;issues=0;largest_gap=0;previous=began;events=set();observed_fresh={'baseline':0,'candidate':0}
    def interrupted(*_):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,interrupted)
    try:
        fixtures.append(Fixture(root,'baseline',args.server_baseline.resolve(),args.agent_baseline.resolve(),args.agents))
        fixtures.append(Fixture(root,'candidate',args.server_candidate.resolve(),args.agent_candidate.resolve(),args.agents))
        manifest.update(status='Running',collection_started_at=stamp());save()
        expanded_at=20 if args.rehearsal else 3600
        restart_at=35 if args.rehearsal else 7200
        paused_at=50 if args.rehearsal else 10800
        restored_at=65 if args.rehearsal else 10845
        while time.monotonic()-began<args.duration_seconds:
            elapsed=time.monotonic()-began
            if elapsed>=expanded_at and 'multi' not in events:
                for fixture in fixtures:
                    for number in range(1,args.agents):fixture.start_agent(number)
                events.add('multi')
            if elapsed>=restart_at and 'restart' not in events:
                for fixture in fixtures:fixture.stop_server();fixture.start_server()
                events.add('restart')
            if elapsed>=paused_at and 'pause' not in events:
                for fixture in fixtures:fixture.stop(fixture.agents[0])
                events.add('pause')
            if elapsed>=restored_at and 'resume' not in events:
                for fixture in fixtures:fixture.start_agent(0)
                events.add('resume')
            now=time.monotonic();largest_gap=max(largest_gap,now-previous);previous=now
            rows=[fixture.sample() for fixture in fixtures]
            planned=(0<=elapsed-restart_at<90) or paused_at<=elapsed<restored_at+60 or elapsed<60 or 0<=elapsed-expanded_at<60
            for row in rows:
                if row.get('fresh',0)>0:observed_fresh[row['label']]+=1
                if not planned and (row.get('read_error') or row.get('fresh')!=row['started_agents'] or not row['server']['running']):issues+=1
            with (root/'samples.jsonl').open('a') as file:file.write(json.dumps({'at':stamp(),'elapsed_seconds':elapsed,'planned_transition':planned,'fixtures':rows})+'\n')
            samples+=1;manifest.update(samples=samples,last_sample_at=stamp(),elapsed_seconds=elapsed,unexpected_health_samples=issues,largest_sample_gap_seconds=largest_gap,events=sorted(events));save()
            time.sleep(min(args.sample_seconds,max(0,args.duration_seconds-(time.monotonic()-began))))
        met_duration=not args.rehearsal and time.monotonic()-began>=86400 and time.time()-wall>=86400
        manifest.update(status='Completed',finished_at=stamp(),elapsed_seconds=time.monotonic()-began,wall_seconds=time.time()-wall,met_24h_duration=met_duration,observed_fresh_samples=observed_fresh,acceptance='NeedsReview' if issues or largest_gap>3*args.sample_seconds or not met_duration or not all(observed_fresh.values()) else 'ReadyForReview')
    except Exception as error:
        manifest.update(status='Failed',failure_type=type(error).__name__,finished_at=stamp());raise
    finally:
        if manifest['status'] not in ('Completed','Failed'):manifest.update(status='Interrupted',finished_at=stamp())
        for fixture in fixtures:fixture.close()
        manifest['owned_processes_closed']=all(v.process.poll() is not None and all(a is None or a.poll() is not None for a in v.agents) for v in fixtures);save()

if __name__=='__main__':main()
