"""Real fixed-core loopback DNS, TCP preference/fallback and UDP no-replay.

No hosts file, system DNS, routes, proxy ownership, service or firewall changes.
"""
import argparse, contextlib, copy, json, os, shutil, socket, socketserver, struct, subprocess, tempfile, threading, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
class Dns(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request; cursor=12
        while data[cursor]: cursor+=data[cursor]+1
        cursor+=1; qtype=struct.unpack('!H',data[cursor:cursor+2])[0]
        address=self.server.addresses.get(qtype); question=data[12:cursor+4]
        answer=b'' if address is None else b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,0,len(address))+address
        sock.sendto(data[:2]+struct.pack('!HHHHH',0x8180,1,int(address is not None),0,0)+question+answer,self.client_address)
class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3); data=b''
        while b'\r\n\r\n' not in data and len(data)<8192: data+=self.request.recv(4096)
        body=(self.client_address[0] if self.server.label=='Source' else self.server.label).encode(); self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
class Tcp6(socketserver.ThreadingTCPServer): address_family=socket.AF_INET6
class Udp(socketserver.BaseRequestHandler):
    def handle(self): self.server.count+=1  # Deliberately silent: no application acknowledgement.
class Udp6(socketserver.ThreadingUDPServer): address_family=socket.AF_INET6
def serve(server):
    server.daemon_threads=True; thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def receive(s,count):
    out=b''
    while len(out)<count:
        data=s.recv(count-len(out))
        if not data:raise OSError('early SOCKS close')
        out+=data
    return out
def socks_header(host,portnum):
    if ':' in host: address=b'\x04'+socket.inet_pton(socket.AF_INET6,host)
    elif host[0].isdigit():address=b'\x01'+socket.inet_aton(host)
    else:
        value=host.encode();address=b'\x03'+bytes([len(value)])+value
    return address+struct.pack('!H',portnum)
def request(proxy,host,remote):
    with socket.create_connection(('127.0.0.1',proxy),3) as s:
        s.settimeout(5);s.sendall(b'\x05\x01\x00');assert receive(s,2)==b'\x05\x00'
        s.sendall(b'\x05\x01\x00'+socks_header(host,remote));head=receive(s,4)
        if head[1]:raise OSError('SOCKS rejected '+str(head[1]))
        size={1:4,4:16}.get(head[3]);receive(s,size if size else receive(s,1)[0]);receive(s,2)
        s.sendall(b'GET / HTTP/1.1\r\nHost: family.example.test\r\nConnection: close\r\n\r\n');out=b''
        while True:
            part=s.recv(4096)
            if not part:break
            out+=part
            if b'\r\n\r\n' in out:
                headers,body=out.split(b'\r\n\r\n',1)
                length=int(next(line.split(b':',1)[1] for line in headers.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                if len(body)>=length:break
        assert b'200 OK' in out;return out.split(b'\r\n\r\n',1)[1].decode()
def udp_once(proxy,remote):
    control=socket.create_connection(('127.0.0.1',proxy),3);control.settimeout(3)
    try:
        control.sendall(b'\x05\x01\x00');assert receive(control,2)==b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00');head=receive(control,4);assert head[1]==0
        if head[3]==1:host=socket.inet_ntop(socket.AF_INET,receive(control,4))
        elif head[3]==4:host=socket.inet_ntop(socket.AF_INET6,receive(control,16))
        else:raise AssertionError('unexpected UDP bind address')
        dest=struct.unpack('!H',receive(control,2))[0]
        if host in ('0.0.0.0','::'):host='127.0.0.1'
        with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.sendto(b'\x00\x00\x00'+socks_header('family.example.test',remote)+b'one-datagram',(host,dest));time.sleep(.8)
    finally:control.close()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--sing-box',required=True);parser.add_argument('--xray',required=True);parser.add_argument('--output',required=True);parser.add_argument('--test-dll',type=Path);args=parser.parse_args()
    dll=args.test_dll or ROOT/'desktop/May.VpsDeploy.Tests/bin/Release/net10.0/May.VpsDeploy.Tests.dll'
    fixtures=json.loads(subprocess.check_output(['dotnet',str(dll),str(ROOT),'--address-policy-fixtures'],text=True))
    servers=[];processes=[];proof=[];root=None;sslog=None
    try:
        dns=serve(socketserver.ThreadingUDPServer(('127.0.0.1',0),Dns));dns.addresses={1:socket.inet_aton('127.0.0.1'),28:socket.inet_pton(socket.AF_INET6,'::1')};servers.append(dns)
        four=serve(socketserver.ThreadingTCPServer(('127.0.0.1',0),Tcp));four.label='IPv4';servers.append(four);remote=four.server_address[1]
        six=serve(Tcp6(('::1',remote),Tcp));six.label='IPv6';servers.append(six)
        udp4=serve(socketserver.ThreadingUDPServer(('127.0.0.1',remote),Udp));udp4.count=0;servers.append(udp4)
        udp6=serve(Udp6(('::1',remote),Udp));udp6.count=0;servers.append(udp6)
        marked=serve(socketserver.ThreadingTCPServer(('127.0.0.1',0),Tcp));marked.label='Source';servers.append(marked)
        with contextlib.nullcontext(tempfile.mkdtemp(prefix='may-address44-')) as temporary:
            root=Path(temporary)
            ssport=port();ssconfig={'log':{'level':'error'},'inbounds':[{'type':'shadowsocks','tag':'in'+label,'listen':addr,'listen_port':ssport,'method':'aes-128-gcm','password':'synthetic-address44-password'} for label,addr in [('4','127.0.0.1'),('6','::1')]],'outbounds':[{'type':'direct','tag':'out'+label,'inet4_bind_address':address} for label,address in [('4','127.0.0.3'),('6','127.0.0.4')]],'route':{'rules':[{'inbound':['in'+label],'action':'route','outbound':'out'+label} for label in ['4','6']]}}
            ssfile=root/'peer.json';ssfile.write_text(json.dumps(ssconfig),encoding='utf-8');sslog=(root/'peer.log').open('wb');ssproc=subprocess.Popen([args.sing_box,'run','-c',str(ssfile)],cwd=root,stdout=sslog,stderr=sslog,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));processes.append(ssproc)
            for engine,exe in [('sing-box',args.sing_box),('xray',args.xray)]:
                for policy in fixtures:
                    for scenario in (['dual','failed-preferred','restart','proxy-dual','proxy-failed-preferred'] if policy.startswith('Prefer') else ['dual']):
                        print('CHECK',engine,policy,scenario,flush=True)
                        # An immediate TCP refusal in the preferred family must still
                        # reach the alternative, rather than just retry DNS ordering.
                        dead=policy=='PreferIPv4';failed=scenario.endswith('failed-preferred');via_proxy=scenario.startswith('proxy-')
                        dns.addresses={1:socket.inet_aton('127.0.0.2' if failed and dead else '127.0.0.1'),28:socket.inet_pton(socket.AF_INET6,'::2' if failed and not dead else '::1')}
                        local=port();out=copy.deepcopy(fixtures[policy][engine+('-proxy' if via_proxy else '')]);config={'log':{'level':'error'} if engine=='sing-box' else {'loglevel':'error'}}
                        if via_proxy:
                            if engine=='sing-box':out['server_port']=ssport
                            else:out['settings']['servers'][0]['port']=ssport
                        if engine=='sing-box':
                            config.update(dns={'servers':[{'type':'udp','tag':'local','server':'127.0.0.1','server_port':dns.server_address[1]}]},inbounds=[{'type':'mixed','listen':'127.0.0.1','listen_port':local}],outbounds=[out],route={'final':'egress','rules':[{'ip_version':6 if policy=='IPv4' else 4,'action':'reject'}] if policy in ('IPv4','IPv6') else []})
                        else:
                            config.update(dns={'servers':[{'address':'127.0.0.1','port':dns.server_address[1]}],'queryStrategy':'UseIP'},inbounds=[{'listen':'127.0.0.1','port':local,'protocol':'socks','tag':'qa-in','settings':{'auth':'noauth','udp':True}}],outbounds=[out,{'tag':'block','protocol':'blackhole'}],routing={'domainStrategy':'AsIs','rules':[{'type':'field','inboundTag':['qa-in'],'ip':['::/0' if policy=='IPv4' else '0.0.0.0/0'],'outboundTag':'block'}] if policy in ('IPv4','IPv6') else []})
                            # Production uses the OS-local resolver. This fixture
                            # substitutes a controlled UDP DNS server and routes
                            # only its tagged DNS traffic directly to avoid making
                            # name resolution depend on the unresolved SS peer.
                            config['dns']['tag']='qa-dns';config['outbounds'].append({'tag':'qa-resolver','protocol':'freedom','settings':{}})
                            config['routing']['rules'].insert(0,{'type':'field','inboundTag':['qa-dns'],'outboundTag':'qa-resolver'})
                        filename=root/(engine+'-'+policy+'-'+scenario+'.json');filename.write_text(json.dumps(config),encoding='utf-8');log=(root/(filename.stem+'.log')).open('wb')
                        cmd=[exe,'run','-c',str(filename)] if engine=='sing-box' else [exe,'run','-config',str(filename)]
                        child=subprocess.Popen(cmd,cwd=root,stdout=log,stderr=log,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));processes.append(child)
                        try:
                            deadline=time.monotonic()+7
                            while True:
                                if child.poll() is not None:raise AssertionError(filename.read_text()+'\n'+(root/(filename.stem+'.log')).read_text(errors='replace'))
                                try:
                                    with socket.create_connection(('127.0.0.1',local),.2):break
                                except OSError:
                                    if time.monotonic()>deadline:raise
                                    time.sleep(.04)
                            expected='IPv6' if policy in ('IPv6','PreferIPv6') else 'IPv4'
                            if failed:expected='IPv4' if expected=='IPv6' else 'IPv6'
                            if via_proxy:expected='127.0.0.3' if expected=='IPv4' else '127.0.0.4'
                            actual=request(local,'127.0.0.1' if policy=='Auto' or via_proxy else 'family.example.test',marked.server_address[1] if via_proxy else remote)
                            if policy!='Auto':assert actual==expected,(engine,policy,scenario,actual,expected)
                            if policy.startswith('Prefer') and not via_proxy:
                                assert request(local,'127.0.0.1',remote)=='IPv4';assert request(local,'::1',remote)=='IPv6'
                                if scenario=='dual':
                                    before=udp4.count+udp6.count;udp_once(local,remote);assert udp4.count+udp6.count-before==1,'silent UDP was lost or replayed to second family'
                            if policy in ('IPv4','IPv6'):
                                refused=False
                                try:request(local,'::1' if policy=='IPv4' else '127.0.0.1',remote)
                                except OSError:refused=True
                                assert refused,'strict policy accepted opposite explicit IP'
                            proof.append({'engine':engine,'policy':policy,'scenario':scenario,'observed':actual,'passed':True})
                        except Exception:
                            log.flush();print((root/(filename.stem+'.log')).read_text(errors='replace'),flush=True);raise
                        finally:
                            child.terminate();child.wait(timeout=6);log.close()
            ssproc.terminate();ssproc.wait(timeout=5);sslog.close()
        Path(args.output).write_text(json.dumps({'passed':True,'cases':proof,'ownedProcessesStopped':all(p.poll() is not None for p in processes),'scope':'loopback only; no public WAN or production migration'},indent=2),encoding='utf-8')
        print('PASS:',len(proof),'fixed-core DNS, TCP preference, failed-preferred fallback, explicit IP and restart cases')
    finally:
        for p in processes:
            if p.poll() is None:p.kill();p.wait(timeout=5)
        if sslog:sslog.close()
        for server in servers:server.shutdown();server.server_close()
        if root is not None and root.exists():
            assert root.resolve().parent==Path(tempfile.gettempdir()).resolve() and root.name.startswith('may-address44-')
            shutil.rmtree(root)
if __name__=='__main__':main()
