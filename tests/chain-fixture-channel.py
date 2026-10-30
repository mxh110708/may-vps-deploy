"""Synthetic controller ingress over SSH; not a product tunnel or fallback.

WSL only mirrors TCP to Windows. This channel carries still-encrypted QUIC
datagrams to a socket on the marker-checked front guest. Both forwarding hops
remain real UDP over the selected isolated IPv4/IPv6 guest NICs.
"""
import hmac
import ipaddress
import json
import select
import shlex
import socketserver
import subprocess
import threading


def start(ssh, address, token):
    address=str(ipaddress.ip_address(address))
    program="""import os,select,socket,sys
def readn(fd,n):
 b=b''
 while len(b)<n:
  p=os.read(fd,n-len(b))
  if not p:raise EOFError()
  b+=p
 return b
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM)
s.connect((sys.argv[1],18443))
try:
 while True:
  ready,_,_=select.select([0,s],[],[],15)
  if not ready:break
  if 0 in ready:
   h=readn(0,2);n=int.from_bytes(h,'big')
   if not 0<n<=65507:break
   s.send(readn(0,n))
  if s in ready:
   data=s.recv(65507);sys.stdout.buffer.write(len(data).to_bytes(2,'big')+data);sys.stdout.buffer.flush()
except (OSError,EOFError):pass
finally:s.close()
"""
    command=ssh+['python3 -c '+shlex.quote(program)+' '+shlex.quote(address)]
    limit=threading.BoundedSemaphore(8)
    children=set();lock=threading.Lock()
    class Handler(socketserver.StreamRequestHandler):
        rbufsize=0
        def readn(self,fd,size):
            value=b''
            while len(value)<size:
                p=fd.read(size-len(value))
                if not p:raise EOFError()
                value+=p
            return value
        def handle(self):
            self.request.settimeout(15);p=None
            try:
                claim=json.loads(self.rfile.readline(512))
                if not hmac.compare_digest(claim.get('Token',''),token) or claim.get('Port')!=18443:return
                p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
                with lock:children.add(p)
                while True:
                    ready,_,_=select.select([self.request,p.stdout],[],[],15)
                    if not ready:return
                    for source in ready:
                        reader=self.rfile if source is self.request else p.stdout
                        h=self.readn(reader,2);n=int.from_bytes(h,'big')
                        if not 0<n<=65507:return
                        data=self.readn(reader,n)
                        if source is self.request:p.stdin.write(h+data);p.stdin.flush()
                        else:self.request.sendall(h+data)
            except (OSError,ValueError,EOFError):pass
            finally:
                if p:
                    p.terminate()
                    try:p.wait(5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(5)
                    with lock:children.discard(p)
        def finish(self):
            try:super().finish()
            except OSError:pass
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads=True
        def process_request(self,request,address):
            if not limit.acquire(blocking=False):request.close();return
            super().process_request(request,address)
        def process_request_thread(self,request,address):
            try:super().process_request_thread(request,address)
            finally:limit.release()
        def server_close(self):
            super().server_close()
            with lock:pending=list(children)
            for p in pending:
                p.terminate()
                try:p.wait(5)
                except subprocess.TimeoutExpired:p.kill();p.wait(5)
    server=Server(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server
