"""Bounded loopback fixture channel across the Windows/WSL boundary.

Datagrams retain Hysteria2's real QUIC/TLS/authentication. Only the host-side
fixture hop is framed over TCP; the guest still receives actual UDP packets.
No production endpoints, host routing rules or firewall changes are accepted.
"""
import hmac
import json
import select
import socket
import socketserver
import threading

def start(manifest):
    if not manifest.get('SyntheticOnly') or manifest.get('Name')!='Inbound': raise ValueError('Synthetic fixture required.')
    limit=threading.BoundedSemaphore(8)
    class Handler(socketserver.StreamRequestHandler):
        rbufsize=0
        def readn(self,size):
            result=b''
            while len(result)<size:
                chunk=self.rfile.read(size-len(result))
                if not chunk:return result
                result+=chunk
            return result
        def handle(self):
            self.request.settimeout(15)
            self.request.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            try:
                claim=json.loads(self.rfile.readline(512))
                if not hmac.compare_digest(claim.get('Token',''),manifest['DatagramTunnelToken']) or str(claim.get('Port','')) not in manifest['UdpApplications']: return
                with socket.socket(type=socket.SOCK_DGRAM) as udp:
                    udp.connect((manifest['UdpAddress'],manifest['UdpApplications'][str(claim['Port'])]))
                    while True:
                        readable,_,_=select.select([self.request,udp],[],[],15)
                        if not readable: return
                        if self.request in readable:
                            header=self.readn(2)
                            if len(header)!=2:return
                            size=int.from_bytes(header,'big')
                            if not 0<size<=65507:return
                            data=self.readn(size)
                            if len(data)!=size:return
                            udp.send(data)
                        if udp in readable:
                            data=udp.recv(65507);self.request.sendall(len(data).to_bytes(2,'big')+data)
            except (OSError,ValueError,KeyError):pass
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads=True
        allow_reuse_address=False
        def process_request(self,request,address):
            if not limit.acquire(blocking=False):request.close();return
            super().process_request(request,address)
        def process_request_thread(self,request,address):
            try:super().process_request_thread(request,address)
            finally:limit.release()
    server=Server(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server
