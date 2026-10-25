"""Private CA HTTPS fixture, loopback only. No global certificate installation."""
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import socketserver
import sys

settings=json.loads(Path(sys.argv[3]).read_text(encoding='utf-8-sig'))
hits=Path(sys.argv[4]); requests=0

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global requests
        if self.path!='/api/integration/v1/snapshot' or self.headers.get('Authorization')!='Bearer '+settings['Token']:
            self.send_error(401); return
        requests+=1; hits.write_text(json.dumps({'Requests':requests}))
        now=datetime.datetime.now(datetime.timezone.utc).isoformat()
        body=json.dumps({'schema_version':1,'server_version':'0.1.0-rc.3','server_instance_id':settings['Origin'],'captured_at':now,'nodes':[{'uuid':settings['Node'],'online':True,'report_at':now,'metrics':{'cpu_percent':3.5,'memory_used':128,'memory_total':1024,'upload_per_sec':1,'download_per_sec':2,'upload_total':3,'download_total':4}}]}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass

class FixtureServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer's default reverse lookup can stall on macOS runners. This
        # fixture binds only a literal loopback address and needs no DNS at all.
        socketserver.TCPServer.server_bind(self)
        self.server_name='localhost'
        self.server_port=self.server_address[1]

with FixtureServer(('127.0.0.1',0),Handler) as server:
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(sys.argv[1],sys.argv[2]);server.socket=context.wrap_socket(server.socket,server_side=True)
    print(server.server_port,flush=True);server.serve_forever(poll_interval=.1)
