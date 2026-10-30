"""Controlled loopback HTTPS origin; no operating-system trust changes."""
import http.server
import ssl
import sys
import time

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'198.51.100.22'
        print('REQUEST',flush=True)
        if self.path == '/stream':
            self.send_response(200);self.send_header('Content-Length',str(18*4096));self.end_headers()
            try:
                for _ in range(18):
                    self.wfile.write(b'x'*4096);self.wfile.flush();time.sleep(1)
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
            return
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(sys.argv[1],sys.argv[2])
server.socket=context.wrap_socket(server.socket,server_side=True)
print(server.server_address[1],flush=True)
server.serve_forever()
