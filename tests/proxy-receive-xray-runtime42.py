"""Pinned Xray VLESS/TLS target: real authentication and observed original IP.

Only private, explicitly marked process fixtures and ephemeral loopback ports;
no service, system trust, firewall or client application changes.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import threading
import time
import uuid
import zipfile

PROJECT = Path(__file__).resolve().parents[1]


def exact(peer, size):
    data = bytearray()
    while len(data) < size:
        value = peer.recv(size-len(data))
        if not value: raise AssertionError('Truncated authenticated proxy response')
        data.extend(value)
    return bytes(data)


def port():
    with socket.socket() as peer: peer.bind(('127.0.0.1', 0)); return peer.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture-root', required=True); parser.add_argument('--core-archive', required=True); args = parser.parse_args()
    root = Path(args.fixture_root).resolve(); marker = root/'qa-process-fixture.json'
    if not re.fullmatch(r'may-proxy42-process-[a-f0-9]{32}', root.name) or not marker.is_file() or marker.is_symlink() or json.loads(marker.read_text()) != dict(SyntheticOnly=True, Id=root.name.removeprefix('may-proxy42-process-')):
        raise RuntimeError('Explicit isolated process fixture identity required')
    versions = json.loads((PROJECT/'config/versions.json').read_text()); archive = Path(args.core_archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == versions['xray']['assets']['amd64']['sha256']
    with zipfile.ZipFile(archive) as source: executable = source.read('xray')
    core = root/'xray'; core.write_bytes(executable); core.chmod(0o700)
    spec = importlib.util.spec_from_file_location('proxy42_worker', PROJECT/'scripts/tcp-proxy-worker.py'); worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
    cert, key = root/'cert.pem', root/'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=target.example.test', '-addext', 'subjectAltName=DNS:target.example.test', '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True, timeout=20)
    nonce = uuid.uuid4().hex; requests = []
    class Web(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path); body = ('proxy42-authenticated-'+nonce).encode(); self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args): pass
    web = ThreadingHTTPServer(('127.0.0.1', 0), Web); web_thread = threading.Thread(target=web.serve_forever, daemon=True); web_thread.start()
    xray_port = port(); identity = str(uuid.uuid4())
    config = dict(log=dict(loglevel='warning', access=str(root/'access.log'), error=str(root/'error.log')),
                  inbounds=[dict(tag='qa-proxy-aware-tls', listen='127.0.0.1', port=xray_port, protocol='vless', settings=dict(clients=[dict(id=identity, email='proxy42-fixture')], decryption='none'),
                                 streamSettings=dict(network='tcp', security='tls', tcpSettings=dict(acceptProxyProtocol=True), tlsSettings=dict(certificates=[dict(certificateFile=str(cert), keyFile=str(key))])))],
                  outbounds=[dict(protocol='freedom', tag='direct')])
    config_path = root/'xray.private.json'; config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
    checked = subprocess.run([str(core), 'run', '-test', '-config', str(config_path)], capture_output=True, timeout=15)
    assert checked.returncode == 0, 'Pinned Xray rejected the explicit PROXY-aware TLS target'
    with (root/'process.log').open('wb') as output:
        process = subprocess.Popen([str(core), 'run', '-config', str(config_path)], stdout=output, stderr=subprocess.STDOUT, cwd=root)
    observed = []; checks = []
    try:
        until = time.monotonic()+10
        while time.monotonic() < until:
            if process.poll() is not None: raise RuntimeError('Pinned Xray exited; see private fixture log')
            try:
                with socket.create_connection(('127.0.0.1', xray_port), .2): break
            except OSError: time.sleep(.05)
        else: raise TimeoutError('Pinned Xray fixture startup exceeded budget')
        context = ssl.create_default_context(cafile=str(cert))
        for incoming in ('v1', 'v2'):
            for outgoing in ('v1', 'v2'):
                for family in (socket.AF_INET, socket.AF_INET6):
                    receiver = socket.socket(); receiver.bind(('127.0.0.1', 0)); receiver.listen()
                    entry = socket.socket(family); entry.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0)); entry.listen()
                    stop = threading.Event(); errors = []
                    policy = dict(Version=1, Protocol='Auto', TrustedSources=['127.0.0.1/32'], ClientSources=['127.0.0.0/8', '::1/128'], ProbeSource='127.0.0.2', ProbeDestination='127.0.0.1', TimeoutSeconds=2)
                    def run(listeners, target_port, version, receive=None):
                        try: worker.run(listeners, '127.0.0.1', target_port, version, receive=receive, stop=stop, idle=20)
                        except BaseException as error: errors.append(error)
                    threads = [threading.Thread(target=run, args=([receiver], xray_port, outgoing, policy)), threading.Thread(target=run, args=([entry], receiver.getsockname()[1], incoming))]
                    for thread in threads: thread.start()
                    try:
                        with socket.socket(family) as peer:
                            peer.settimeout(5); peer.bind(('127.0.0.2' if family == socket.AF_INET else '::1', 0)); peer.connect(entry.getsockname()); original = peer.getsockname()[:2]
                            with context.wrap_socket(peer, server_hostname='target.example.test') as tls:
                                request = b'\x00' + uuid.UUID(identity).bytes + b'\x00\x01' + web.server_port.to_bytes(2, 'big') + b'\x01\x7f\x00\x00\x01'
                                tls.sendall(request + b'GET / HTTP/1.1\r\nHost: proxy42.example.test\r\nConnection: close\r\n\r\n')
                                response_header = exact(tls, 2); assert response_header == b'\x00\x00'
                                response = bytearray()
                                while True:
                                    value = tls.recv(4096)
                                    if not value: break
                                    response.extend(value)
                                assert response.startswith(b'HTTP/1.0 200') and ('proxy42-authenticated-'+nonce).encode() in response
                                observed.append(original)
                        assert not errors
                    finally:
                        stop.set()
                        for thread in threads: thread.join(3); assert not thread.is_alive()
                        entry.close(); receiver.close()
        log = (root/'access.log').read_text()
        for address, source_port in observed:
            endpoint = (address+':'+str(source_port)) if ':' not in address else ('['+address+']:'+str(source_port))
            assert endpoint in log and 'accepted' in log, 'Xray access evidence lost the original client endpoint'
        assert len(requests) == 8
        checks.extend(['fixed-xray-proxy-aware-vless-tls-inbound', 'real-vless-uuid-authentication-and-http-business', 'v1-v2-two-hop-header-conversions', 'ipv4-ipv6-original-source-endpoints-in-xray-access-log'])
        result = dict(passed=True, xrayVersion=versions['xray']['version'], workerSha256=hashlib.sha256((PROJECT/'scripts/tcp-proxy-worker.py').read_bytes()).hexdigest(), combinations=len(observed), checks=checks, globalTrustChanged=False, servicesChanged=False, productionChanged=False)
        (root/'result.json').write_text(json.dumps(result, indent=2)); print(json.dumps(result))
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        web.shutdown(); web.server_close(); web_thread.join(3)
        (root/'cleanup.json').write_text(json.dumps(dict(ownedXrayExited=process.poll() is not None, ownedWebThreadExited=not web_thread.is_alive())))


if __name__ == '__main__': main()
