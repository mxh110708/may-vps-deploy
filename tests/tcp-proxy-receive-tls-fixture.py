"""Process-local certificate fixture; not a production server or trust installer."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading

spec = importlib.util.spec_from_file_location('fixture_proxy', Path(__file__).resolve().parents[1] / 'scripts/tcp-proxy-worker.py')
worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
certificate, key, proof, family = sys.argv[1:]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certificate, key)
context.num_tickets = 0  # Handshake-only fixture; no session-resumption coverage.
listener = socket.socket(socket.AF_INET6 if family == 'IPv6' else socket.AF_INET)
listener.bind(('::1' if family == 'IPv6' else '127.0.0.1', 0)); listener.listen()


def serve(peer):
    try:
        with peer:
            peer.settimeout(6); data = bytearray(); parsed = None
            while parsed is None:
                value = peer.recv(1)
                if not value: return
                data.extend(value); parsed = worker.parse_header(data, 'Auto')
            with context.wrap_socket(peer, server_side=True):
                source, destination, _ = parsed
                temporary = Path(proof + '.new')
                temporary.write_text(json.dumps(dict(Source=source[0], SourcePort=source[1], Destination=destination[0], DestinationPort=destination[1], CertificateHandshake=True)))
                os.replace(temporary, proof)
    except (OSError, ValueError): pass


print(listener.getsockname()[1], flush=True)
while True:
    peer, _ = listener.accept()
    threading.Thread(target=serve, args=(peer,), daemon=True).start()
