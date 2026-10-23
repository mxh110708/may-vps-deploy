"""Loopback-only OpenSSL TLS fixture; never installs a certificate."""
import socket
import ssl
import sys

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    print(listener.getsockname()[1], flush=True)
    while True:
        stream, _ = listener.accept()
        with stream:
            stream.settimeout(8)
            try:
                with context.wrap_socket(stream, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass
