"""Bounded socket-activated TCP forwarding with explicit PROXY v1/v2 output.

Input bytes are always application data: no header detection or trusted input
addresses. Endpoints come exclusively from the accepted kernel socket.
"""
import argparse
import errno
import ipaddress
import os
import selectors
import socket
import struct
import time

CAPACITY = 256
BUFFER = 65536


def header(version, source, destination):
    src, dst = (ipaddress.ip_address(v[0]) for v in (source, destination))
    if src.version != dst.version or version not in ('v1', 'v2'):
        raise ValueError('Unsupported PROXY header family or version.')
    ports = (int(source[1]), int(destination[1]))
    if any(not 1 <= p <= 65535 for p in ports):
        raise ValueError('Invalid PROXY header port.')
    if version == 'v1':
        return ('PROXY TCP' + str(src.version) + ' ' + str(src) + ' ' + str(dst) + ' ' + str(ports[0]) + ' ' + str(ports[1]) + '\r\n').encode('ascii')
    payload = src.packed + dst.packed + struct.pack('!HH', *ports)
    return b'\r\n\r\n\x00\r\nQUIT\n' + bytes((0x21, 0x11 if src.version == 4 else 0x21)) + struct.pack('!H', len(payload)) + payload


def run(listeners, target, port, version, *, idle=60, connection_idle=300, stop=None):
    ip = ipaddress.ip_address(target)
    if version not in ('v1', 'v2') or ip.is_unspecified or ip.is_multicast or not 1 <= port <= 65535:
        raise ValueError('Invalid fixed TCP target.')
    selector = selectors.DefaultSelector()
    pairs = set()
    last = time.monotonic()
    for listener in listeners:
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, None)

    def close(pair):
        if pair not in pairs:
            return
        pairs.remove(pair)
        for s in pair.sockets:
            try: selector.unregister(s)
            except KeyError: pass
            s.close()

    def refresh(pair):
        for i, s in enumerate(pair.sockets):
            events = (selectors.EVENT_READ if not pair.eof[i] and len(pair.pending[1-i]) < BUFFER else 0)
            if pair.pending[i] or i == 1 and pair.connecting:
                events |= selectors.EVENT_WRITE
            try: selector.unregister(s)
            except KeyError: pass
            if events:
                selector.register(s, events, (pair, i))

    class Pair:
        pass

    try:
        while stop is None or not stop.is_set():
            now = time.monotonic()
            for pair in tuple(pairs):
                if (pair.connecting and pair.sockets[1].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)) or now - pair.touched > (5 if pair.connecting else connection_idle):
                    close(pair)
            if not pairs and now - last >= idle:
                break
            for key, events in selector.select(min(0.25, idle)):
                if key.data is None:
                    try: client, source = key.fileobj.accept()
                    except BlockingIOError: continue
                    last = time.monotonic()
                    if len(pairs) >= CAPACITY:
                        client.close(); continue
                    upstream = None
                    try:
                        prefix = header(version, source, client.getsockname())
                        upstream = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
                        upstream.setblocking(False); client.setblocking(False)
                        code = upstream.connect_ex((str(ip), port))
                        if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035):
                            raise OSError(code, 'TCP target refused')
                        pair = Pair(); pair.sockets = (client, upstream)
                        pair.pending = [bytearray(), bytearray(prefix)]
                        pair.eof = [False, False]; pair.shutdown = [False, False]
                        pair.connecting = code != 0; pair.touched = last
                        pairs.add(pair); refresh(pair)
                    except (OSError, ValueError):
                        client.close()
                        if upstream is not None: upstream.close()
                    continue
                pair, i = key.data
                if pair not in pairs:
                    continue
                s, other = pair.sockets[i], pair.sockets[1-i]
                try:
                    if i == 1 and pair.connecting and events & selectors.EVENT_WRITE:
                        if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR): raise OSError('TCP target connect failed')
                        pair.connecting = False
                    if events & selectors.EVENT_WRITE and pair.pending[i] and not (i == 1 and pair.connecting):
                        try: count = s.send(pair.pending[i])
                        except BlockingIOError: count = 0
                        if count:
                            del pair.pending[i][:count]; pair.touched = time.monotonic()
                    if events & selectors.EVENT_READ:
                        try: data = s.recv(min(16384, BUFFER-len(pair.pending[1-i])))
                        except BlockingIOError: data = None
                        if data is not None:
                            if data: pair.pending[1-i].extend(data)
                            else: pair.eof[i] = True
                            pair.touched = time.monotonic()
                    for destination in (0, 1):
                        if pair.eof[1-destination] and not pair.pending[destination] and not pair.shutdown[destination] and not (destination == 1 and pair.connecting):
                            pair.sockets[destination].shutdown(socket.SHUT_WR); pair.shutdown[destination] = True
                    if all(pair.eof) and not any(pair.pending): close(pair)
                    else: refresh(pair)
                except OSError:
                    close(pair)
                last = time.monotonic()
    finally:
        for pair in tuple(pairs): close(pair)
        selector.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--proxy-protocol', choices=('v1', 'v2'), required=True)
    args = parser.parse_args()
    count = int(os.environ.get('LISTEN_FDS', '0'))
    if os.environ.get('LISTEN_PID') != str(os.getpid()) or count not in (1, 2):
        raise ValueError('Owned socket activation is required.')
    listeners = [socket.socket(fileno=fd) for fd in range(3, 3+count)]
    try:
        if any(s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or not s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) for s in listeners):
            raise ValueError('Invalid activation listener.')
        run(listeners, args.target, args.port, args.proxy_protocol)
    finally:
        for s in listeners: s.close()


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError): raise SystemExit('Owned TCP PROXY forwarding failed.') from None
