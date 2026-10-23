"""Socket-activated UDP relay; bounded peer sessions, no persistent state."""
import argparse
import ipaddress
import os
import selectors
import socket
import struct
import sys
import time


class Relay:
    def __init__(self, listeners, target, timeout=120, maximum=256, idle=60, allowed=('127.0.0.0/8', '::1/128')):
        address = ipaddress.ip_address(target[0])
        if address.is_unspecified or address.is_multicast or '%' in str(address) or getattr(address, 'ipv4_mapped', None):
            raise ValueError('A unicast UDP target is required.')
        if not 1 <= target[1] <= 65535 or not 0 < timeout <= 600 or not 1 <= maximum <= 1024 or not 0 < idle <= 60:
            raise ValueError('UDP worker limits are invalid.')
        self.target, self.timeout, self.maximum, self.idle = target, timeout, maximum, idle
        self.family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        self.allowed = tuple(ipaddress.ip_network(source, strict=False) for source in allowed)
        if not 1 <= len(self.allowed) <= 32:
            raise ValueError('UDP worker requires explicit allowed sources.')
        self.selector, self.sessions = selectors.DefaultSelector(), {}
        self.empty_since = time.monotonic()
        self.listeners = listeners
        for listener in listeners:
            if listener.type & socket.SOCK_DGRAM != socket.SOCK_DGRAM:
                raise ValueError('UDP activation requires datagram sockets.')
            listener.setblocking(False)
            if listener.family == socket.AF_INET:
                listener.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_PKTINFO', 8), 1)
            else:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
            self.selector.register(listener, selectors.EVENT_READ, None)

    def close_session(self, key):
        session = self.sessions.pop(key)
        self.selector.unregister(session['socket'])
        session['socket'].close()
        if not self.sessions:
            self.empty_since = time.monotonic()

    def run(self):
        sweep_at = 0
        try:
            while True:
                now = time.monotonic()
                if self.sessions and now >= sweep_at:
                    for key, session in list(self.sessions.items()):
                        if now - session['activity'] >= self.timeout:
                            self.close_session(key)
                    sweep_at = now + min(1, self.timeout)
                if not self.sessions and now - self.empty_since >= self.idle:
                    return
                wait = max(0, sweep_at - now) if self.sessions else self.idle - (now - self.empty_since)
                for event, _ in self.selector.select(wait):
                    if event.data is None:
                        listener = event.fileobj
                        # Bound work per ready socket so a busy sender cannot
                        # prevent replies, expiry or another address family.
                        for _ in range(32):
                            try:
                                payload, control, flags, peer = listener.recvmsg(65535, 128)
                            except BlockingIOError:
                                break
                            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                                continue
                            reply_control = []
                            for level, kind, data in control:
                                if level == socket.IPPROTO_IP and kind == getattr(socket, 'IP_PKTINFO', 8) and len(data) == 12:
                                    # Reply using the destination address on which
                                    # this packet arrived, even on multihomed VPSes.
                                    interface = struct.unpack('=I', data[:4])[0]
                                    reply_control.append((level, kind, struct.pack('=I4s4s', interface, data[8:12], b'\0' * 4)))
                                elif level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO and len(data) == 20:
                                    reply_control.append((level, kind, data))
                            if not reply_control:
                                continue  # Never guess a different reply source.
                            key = (listener.fileno(), peer, tuple(reply_control))
                            if key not in self.sessions:
                                source = ipaddress.ip_address(peer[0])
                                if not source.is_loopback and not any(source in network for network in self.allowed):
                                    continue
                                if len(self.sessions) >= self.maximum:
                                    continue  # Preserve established sessions.
                                try:
                                    upstream = socket.socket(self.family, socket.SOCK_DGRAM)
                                except OSError:
                                    continue
                                try:
                                    upstream.setblocking(False)
                                    upstream.connect(self.target)
                                    self.selector.register(upstream, selectors.EVENT_READ, key)
                                except OSError:
                                    upstream.close()
                                    continue
                                self.sessions[key] = {'socket': upstream, 'listener': listener, 'peer': peer, 'control': reply_control, 'activity': time.monotonic()}
                            session = self.sessions[key]
                            try:
                                session['socket'].send(payload)  # Empty datagrams are valid.
                                session['activity'] = time.monotonic()
                            except BlockingIOError:
                                pass  # UDP is best effort; do not buffer unbounded traffic.
                            except OSError:
                                self.close_session(key)
                    else:
                        key = event.data
                        session = self.sessions.get(key)
                        if session is None:
                            continue
                        for _ in range(32):
                            try:
                                payload = session['socket'].recv(65535)
                                session['listener'].sendmsg([payload], session['control'], 0, session['peer'])
                                session['activity'] = time.monotonic()
                            except BlockingIOError:
                                break
                            except OSError:
                                self.close_session(key)
                                break
        finally:
            for key in list(self.sessions):
                self.close_session(key)
            self.selector.close()
            for listener in self.listeners:
                listener.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--timeout', type=int, required=True)
    parser.add_argument('--maximum', type=int, required=True)
    parser.add_argument('--allowed', required=True)
    args = parser.parse_args()
    count = int(os.environ.pop('LISTEN_FDS', '0'))
    if int(os.environ.pop('LISTEN_PID', '0')) != os.getpid() or count not in (1, 2):
        raise ValueError('UDP worker requires systemd socket activation.')
    os.environ.pop('LISTEN_FDNAMES', None)
    listeners = [socket.socket(fileno=fd) for fd in range(3, 3 + count)]
    Relay(listeners, (args.target, args.port), args.timeout, args.maximum, allowed=args.allowed.split(',')).run()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError):
        print('UDP forwarding worker failed; check activation and target configuration.', file=sys.stderr)
        sys.exit(1)
