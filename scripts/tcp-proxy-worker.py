"""Bounded TCP forwarding; PROXY input requires an explicit, closed trust policy."""
import argparse
import errno
import ipaddress
import json
import os
import re
import selectors
import socket
import struct
import time

CAPACITY = 256
BUFFER = 65536
SIGNATURE = b'\r\n\r\n\x00\r\nQUIT\n'


def unicast(value):
    address = ipaddress.ip_address(value)
    if '%' in str(address) or getattr(address, 'ipv4_mapped', None) or address.is_unspecified or address.is_multicast or address.version == 4 and address.packed[0] >= 224:
        raise ValueError('A concrete unicast PROXY endpoint is required.')
    return address


def contains(networks, address):
    ip = ipaddress.ip_address(address)
    if getattr(ip, 'ipv4_mapped', None): ip = ip.ipv4_mapped
    return any(ip.version == network.version and ip in network for network in networks)


def normalize_receive(policy, allowed=None):
    fields = {'Version', 'Protocol', 'TrustedSources', 'ClientSources', 'ProbeSource', 'ProbeDestination', 'TimeoutSeconds'}
    if not isinstance(policy, dict) or set(policy) != fields or type(policy['Version']) is not int or policy['Version'] != 1 or policy['Protocol'] not in ('v1', 'v2', 'Auto'):
        raise ValueError('Unsupported PROXY receive policy.')
    if type(policy['TimeoutSeconds']) is not int or not 1 <= policy['TimeoutSeconds'] <= 10:
        raise ValueError('PROXY header deadline must be 1-10 seconds.')
    result = dict(policy)
    for key in ('TrustedSources', 'ClientSources'):
        sources = policy[key]
        if not isinstance(sources, list) or not 1 <= len(sources) <= 32 or any(not isinstance(v, str) for v in sources):
            raise ValueError('Explicit trusted relays and client networks are required.')
        networks = [ipaddress.ip_network(v, strict=False) for v in sources]
        if any('%' in str(n) or getattr(n.network_address, 'ipv4_mapped', None) or n.is_multicast or key == 'TrustedSources' and n.prefixlen == 0 for n in networks):
            raise ValueError('A trusted relay cannot be the entire Internet or a multicast network.')
        result[key] = sorted(set(str(n) for n in networks))
    if allowed is not None:
        permitted = [ipaddress.ip_network(v, strict=False) for v in allowed]
        if any(not any(n.version == a.version and n.subnet_of(a) for a in permitted) for n in (ipaddress.ip_network(v) for v in result['TrustedSources'])):
            raise ValueError('Trusted relays must be covered by the transport source whitelist.')
    if not isinstance(policy['ProbeSource'], str): raise ValueError('An explicit validation client address is required.')
    probe = unicast(policy['ProbeSource'])
    if not contains([ipaddress.ip_network(v) for v in result['ClientSources']], probe):
        raise ValueError('The declared validation client must be allowed by the client policy.')
    result['ProbeSource'] = str(probe)
    if not isinstance(policy['ProbeDestination'], str): raise ValueError('An explicit validation destination address is required.')
    destination = unicast(policy['ProbeDestination'])
    if probe.version != destination.version: raise ValueError('Declared validation endpoints must have the same address family.')
    result['ProbeDestination'] = str(destination)
    return result


def parse_header(data, mode):
    """Return endpoints and consumed bytes, or None for a bounded partial header.

    Only address-bearing TCP headers are accepted. UNKNOWN, LOCAL, UDP, UNIX,
    TLVs and unsupported commands/families are deliberately not part of v1.
    """
    if mode == 'Auto':
        if not data: return None
        mode = 'v1' if data[0] == ord('P') else 'v2' if data[0] == 13 else ''
    if mode == 'v1':
        prefix = b'PROXY '
        if data[:min(len(data), len(prefix))] != prefix[:min(len(data), len(prefix))]: raise ValueError('Missing required PROXY v1 header.')
        end = data.find(b'\r\n')
        if end < 0:
            if len(data) >= 108 or b'\n' in data: raise ValueError('Oversized or malformed PROXY v1 header.')
            return None
        if end + 2 > 108: raise ValueError('Oversized PROXY v1 header.')
        fields = bytes(data[:end]).decode('ascii').split(' ')
        if len(fields) != 6 or fields[:2] not in (['PROXY', 'TCP4'], ['PROXY', 'TCP6']) or any(not re.fullmatch(r'[0-9]{1,5}', v) for v in fields[4:]):
            raise ValueError('Only PROXY v1 TCP addresses are accepted.')
        src, dst = unicast(fields[2]), unicast(fields[3])
        ports = [int(v) for v in fields[4:]]
        if src.version != dst.version or src.version != int(fields[1][-1]) or any(not 1 <= p <= 65535 for p in ports): raise ValueError('Invalid PROXY v1 endpoints.')
        return (str(src), ports[0]), (str(dst), ports[1]), end + 2
    if mode == 'v2':
        if data[:min(len(data), 12)] != SIGNATURE[:min(len(data), 12)]: raise ValueError('Missing required PROXY v2 signature.')
        if len(data) < 16: return None
        if data[12] != 0x21 or data[13] not in (0x11, 0x21): raise ValueError('Only PROXY v2 TCP addresses are accepted.')
        size = 4 if data[13] == 0x11 else 16
        length = struct.unpack('!H', data[14:16])[0]
        if length != size * 2 + 4: raise ValueError('PROXY v2 TLVs and oversized headers are not supported.')
        if len(data) < 16 + length: return None
        src, dst = unicast(bytes(data[16:16+size])), unicast(bytes(data[16+size:16+size*2]))
        ports = struct.unpack('!HH', data[16+size*2:16+length])
        if any(not 1 <= p <= 65535 for p in ports): raise ValueError('Invalid PROXY v2 ports.')
        return (str(src), ports[0]), (str(dst), ports[1]), 16 + length
    raise ValueError('Unrecognized required PROXY header.')


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


def run(listeners, target, port, version, *, idle=60, connection_idle=300, stop=None, target_selector=None, source_selector=None, receive=None):
    ip = ipaddress.ip_address(target)
    if version not in (None, 'v1', 'v2') or ip.is_unspecified or ip.is_multicast or not 1 <= port <= 65535:
        raise ValueError('Invalid fixed TCP target.')
    policy = normalize_receive(receive) if receive is not None else None
    if policy is not None and version is None: raise ValueError('Received client identity requires explicit PROXY output.')
    trusted = [ipaddress.ip_network(v) for v in policy['TrustedSources']] if policy else []
    clients = [ipaddress.ip_network(v) for v in policy['ClientSources']] if policy else []
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
            if s is None: continue
            try: selector.unregister(s)
            except KeyError: pass
            s.close()

    def refresh(pair):
        for i, s in enumerate(pair.sockets):
            if s is None: continue
            if pair.reading:
                try: selector.unregister(s)
                except KeyError: pass
                selector.register(s, selectors.EVENT_READ, (pair, i))
                continue
            events = (selectors.EVENT_READ if not pair.eof[i] and len(pair.pending[1-i]) < BUFFER else 0)
            if pair.pending[i] or i == 1 and pair.connecting:
                events |= selectors.EVENT_WRITE
            try: selector.unregister(s)
            except KeyError: pass
            if events:
                selector.register(s, events, (pair, i))

    class Pair:
        pass

    def connect(pair, source, destination, payload=b''):
        # No upstream socket or target allocation exists before trust, complete
        # parsing and the claimed-client policy have all succeeded.
        selected = source_selector(source) if source_selector is not None else target_selector() if target_selector is not None else (str(ip), port)
        if selected is None:
            close(pair); return
        selected_ip = unicast(selected[0])
        prefix = header(version, source, destination) if version is not None else b''
        upstream = socket.socket(socket.AF_INET6 if selected_ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        pair.sockets[1] = upstream
        upstream.setblocking(False)
        code = upstream.connect_ex((str(selected_ip), selected[1]))
        if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035): raise OSError(code, 'TCP target refused')
        pair.reading = False; pair.input.clear()
        pair.pending[1].extend(prefix + payload)
        pair.connecting = code != 0
        pair.touched = time.monotonic()  # The five-second connect budget starts here, not at accept.
        refresh(pair)

    try:
        while stop is None or not stop.is_set():
            now = time.monotonic()
            for pair in tuple(pairs):
                if (pair.reading and now >= pair.deadline) or (pair.connecting and pair.sockets[1].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)) or now - pair.touched > (5 if pair.connecting else connection_idle):
                    close(pair)
            if not pairs and now - last >= idle:
                break
            for key, events in selector.select(min(0.25, idle)):
                if key.data is None:
                    try: client, source = key.fileobj.accept()
                    except BlockingIOError: continue
                    last = time.monotonic()
                    if len(pairs) >= CAPACITY or policy is not None and not contains(trusted, source[0]):
                        client.close(); continue
                    pair = Pair(); pair.sockets = [client, None]
                    pair.pending = [bytearray(), bytearray()]
                    pair.eof = [False, False]; pair.shutdown = [False, False]
                    pair.connecting = False; pair.touched = last
                    pair.reading = policy is not None; pair.input = bytearray()
                    pair.deadline = last + (policy['TimeoutSeconds'] if policy else 0)
                    pairs.add(pair)
                    try:
                        client.setblocking(False)
                        if pair.reading: refresh(pair)
                        else: connect(pair, source, client.getsockname())
                    except (OSError, ValueError):
                        close(pair)
                    continue
                pair, i = key.data
                if pair not in pairs:
                    continue
                s, other = pair.sockets[i], pair.sockets[1-i]
                try:
                    if pair.reading:
                        if time.monotonic() >= pair.deadline: close(pair); continue
                        data = s.recv(16384)
                        if not data: close(pair); continue
                        pair.input.extend(data)
                        parsed = parse_header(pair.input, policy['Protocol'])
                        if parsed is not None:
                            source, destination, consumed = parsed
                            if time.monotonic() >= pair.deadline or not contains(clients, source[0]): close(pair); continue
                            connect(pair, source, destination, bytes(pair.input[consumed:]))
                        continue
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
                except (OSError, ValueError, UnicodeError):
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
    parser.add_argument('--receive-policy')
    args = parser.parse_args()
    count = int(os.environ.get('LISTEN_FDS', '0'))
    if os.environ.get('LISTEN_PID') != str(os.getpid()) or count not in (1, 2):
        raise ValueError('Owned socket activation is required.')
    listeners = [socket.socket(fileno=fd) for fd in range(3, 3+count)]
    try:
        if any(s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or not s.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) for s in listeners):
            raise ValueError('Invalid activation listener.')
        receive = json.loads(args.receive_policy) if args.receive_policy else None
        run(listeners, args.target, args.port, args.proxy_protocol, receive=receive)
    finally:
        for s in listeners: s.close()


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError): raise SystemExit('Owned TCP PROXY forwarding failed.') from None
