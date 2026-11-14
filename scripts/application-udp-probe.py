"""Finite UDP DNS through an owned loopback SOCKS relay; never direct DNS.

Only fixed public resolvers are used in production. The response must match a
fresh DNS identity and complete question; SOCKS TCP negotiation is not proof.
"""
import ipaddress
import secrets
import socket
import time

APPLICATION_UDP_RESOLVERS = {'IPv4': ('1.1.1.1', 53), 'IPv6': ('2606:4700:4700::1111', 53)}


def application_udp_exact(stream, size):
    result = b''
    while len(result) < size:
        piece = stream.recv(size - len(result))
        if not piece:
            raise ValueError('Incomplete UDP relay negotiation.')
        result += piece
    return result


def application_udp_dns_matches(query, answer):
    if not 12 <= len(answer) <= 4096 or answer[:2] != query[:2] or answer[2] & 0xFA != 0x80 or answer[3] & 0x0F or answer[4:6] != b'\0\1' or answer[6:8] == b'\0\0':
        return False
    # Queries use one fixed, uncompressed question. Echoing that exact question
    # is required; a matching transaction number alone is insufficient.
    if answer[12:len(query)] != query[12:]:
        return False
    cursor = len(query)
    count = int.from_bytes(answer[6:8], 'big')
    if count > 32:
        return False
    for _ in range(count):
        labels = 0
        while cursor < len(answer):
            length = answer[cursor]
            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(answer) or ((length & 0x3F) << 8 | answer[cursor + 1]) >= cursor:
                    return False
                cursor += 2
                break
            if length > 63 or labels > 127 or cursor + length >= len(answer):
                return False
            cursor += 1 + length
            labels += 1
            if length == 0:
                break
        if cursor + 10 > len(answer):
            return False
        kind = answer[cursor:cursor + 2]
        group = answer[cursor + 2:cursor + 4]
        size = int.from_bytes(answer[cursor + 8:cursor + 10], 'big')
        cursor += 10 + size
        if cursor > len(answer):
            return False
        if group == b'\0\1' and kind == query[-4:-2] and size == (4 if kind == b'\0\1' else 16):
            return True
    return False


def application_udp_probe(port, family):
    if family not in ('IPv4', 'IPv6'):
        raise ValueError('Explicit application UDP family required.')
    address, target_port = APPLICATION_UDP_RESOLVERS[family]
    destination = ipaddress.ip_address(address)
    version = 4 if destination.version == 4 else 16
    with socket.create_connection(('127.0.0.1', port), timeout=3) as control, socket.socket(type=socket.SOCK_DGRAM) as channel:
        control.settimeout(3)
        control.sendall(b'\x05\x01\x00')
        if application_udp_exact(control, 2) != b'\x05\x00':
            raise ValueError('UDP relay authentication negotiation failed.')
        channel.bind(('127.0.0.1', 0))
        local_port = channel.getsockname()[1]
        control.sendall(b'\x05\x03\x00\x01\x7f\0\0\x01' + local_port.to_bytes(2, 'big'))
        head = application_udp_exact(control, 4)
        if head[:3] != b'\x05\0\0' or head[3] != 1:
            raise ValueError('Expected an IPv4 loopback SOCKS UDP relay.')
        relay = application_udp_exact(control, 6)
        relay_address = str(ipaddress.ip_address(relay[:4]))
        if relay_address == '0.0.0.0':
            relay_address = '127.0.0.1'
        relay_port = int.from_bytes(relay[4:], 'big')
        if not ipaddress.ip_address(relay_address).is_loopback or not relay_port:
            raise ValueError('UDP relay exceeds loopback scope.')
        channel.connect((relay_address, relay_port))
        header = b'\0\0\0' + bytes([1 if version == 4 else 4]) + destination.packed + target_port.to_bytes(2, 'big')
        for _ in range(3):
            query = secrets.token_bytes(2) + b'\x01\0\0\x01\0\0\0\0\0\0' + b'\x07example\x03com\0' + (b'\0\x01' if family == 'IPv4' else b'\0\x1c') + b'\0\x01'
            end = time.monotonic() + 2
            channel.send(header + query)
            for _ in range(16):
                try:
                    channel.settimeout(max(0.01, end - time.monotonic()))
                    answer = channel.recv(4096 + len(header))
                except (socket.timeout, ConnectionResetError):
                    break
                if answer[:len(header)] == header and application_udp_dns_matches(query, answer[len(header):]):
                    return {'Scope': 'NativeOutboundUdpDns', 'Transport': 'UDP', 'ResponseMatched': True,
                            'ResolverAddress': address, 'ResolverPort': target_port, 'QueryName': 'example.com',
                            'QueryType': 'A' if family == 'IPv4' else 'AAAA'}
                if time.monotonic() >= end:
                    break
    raise ValueError('No matching DNS datagram returned through the selected native outbound.')
