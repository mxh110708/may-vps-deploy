"""Bounded per-socket evidence, including kernels with built-in BBR."""
import socket
from pathlib import Path


def bbr_runtime():
    try:
        version = Path('/sys/module/tcp_bbr/version').read_text().strip()
    except OSError:
        version = ''
    result = {'BbrVersion': 'v'+version if version in ('1', '2', '3') else 'VersionUnverified',
              'BbrVersionEvidence': 'LoadedModule' if version in ('1', '2', '3') else 'Unavailable'}
    try:
        with socket.socket() as listener, socket.socket() as sender:
            listener.settimeout(2); sender.settimeout(2)
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            sender.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b'bbr')
            sender.connect(listener.getsockname())
            with listener.accept()[0] as receiver:
                receiver.settimeout(2); sender.sendall(b'MXH-BBR-runtime'); receiver.recv(64)
                info = sender.getsockopt(socket.IPPROTO_TCP, 26, 128)  # TCP_CC_INFO
                # Google BBR v3: nine u32s, mode, phase, pad, version, three u32s.
                if len(info) >= 52 and info[39] in (2, 3):
                    observed = str(info[39])
                    if version in ('1', '2', '3') and version != observed:
                        return {'BbrVersion': 'VersionUnverified', 'BbrVersionEvidence': 'ConflictingRuntime'}
                    result = {'BbrVersion': 'v'+observed, 'BbrVersionEvidence': 'TcpCcInfo', 'BbrInfoBytes': len(info)}
    except (OSError, ValueError):
        pass
    return result
