"""A listening TCP port must not release one-shot UDP acceptance prematurely."""
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from test_linux_core_upgrade import owns_udp_listener, wait_udp_listener


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux /proc socket ownership fixture')
class OwnedUdpReadiness(unittest.TestCase):
    @contextlib.contextmanager
    def child(self, root, bind_udp):
        # The parent controls when the child may bind UDP. No timing assumption
        # can make TCP-listening alone sufficient for the assertion below.
        code = '''import json,pathlib,socket,sys,time
root=pathlib.Path(sys.argv[1]); tcp=socket.socket(); tcp.bind(('127.0.0.1',0)); tcp.listen()
(root/'ready.tmp').write_text(json.dumps({'port':tcp.getsockname()[1]})); (root/'ready.tmp').replace(root/'ready.json')
while not (root/'release').exists(): time.sleep(.01)
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
if sys.argv[2]=='yes': udp.bind(('127.0.0.1',tcp.getsockname()[1]))
while True: time.sleep(1)
'''
        process = subprocess.Popen([sys.executable, '-c', code, str(root), 'yes' if bind_udp else 'no'])
        try:
            deadline = time.monotonic() + 5
            while not (root / 'ready.json').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError('readiness child did not start')
                time.sleep(.01)
            value = json.loads((root / 'ready.json').read_text())
            yield process, value['port']
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_tcp_ready_precedes_owned_udp_and_wait_observes_real_bind(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.child(root, True) as (process, port):
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    pass
                self.assertFalse(owns_udp_listener(process, port))
                (root / 'release').touch()
                wait_udp_listener(process, port, timeout=2)
                self.assertTrue(owns_udp_listener(process, port))

    def test_unrelated_process_udp_socket_does_not_satisfy_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.child(root, False) as (process, port):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unrelated:
                    unrelated.bind(('127.0.0.1', port))
                    self.assertFalse(owns_udp_listener(process, port))
                    (root / 'release').touch()
                    with self.assertRaisesRegex(AssertionError, 'UDP listener'):
                        wait_udp_listener(process, port, timeout=.1)

    def test_exited_process_is_failure(self):
        process = subprocess.Popen([sys.executable, '-c', 'pass'])
        process.wait(timeout=5)
        with self.assertRaisesRegex(AssertionError, 'exited'):
            wait_udp_listener(process, 1, timeout=.1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
