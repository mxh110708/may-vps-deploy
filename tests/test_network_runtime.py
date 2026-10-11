"""Exercise the embedded runtime/queue snapshot code with an isolated OS model.

These contracts cover refusal, scoped restore and multiqueue behavior. They do
not replace real kernel/SSH verification on the authorized test VPS.
"""
import contextlib
import copy
import io
import json
import pathlib
import subprocess
import sys
import types
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE = (REPO / 'assets/remote/network-tools.sh').read_text(encoding='utf-8-sig')
CODE = SOURCE.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
BACKUP = '/root/vps-deploy-backups/20000101-000000/protocol-lifecycle'
KEYS = {'net.core.default_qdisc': 'fq_codel', 'net.ipv4.tcp_congestion_control': 'cubic',
        'net.ipv4.tcp_rmem': '4096 131072 6291456', 'net.ipv4.tcp_wmem': '4096 16384 4194304',
        'net.core.rmem_max': '212992', 'net.core.wmem_max': '212992', 'net.ipv4.tcp_moderate_rcvbuf': '1'}


class VirtualPath:
    def __init__(self, model, value): self.model, self.value = model, str(value)
    def __str__(self): return self.value
    def __truediv__(self, name): return VirtualPath(self.model, self.value.rstrip('/') + '/' + name)
    @property
    def parents(self):
        value = self.value
        while value != '/':
            value = value.rsplit('/', 1)[0] or '/'
            yield VirtualPath(self.model, value)
    def exists(self): return self.value in self.model.files
    def is_symlink(self): return self.value in self.model.links
    def is_file(self): return self.exists()
    def read_bytes(self): return self.model.files[self.value]
    def read_text(self): return self.read_bytes().decode()
    def write_bytes(self, data): self.model.files[self.value] = data
    def stat(self): return types.SimpleNamespace(st_mode=0o100600)
    def unlink(self, missing_ok=False): self.model.files.pop(self.value, None)
    def open(self, mode):
        if mode != 'x' or self.exists(): raise FileExistsError(self.value)
        path = self
        class Writer(io.StringIO):
            def __exit__(self, *args):
                path.write_bytes(self.getvalue().encode())
                return super().__exit__(*args)
        return Writer()


class Model:
    def __init__(self):
        self.files = {'/proc/self/status': b'CapEff:\t0000000000001000\n'}
        self.links = set()
        self.values = copy.deepcopy(KEYS)
        self.queues = [{'kind': 'fq_codel', 'root': True, 'handle': '0:',
                        'options': {'limit': 10240, 'flows': 1024, 'target': 5000, 'interval': 100000, 'ecn': True}}]
        self.calls = []
        self.ignore_tc_replace = False
        self.generated_handles = False
    def run(self, args, **kwargs):
        self.calls.append(list(args))
        output, code = '', 0
        if args[0] == 'sysctl':
            if args[1] == '-n': output = self.values[args[2]]
            else:
                key, value = args[2].split('=', 1); self.values[key] = value
        elif args[0] == 'ip': output = json.dumps([{'dev': 'eth0'}] if '-4' in args else [])
        elif args[:3] == ['tc', '-j', 'qdisc']: output = json.dumps(self.queues)
        elif args[:3] == ['tc', 'qdisc', 'replace']:
            if self.ignore_tc_replace: return subprocess.CompletedProcess(args, 0, '', '')
            position = args.index('root') if 'root' in args else args.index('parent') + 1
            parent = args[args.index('parent')+1] if 'parent' in args else None
            start = position + 1
            handle = '8001:' if self.generated_handles else '0:'
            if args[start] == 'handle': handle = args[start+1]; start += 2
            kind = args[start]; opts = {}; rest = iter(args[start+1:])
            for name in rest:
                if name in ('ecn', 'noecn'): opts['ecn'] = name == 'ecn'; continue
                value = next(rest); opts[name] = int(value.removesuffix('us'))
            result = {'kind': kind, 'handle': handle, 'options': opts}
            if parent is None: result['root'] = True
            else: result['parent'] = parent
            self.queues = [result if q.get('parent') == parent and bool(q.get('root')) == (parent is None) else q for q in self.queues]
        elif args[:2] in (['systemctl', 'is-enabled'], ['systemctl', 'is-active']): code = 1
        return subprocess.CompletedProcess(args, code, output, '')
    def execute(self, action):
        with mock.patch.object(pathlib, 'Path', lambda value: VirtualPath(self, value)), \
             mock.patch.object(subprocess, 'run', self.run), \
             mock.patch.object(sys, 'argv', ['network-runtime', action, BACKUP]), \
             mock.patch('os.chmod'), contextlib.redirect_stdout(io.StringIO()):
            try: exec(compile(CODE, 'network-runtime', 'exec'), {})
            except SystemExit as error:
                if error.code != 0: raise


class NetworkRuntimeTests(unittest.TestCase):
    def test_preflight_does_not_change_runtime_or_create_snapshot(self):
        model = Model(); original = copy.deepcopy(model.values)
        model.execute('preflight')
        self.assertEqual(original, model.values)
        self.assertNotIn(BACKUP + '/network-state.json', model.files)
        self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] for c in model.calls))

    def test_snapshot_apply_and_restore_runtime_and_persistence(self):
        model = Model(); queues = copy.deepcopy(model.queues)
        model.execute('snapshot'); model.execute('apply'); model.execute('verify')
        model.values['net.core.default_qdisc'] = 'fq'; model.values['net.ipv4.tcp_congestion_control'] = 'bbr'
        for name in ('/usr/local/libexec/mxh-network-queue', '/etc/systemd/system/mxh-network-queue.service'):
            model.files[name] = b'# Managed by MXH VPS Deploy.\n'
        model.execute('restore')
        self.assertEqual(KEYS, model.values); self.assertEqual(queues, model.queues)
        self.assertNotIn('/usr/local/libexec/mxh-network-queue', model.files)
        self.assertNotIn('/etc/systemd/system/mxh-network-queue.service', model.files)

    def test_multiqueue_keeps_root_and_only_replaces_leaves(self):
        model = Model(); model.queues = [{'kind': 'mq', 'root': True, 'handle': '0:', 'options': {}},
            {'kind': 'fq_codel', 'parent': ':1', 'handle': '0:', 'options': {}},
            {'kind': 'fq', 'parent': ':2', 'handle': '8001:', 'options': {'horizon_drop': None, 'timer_slack': 10000}}]
        original = copy.deepcopy(model.queues); model.execute('snapshot'); model.execute('apply'); model.execute('verify')
        self.assertEqual(model.queues[0], original[0]); self.assertEqual(model.queues[2], original[2])
        model.execute('restore'); self.assertEqual(model.queues, original)

    def test_custom_shaping_and_linked_persistence_are_refused_before_writes(self):
        for kind in ('cake', 'htb', 'netem'):
            model = Model(); model.queues[0]['kind'] = kind
            with self.assertRaises(SystemExit): model.execute('preflight')
            self.assertEqual(model.values, KEYS)
        model = Model(); model.links.add('/usr/local/libexec')
        with self.assertRaises(SystemExit): model.execute('preflight')

    def test_changed_queue_or_unmanaged_file_is_not_overwritten(self):
        model = Model(); model.execute('snapshot'); model.queues[0]['kind'] = 'cake'
        with self.assertRaises(SystemExit): model.execute('apply')
        with self.assertRaises(SystemExit): model.execute('restore')
        model = Model(); model.execute('snapshot'); model.execute('apply')
        model.files['/etc/systemd/system/mxh-network-queue.service'] = b'External administrator service'
        model.values['net.core.default_qdisc'] = 'fq'; before = copy.deepcopy(model.values)
        with self.assertRaises(SystemExit): model.execute('restore')
        self.assertEqual(before, model.values)

    def test_existing_fq_options_remain_untouched(self):
        model = Model(); model.queues[0] = {'kind': 'fq', 'root': True, 'handle': '8001:', 'options': {'horizon_drop': None, 'timer_slack': 10000}}
        original = copy.deepcopy(model.queues); model.execute('snapshot'); model.execute('apply'); model.execute('verify'); model.execute('restore')
        self.assertEqual(original, model.queues)
        self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] for c in model.calls))

    def test_restore_verifies_actual_queue_instead_of_command_exit(self):
        model = Model(); model.execute('snapshot'); model.execute('apply')
        model.ignore_tc_replace = True
        with self.assertRaisesRegex(SystemExit, 'restore was not confirmed'): model.execute('restore')

    def test_restore_accepts_kernel_assigned_handle_and_time_rounding(self):
        model = Model(); model.queues[0]['options']['target'] = 4999.999999
        model.generated_handles = True
        model.execute('snapshot'); model.execute('apply'); model.execute('restore')
        self.assertEqual(model.queues[0]['kind'], 'fq_codel')
        self.assertEqual(model.queues[0]['options']['target'], 5000)
        calls = len(model.calls); model.execute('restore')
        self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] for c in model.calls[calls:]))


if __name__ == '__main__': unittest.main()
