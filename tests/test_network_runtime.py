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
PFIFO_OPTIONS = {'bands': 3, 'priomap': [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1], 'multiqueue': False}


class VirtualPath:
    def __init__(self, model, value): self.model, self.value = model, str(value)
    def __str__(self): return self.value
    def __truediv__(self, name): return VirtualPath(self.model, self.value.rstrip('/') + '/' + name)
    def with_suffix(self, suffix): return VirtualPath(self.model, self.value.rsplit('.', 1)[0] + suffix)
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
    def stat(self): return types.SimpleNamespace(st_mode=0o100000 | self.model.modes.get(self.value, 0o600))
    def unlink(self, missing_ok=False): self.model.files.pop(self.value, None)
    def open(self, mode):
        if mode not in ('x', 'w') or mode == 'x' and self.exists(): raise FileExistsError(self.value)
        path = self
        class Writer(io.StringIO):
            def __exit__(self, *args):
                path.write_bytes(self.getvalue().encode())
                return super().__exit__(*args)
        return Writer()


class Model:
    def __init__(self):
        self.files = {'/proc/self/status': b'CapEff:\t0000000000001000\n'}
        self.modes = {}
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
            if kind == 'pfifo_fast':
                if args[start+1:]: raise AssertionError('pfifo_fast has no tc option parser')
                opts = copy.deepcopy(PFIFO_OPTIONS)
            for name in rest:
                if name in ('ecn', 'noecn'): opts['ecn'] = name == 'ecn'; continue
                value = next(rest); opts[name] = int(value.removesuffix('us'))
            result = {'kind': kind, 'handle': handle, 'options': opts}
            if parent is None: result['root'] = True
            else: result['parent'] = parent
            self.queues = [result if q.get('parent') == parent and bool(q.get('root')) == (parent is None) else q for q in self.queues]
        elif args[:2] in (['systemctl', 'is-enabled'], ['systemctl', 'is-active']): code = 1
        return subprocess.CompletedProcess(args, code, output, '')
    def execute(self, action, *parameters):
        with mock.patch.object(pathlib, 'Path', lambda value: VirtualPath(self, value)), \
             mock.patch.object(subprocess, 'run', self.run), \
             mock.patch.object(sys, 'argv', ['network-runtime', action, BACKUP, *parameters]), \
             mock.patch('os.replace', side_effect=self.replace), \
             mock.patch('os.chmod', side_effect=lambda path, mode: self.modes.__setitem__(str(path), mode)), contextlib.redirect_stdout(io.StringIO()):
            try: exec(compile(CODE, 'network-runtime', 'exec'), {})
            except SystemExit as error:
                if error.code != 0: raise
    def replace(self, source, target):
        self.files[str(target)] = self.files.pop(str(source))
        self.modes[str(target)] = self.modes.pop(str(source), 0o600)
    def write_owned(self, name, content, mode=0o644):
        candidate = BACKUP + '/candidate'; self.files[candidate] = content
        self.execute('expect-file', name, candidate, oct(mode))
        self.files[name] = content; self.modes[name] = mode
    def set_owned(self, key, value):
        self.execute('expect-sysctl', key, value); self.values[key] = value


class NetworkRuntimeTests(unittest.TestCase):
    def test_private_backup_does_not_change_restored_sysctl_permissions(self):
        model = Model()
        filename = '/etc/sysctl.d/99-mxh-vps-deploy.conf'
        original = b'# Managed by MXH VPS Deploy.\nnet.core.default_qdisc = fq_codel\n'
        model.files[filename] = original
        model.modes[filename] = 0o644
        model.execute('snapshot')
        model.write_owned(filename, b'# Managed by MXH VPS Deploy.\nnet.core.default_qdisc = fq\n', 0o644)
        model.execute('restore')
        self.assertEqual(model.files[filename], original)
        self.assertEqual(model.modes[filename], 0o644)

    def test_previous_owned_queue_snapshot_remains_recoverable(self):
        model = Model(); model.execute('snapshot')
        filename = BACKUP + '/network-state.json'
        state = json.loads(model.files[filename])
        state['Files'].pop('/etc/sysctl.d/99-mxh-vps-deploy.conf')
        model.files[filename] = json.dumps(state).encode()
        model.execute('apply'); model.execute('restore')
        self.assertEqual(model.values, KEYS)

    def test_builtin_pfifo_fast_metadata_does_not_become_tc_arguments(self):
        model = Model(); model.queues[0] = {'kind': 'pfifo_fast', 'root': True, 'handle': '0:', 'options': copy.deepcopy(PFIFO_OPTIONS)}
        original = copy.deepcopy(model.queues)
        model.execute('preflight')
        self.assertEqual(model.queues, original)
        self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] for c in model.calls))
        model.execute('snapshot'); model.execute('apply'); model.execute('verify'); model.execute('restore')
        self.assertEqual(model.queues, original)
        self.assertEqual(model.values, KEYS)
        restores = [c for c in model.calls if c[:3] == ['tc', 'qdisc', 'replace'] and 'pfifo_fast' in c]
        self.assertEqual(restores, [['tc', 'qdisc', 'replace', 'dev', 'eth0', 'root', 'pfifo_fast']])

    def test_unreproducible_pfifo_fast_layout_is_refused_before_mutation(self):
        for change in ({'bands': 2}, {'bands': 3.0}, {'multiqueue': True}, {'multiqueue': 0},
                       {'priomap': [0] * 16}, {'priomap': [True] * 16}, {'unknown': 1}):
            with self.subTest(change=change):
                model = Model(); values = copy.deepcopy(PFIFO_OPTIONS); values.update(change)
                model.queues[0] = {'kind': 'pfifo_fast', 'root': True, 'handle': '0:', 'options': values}
                with self.assertRaises(SystemExit): model.execute('preflight')
                self.assertEqual(model.values, KEYS)
                self.assertNotIn(BACKUP + '/network-state.json', model.files)
                self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] for c in model.calls))

    def test_pfifo_fast_multiqueue_leaf_restore_keeps_root_and_other_leaf(self):
        model = Model(); model.queues = [{'kind': 'mq', 'root': True, 'handle': '0:', 'options': {}},
            {'kind': 'pfifo_fast', 'parent': ':1', 'handle': '0:', 'options': copy.deepcopy(PFIFO_OPTIONS)},
            {'kind': 'fq', 'parent': ':2', 'handle': '8001:', 'options': {'timer_slack': 10000}}]
        original = copy.deepcopy(model.queues)
        model.execute('snapshot'); model.execute('apply'); model.execute('verify'); model.execute('restore')
        self.assertEqual(model.queues, original)

    def test_preflight_does_not_change_runtime_or_create_snapshot(self):
        model = Model(); original = copy.deepcopy(model.values)
        model.execute('preflight')
        self.assertEqual(original, model.values)
        self.assertNotIn(BACKUP + '/network-state.json', model.files)
        self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] for c in model.calls))

    def test_snapshot_apply_and_restore_runtime_and_persistence(self):
        model = Model(); queues = copy.deepcopy(model.queues)
        model.execute('snapshot'); model.execute('apply'); model.execute('verify')
        model.set_owned('net.core.default_qdisc', 'fq'); model.set_owned('net.ipv4.tcp_congestion_control', 'bbr')
        for name in ('/usr/local/libexec/mxh-network-queue', '/etc/systemd/system/mxh-network-queue.service'):
            model.write_owned(name, b'# Managed by MXH VPS Deploy.\n', 0o750 if name.endswith('mxh-network-queue') else 0o644)
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

    def test_managed_marker_does_not_allow_overwriting_external_edit(self):
        model = Model(); name = '/etc/sysctl.d/99-mxh-vps-deploy.conf'
        model.files[name] = b'# Managed by MXH VPS Deploy.\nnet.ipv4.tcp_fastopen = 3\n'; model.modes[name] = 0o644
        model.execute('snapshot'); model.write_owned(name, b'# Managed by MXH VPS Deploy.\nnet.core.default_qdisc = fq\n')
        external = b'# Managed by MXH VPS Deploy.\nnet.ipv4.tcp_fastopen = 0\n'; model.files[name] = external
        calls = len(model.calls)
        with self.assertRaisesRegex(SystemExit, 'changed externally'): model.execute('restore')
        self.assertEqual(model.files[name], external)
        self.assertFalse(any(c[:3] == ['tc', 'qdisc', 'replace'] or c[:2] == ['sysctl', '-w'] for c in model.calls[calls:]))

    def test_modified_fq_options_after_apply_are_not_restored_over(self):
        model = Model(); model.execute('snapshot'); model.execute('apply')
        model.queues[0]['options'] = {'limit': 321}; current = copy.deepcopy(model.queues)
        with self.assertRaisesRegex(SystemExit, 'changed externally'): model.execute('restore')
        self.assertEqual(model.queues, current)

    def test_externally_changed_runtime_buffers_are_not_overwritten(self):
        model = Model(); model.execute('snapshot'); model.set_owned('net.core.default_qdisc', 'fq')
        model.set_owned('net.core.rmem_max', '123456')
        model.values['net.core.rmem_max'] = '333333'
        with self.assertRaisesRegex(SystemExit, 'changed externally'): model.execute('restore')
        self.assertEqual(model.values['net.core.rmem_max'], '333333')

    def test_unselected_runtime_changes_do_not_block_scoped_restore(self):
        model = Model(); model.execute('snapshot'); model.set_owned('net.core.default_qdisc', 'fq')
        model.values['net.core.rmem_max'] = '333333'
        model.execute('restore')
        self.assertEqual(model.values['net.core.rmem_max'], '333333')
        self.assertEqual(model.values['net.core.default_qdisc'], KEYS['net.core.default_qdisc'])


if __name__ == '__main__': unittest.main()
