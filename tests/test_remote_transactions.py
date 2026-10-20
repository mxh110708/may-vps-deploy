"""Execute transaction guards in an isolated filesystem with mocked systemctl/flock.

These tests validate branching/ownership, not real systemd scheduling or Linux locks.
No production paths or services are touched.
"""
import argparse
import base64
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = None


def shell_path(path):
    value = Path(path).as_posix()
    if os.name == 'nt' and len(value) > 1 and value[1] == ':':
        value = '/' + value[0].lower() + value[2:]
    return value


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='transaction-tests-', dir=ROOT / '.tmp')
        self.root = Path(self.directory.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.backup = self.root / 'backups' / '20260909-120000' / 'protocol-lifecycle'
        self.backup.mkdir(parents=True)
        self.owner = self.state / 'transaction.owner'
        self.owner.write_text(shell_path(self.backup) + '\n', encoding='utf-8')

    def tearDown(self):
        self.directory.cleanup()

    def run_script(self, name, *, expected=None, active='', lock_fail=False, prefix_only=False, action='Status'):
        source = (ROOT / 'assets' / 'remote' / name).read_text(encoding='utf-8')
        if prefix_only:
            source = source.split('stamp="$(date', 1)[0] + "\nprintf 'GUARD_PASSED\\n'\n"
        source = source.replace('/var/lib/may-vps-deploy', shell_path(self.state))
        source = source.replace('/root/vps-deploy-backups', shell_path(self.root / 'backups'))
        source = source.replace('/etc/systemd/system', shell_path(self.root / 'units'))
        source = source.replace('/usr/local/libexec', shell_path(self.root / 'helpers'))
        preamble = r'''
flock() { return "${MOCK_LOCK_FAIL:-0}"; }
install() { mkdir -p "${@: -1}"; }
systemctl() {
  printf '%s\n' "$*" >> "$MOCK_CALLS"
  case "$1" in
    is-active) [[ -n "$MOCK_ACTIVE" && "$*" == *"$MOCK_ACTIVE"* ]];;
    is-failed) return 1;;
    disable) if [[ "$*" == *--now* && "$*" == *"$MOCK_ACTIVE"* ]]; then MOCK_ACTIVE=''; fi; return 0;;
    *) return 0;;
  esac
}
'''
        env = dict(os.environ, MOCK_CALLS=shell_path(self.root / 'calls'), MOCK_ACTIVE=active,
                   MOCK_LOCK_FAIL='1' if lock_fail else '0', VPS_PARAM_EXPECTED_BACKUP=expected or shell_path(self.backup),
                   VPS_PARAM_SOURCE_ROLE='RealityEntry', VPS_PARAM_TARGET_ROLE='AnyTlsEntry',
                   VPS_PARAM_TIMEOUT_MINUTES='20', VPS_PARAM_ACTION=action)
        env.update(VPS_PARAM_KEEP_LATEST='0', VPS_PARAM_CHECK_ONLY='false')
        return subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble + source,
                              text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=10, env=env)

    def test_arm_refuses_owner(self):
        result = self.run_script('protocol-migration-arm-rollback.sh', prefix_only=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.owner.exists())

    def test_arm_refuses_active_legacy_timer(self):
        self.owner.unlink()
        result = self.run_script('protocol-migration-arm-rollback.sh', prefix_only=True,
                                 active='mxh-protocol-migration-rollback.timer')
        self.assertNotEqual(result.returncode, 0)

    def test_arm_refuses_ssh_timer(self):
        self.owner.unlink()
        result = self.run_script('protocol-migration-arm-rollback.sh', prefix_only=True,
                                 active='mxh-ssh-maintenance-rollback.timer')
        self.assertNotEqual(result.returncode, 0)

    def test_arm_lock_failure(self):
        self.owner.unlink()
        self.assertNotEqual(self.run_script('protocol-migration-arm-rollback.sh', prefix_only=True, lock_fail=True).returncode, 0)

    def test_clean_arm_guard(self):
        self.owner.unlink()
        result = self.run_script('protocol-migration-arm-rollback.sh', prefix_only=True)
        self.assertIn('GUARD_PASSED', result.stdout, result.stderr)

    def test_wrong_commit_identity(self):
        self.assertNotEqual(self.run_script('maintenance-transaction-commit.sh', expected=shell_path(self.backup) + '-wrong').returncode, 0)
        self.assertTrue(self.owner.exists())

    def test_commit_and_repeat(self):
        self.assertEqual(self.run_script('maintenance-transaction-commit.sh').returncode, 0)
        self.assertFalse(self.owner.exists())
        self.assertTrue((self.backup / 'transaction-committed').exists())
        self.assertEqual(self.run_script('maintenance-transaction-commit.sh').returncode, 0)

    def test_commit_after_rollback_rejected(self):
        (self.backup / 'rollback-executed').touch()
        self.assertNotEqual(self.run_script('maintenance-transaction-commit.sh').returncode, 0)

    def test_commit_after_deadline_is_refused(self):
        (self.backup/'deadline-epoch').write_text(str(int(time.time())-30))
        self.assertNotEqual(self.run_script('maintenance-transaction-commit.sh').returncode,0)
        self.assertTrue(self.owner.exists())

    def test_running_rollback_blocks_commit(self):
        result = self.run_script('maintenance-transaction-commit.sh', active='mxh-protocol-migration-rollback.service')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.owner.exists())

    def test_wrong_rollback_identity(self):
        result = self.run_script('protocol-migration-trigger-rollback.sh', expected=shell_path(self.backup) + '-wrong')
        self.assertNotEqual(result.returncode, 0)

    def test_preparing_lock_release(self):
        self.assertEqual(self.run_script('maintenance-transaction-status.sh', action='ReleaseUnarmed').returncode, 0)
        self.assertFalse(self.owner.exists())

    def test_armed_lock_cannot_release(self):
        (self.backup / 'transaction-armed').touch()
        self.assertNotEqual(self.run_script('maintenance-transaction-status.sh', action='ReleaseUnarmed').returncode, 0)
        self.assertTrue(self.owner.exists())

    def test_status_uses_controller_marker_contract(self):
        (self.backup / 'transaction-armed').touch()
        result = self.run_script('maintenance-transaction-status.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        encoded = next(line.split('=', 1)[1] for line in result.stdout.splitlines()
                       if line.startswith('VPSDEPLOY_TRANSACTION_PHASE_B64='))
        self.assertEqual(base64.b64decode(encoded).decode('utf-8'), 'Armed')

    def test_active_ssh_lock_cannot_release(self):
        result = self.run_script('maintenance-transaction-status.sh', action='ReleaseUnarmed', active='mxh-ssh-maintenance-rollback.timer')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.owner.exists())

    def test_unowned_arming_is_verified_without_releasing_a_lock(self):
        self.owner.unlink()
        result = self.run_script('maintenance-transaction-status.sh', action='VerifyUnowned')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('VPSDEPLOY_UNOWNED_TRANSACTION_CLEAR', result.stdout)

    def test_unowned_verification_refuses_owner_active_rollback_and_lock_failure(self):
        self.assertNotEqual(self.run_script('maintenance-transaction-status.sh', action='VerifyUnowned').returncode, 0)
        self.assertTrue(self.owner.exists())
        self.owner.unlink()
        for unit in ['mxh-protocol-migration-rollback.timer', 'mxh-protocol-migration-rollback.service', 'mxh-ssh-maintenance-rollback.timer', 'mxh-ssh-maintenance-rollback.service']:
            self.assertNotEqual(self.run_script('maintenance-transaction-status.sh', action='VerifyUnowned', active=unit).returncode, 0)
        self.assertNotEqual(self.run_script('maintenance-transaction-status.sh', action='VerifyUnowned', lock_fail=True).returncode, 0)

    def completed_rollback(self, matching=True):
        self.owner.unlink()
        (self.backup / 'rollback-executed').touch()
        units = self.root / 'units'
        units.mkdir()
        directory = shell_path(self.backup) if matching else '/unknown/transaction'
        (units / 'mxh-protocol-migration-rollback.service').write_text('ExecStart=' + shell_path(self.root / 'helpers') + '/mxh-protocol-migration-rollback ' + directory + ' --transaction\n')

    def test_completed_rollback_disarms_only_its_own_elapsed_timer(self):
        self.completed_rollback()
        result = self.run_script('protocol-migration-trigger-rollback.sh', active='mxh-protocol-migration-rollback.timer')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / 'calls').read_text()
        self.assertIn('disable --now mxh-protocol-migration-rollback.timer', calls)
        self.assertNotIn('start mxh-protocol-migration-rollback.service', calls)

    def test_completed_rollback_refuses_another_timer_owner(self):
        self.completed_rollback(matching=False)
        result = self.run_script('protocol-migration-trigger-rollback.sh', active='mxh-protocol-migration-rollback.timer')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('disable --now', (self.root / 'calls').read_text())

    def mutation(self, *, expired=False, changed_owner=False):
        source=(ROOT/'assets/remote/maintenance-mutation-guard.sh').read_text()
        source=source.replace('/var/lib/may-vps-deploy',shell_path(self.state)).replace('/root/vps-deploy-backups',shell_path(self.root/'backups'))
        (self.backup/'deadline-epoch').write_text(str(int(time.time())+(-30 if expired else 300)))
        if changed_owner:
            self.owner.write_text('different-owner')
        env=dict(os.environ,VPS_PARAM_EXPECTED_TRANSACTION=shell_path(self.backup))
        return subprocess.run([BASH,'--noprofile','--norc','-s'],input='flock(){ return 0; }\n'+source+'\nvps_begin_mutation || exit 1\nprintf WRITE_ALLOWED\\n\n',text=True,capture_output=True,timeout=10,env=env)

    def test_expired_write_is_refused_before_mutation(self):
        result=self.mutation(expired=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('WRITE_ALLOWED',result.stdout)

    def test_changed_owner_is_refused_before_mutation(self):
        self.assertNotEqual(self.mutation(changed_owner=True).returncode,0)

    def test_current_transaction_allows_write(self):
        self.assertEqual(self.mutation().returncode,0)

    def test_prune_refuses_unarmed_owner_running_restore_and_concurrent_writer(self):
        self.assertNotEqual(self.run_script('protocol-backup-prune.sh').returncode, 0)
        self.assertTrue(self.backup.exists()); self.owner.unlink()
        for unit in ('mxh-protocol-migration-rollback.service', 'mxh-ssh-maintenance-rollback.service'):
            self.assertNotEqual(self.run_script('protocol-backup-prune.sh', active=unit).returncode, 0)
            self.assertTrue(self.backup.exists())
        self.assertNotEqual(self.run_script('protocol-backup-prune.sh', lock_fail=True).returncode, 0)
        self.assertTrue(self.backup.exists())


class MaintenanceRuntimeTests(unittest.TestCase):
    def run_isolated(self, name, preamble, parameters, *, matching_process=True):
        with tempfile.TemporaryDirectory(prefix='maintenance-runtime-', dir=ROOT / '.tmp') as folder:
            root = Path(folder)
            source = (ROOT / 'assets' / 'remote' / name).read_text(encoding='utf-8')
            for prefix in ('/usr/local', '/etc', '/proc', '/root/vps-deploy-backups'):
                source = source.replace(prefix, shell_path(root) + prefix)
            binary = root / 'usr/local/bin/sing-box-anytls'
            binary.parent.mkdir(parents=True)
            binary.write_text('#!/usr/bin/env bash\nexit 0\n', encoding='utf-8')
            binary.chmod(0o755)
            config = root / 'etc/sing-box-anytls/config.json'
            config.parent.mkdir(parents=True)
            config.write_text('{}', encoding='utf-8')
            proc = root / 'proc/123/exe'
            proc.parent.mkdir(parents=True)
            if matching_process:
                os.link(binary, proc)
            else:
                proc.write_text('old binary', encoding='utf-8')
            backup = root / 'root/vps-deploy-backups/20260910-010101/protocol-lifecycle'
            backup.mkdir(parents=True)
            (backup / 'protocol-files.tar.gz').touch()
            rollback = root / 'usr/local/libexec/mxh-protocol-migration-rollback'
            rollback.parent.mkdir(parents=True)
            rollback.write_text('#!/usr/bin/env bash\nexit 0\n', encoding='utf-8')
            rollback.chmod(0o755)
            env = dict(os.environ, CALLS=shell_path(root / 'calls'),
                       VPS_PARAM_BACKUP_PATH=shell_path(backup), **parameters)
            result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=preamble + source,
                                    text=True, encoding='utf-8', capture_output=True, timeout=15, env=env)
            calls = (root / 'calls').read_text() if (root / 'calls').exists() else ''
            return result, calls

    def test_upgrade_restarts_only_target_and_checks_running_binary(self):
        preamble = '''
systemctl() {
  echo "$*" >> "$CALLS"
  case "$1" in
    show) echo 123;;
    is-active|is-enabled) [[ "$*" == *sing-box-anytls.service* ]];;
    *) return 0;;
  esac
}
'''
        params = dict(VPS_PARAM_REALITY_ENABLED='false', VPS_PARAM_ANYTLS_ENABLED='true',
                      VPS_PARAM_SHADOWSOCKS_ENABLED='false', VPS_PARAM_RESTART_ROLE='AnyTlsEntry')
        result, calls = self.run_isolated('protocol-lifecycle-apply-state.sh', preamble, params)
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertIn('restart sing-box-anytls.service', calls)
        self.assertNotIn('restart xray.service', calls)
        result, _ = self.run_isolated('protocol-lifecycle-apply-state.sh', preamble, params, matching_process=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not match', result.stderr)
        params.pop('VPS_PARAM_RESTART_ROLE')
        result, calls = self.run_isolated('protocol-lifecycle-apply-state.sh', preamble, params)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('restart ', calls)

    def test_rotation_rejects_external_config_change_before_restart(self):
        result,calls=self.run_isolated('maintenance-protocol-config-apply.sh','systemctl(){ echo "$*" >> "$CALLS"; }\n',
            {'VPS_PARAM_ROLE':'AnyTlsEntry','VPS_PARAM_CONFIG_JSON':'{}','VPS_PARAM_EXPECTED_CONFIG_SHA256':'0'*64,'VPS_PARAM_WAS_ACTIVE':'true'})
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('restart ',calls)

    def test_config_restore_checks_nginx_before_reload(self):
        preamble = '''
tar() { return 0; }
systemctl() {
  echo "$*" >> "$CALLS"
  if [[ "$1" == is-active ]]; then [[ "$*" == *nginx.service* ]]; else return 0; fi
}
nginx() { echo "nginx $*" >> "$CALLS"; return "${NGINX_FAIL:-0}"; }
'''
        result, calls = self.run_isolated('maintenance-restore-apply.sh', preamble, dict(VPS_PARAM_SCOPE='ConfigOnly'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(calls.index('nginx -t'), calls.index('reload nginx.service'))
        result, calls = self.run_isolated('maintenance-restore-apply.sh', preamble, dict(VPS_PARAM_SCOPE='ConfigOnly', NGINX_FAIL='1'))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('reload nginx.service', calls)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bash', required=True)
    args = parser.parse_args()
    BASH = args.bash
    (ROOT / '.tmp').mkdir(exist_ok=True)
    unittest.main(argv=[__file__], verbosity=2)
