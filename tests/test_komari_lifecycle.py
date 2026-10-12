"""Komari 1.5 lifecycle branches in a disposable filesystem with fake services.

No real systemctl, network request, user account, database or VPS is used.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = None


def shell_path(path):
    value = Path(path).as_posix()
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' and len(value) > 1 and value[1] == ':' else value


PREAMBLE = r'''
uname(){ echo x86_64; }
python3(){
  local converted=() argument
  for argument in "$@"; do converted+=("${argument//$TEST_ROOT/$TEST_NATIVE_ROOT}"); done
  "$TEST_PYTHON" "${converted[@]}"
}
systemctl(){
  echo "$*" >> "$CALLS"
  local service="${@: -1}" state_file="$TEST_ROOT/active" binary="$SERVICE_BINARY" pid=123
  if [[ "$service" == cloudflared.service ]]; then
    state_file="$TEST_ROOT/tunnel-active"; binary="$TEST_ROOT/usr/local/bin/cloudflared"; pid=234
  fi
  case "$1" in
    cat) [[ "$service" != cloudflared.service || -f "$TEST_ROOT/etc/systemd/system/cloudflared.service" ]] ;;
    is-active) [[ "$(cat "$state_file")" == true ]] ;;
    is-enabled) if [[ "$service" == cloudflared.service ]]; then [[ "$TUNNEL_ENABLED" == true ]]; else [[ "$WAS_ENABLED" == true ]]; fi ;;
    stop|disable)
      if [[ "$1" == stop || "$*" == *--now* ]] && [[ "$SERVICE_STOP_STILL_ACTIVE" != true ]]; then echo false > "$state_file"; fi
      return 0 ;;
    start|restart)
      if [[ "$SERVICE_START_FAILS" == true ]]; then echo false > "$state_file"; return 1; fi
      if [[ "$service" == cloudflared.service && "$TUNNEL_START_FAILS" == true && ! -e "$TEST_ROOT/tunnel-start-failed" ]]; then
        touch "$TEST_ROOT/tunnel-start-failed"; echo false > "$state_file"; return 1
      fi
      echo true > "$state_file"
      [[ "$STALE_PID" == true ]] || ln -f "$binary" "$TEST_ROOT/proc/$pid/exe"
      if [[ "$VPS_PARAM_ACTION" == TunnelRotate ]]; then
        if [[ "$TOKEN_FILE_LAYOUT" == true ]]; then printf 'cloudflared\0tunnel\0--token-file\0%s\0' "$TEST_NATIVE_ROOT/etc/cloudflared/mxh-token" > "$TEST_ROOT/proc/$pid/cmdline"
        else printf 'cloudflared\0tunnel\0--token\0%s\0' "$VPS_PARAM_TUNNEL_TOKEN" > "$TEST_ROOT/proc/$pid/cmdline"; fi
      fi
      if [[ "$*" == *komari.service* ]] && grep -Fq 'new-upgrade' "$binary"; then
        echo migrated > "$TEST_ROOT/opt/komari/data/komari.db"
        echo new-metrics > "$TEST_ROOT/opt/komari/data/metrics.db"
      fi ;;
    enable)
      if [[ "$*" == *--now* ]]; then
        echo true > "$state_file"
        [[ "$STALE_PID" == true ]] || ln -f "$binary" "$TEST_ROOT/proc/$pid/exe"
      fi ;;
    show)
      if [[ "$*" == *ExecStart* ]]; then printf '{ path=%s ; argv[]=%s server %s ; }\n' "$binary" "$binary" "$EXTRA_DB_ARGUMENTS"
      elif [[ "$*" == *MainPID* ]]; then echo "$pid"
      else echo "$TEST_ROOT/opt/komari"; fi ;;
    *) return 0 ;;
  esac
}
ss(){ echo "LISTEN 0 128 127.0.0.1:${VPS_PARAM_CONTROLLER_PORT:-25774} 0.0.0.0:*"; }
sleep(){ echo "sleep $*" >> "$CALLS"; }
install(){
  local args=()
  while (($#)); do
    case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
  done
  command install "${args[@]}"
  if [[ "$CORRUPT_INSTALL" == true && "$VPS_PARAM_ACTION" == AgentUpgrade ]]; then printf '\n# corrupt-install\n' >> "$SERVICE_BINARY"; fi
}
tar(){
  local args=()
  while (($#)); do
    if [[ "$1" == -C && "$2" == / ]]; then args+=(-C "$TEST_ROOT"); shift 2
    else args+=("$1"); shift; fi
  done
  command tar "${args[@]}"
}
curl(){
  local output='' url='' previous=''
  for arg in "$@"; do
    [[ "$previous" != --output ]] || output="$arg"
    [[ "$arg" != http* ]] || url="$arg"
    previous="$arg"
  done
  if [[ "$url" == *releases/download* ]]; then cp "$TEST_ROOT/new-binary" "$output"
  elif [[ "$url" == *database-migration/auth ]]; then
    printf '%s' "$MIGRATION_BODY" > "$output"; printf '%s' "$MIGRATION_CODE"
  elif [[ "$url" == */api/version ]]; then
    printf '%s' "$VERSION_BODY" > "$output"; printf '%s' "$VERSION_CODE"
  else printf '%s' "$HOME_CODE"; fi
}
'''


class KomariLifecycleTests(unittest.TestCase):
    def run_case(self, action, *, active=True, enabled=True, migration_code='404', body='{}', home_code='200', bad_version=False,
                 extra_db_arguments='', version_code='200', version_body=None, binary_location='opt/komari/komari', stale_pid=False,
                 bad_checksum=False, corrupt_install=False, service_start_fails=False, unsafe_archive=False, service_stop_still_active=False,
                 tunnel=False, include_tunnel=False, incomplete_tunnel=False, tunnel_active=True, tunnel_enabled=True,
                 tunnel_start_fails=False, project_backup=False, final_active=True, token_file=False, download_url=None, controller_port='25774'):
        with tempfile.TemporaryDirectory(prefix='komari-lifecycle-', dir=ROOT / '.tmp') as folder:
            root = Path(folder)
            script = (ROOT / 'assets/remote/maintenance-komari.sh').read_text(encoding='utf-8')
            for prefix in ('/usr/local', '/usr/bin', '/etc', '/var/lib', '/opt', '/root', '/proc'):
                script = script.replace(prefix, shell_path(root) + prefix)
            # Fixture ownership belongs to the test runner; production requires root.
            script = script.replace('st.st_uid!=0', 'st.st_uid!='+str(os.getuid() if hasattr(os,'getuid') else 0))
            script = script.replace('"/$p"', '"$TEST_ROOT/$p"')
            for relative in ('opt/komari/data/plugin', 'opt/komari/data/plguin-data', 'opt/komari/data/theme', 'root/vps-deploy-backups', 'etc/komari-agent', 'etc/systemd/system', 'usr/local/bin', 'proc/123', 'proc/234', 'tmp'):
                (root / relative).mkdir(parents=True, exist_ok=True)
            (root / 'active').write_text(str(active).lower())
            (root / 'tunnel-active').write_text(str(tunnel_active and (tunnel or action in ('TunnelRotate','TunnelUpgrade'))).lower())
            (root / 'opt/komari/data/komari.db').write_text('old-db')
            (root / 'opt/komari/data/plugin/fixture').write_text('old-plugin')
            old_binary = root / ('usr/local/bin/komari-agent' if action == 'AgentUpgrade' else 'usr/local/bin/cloudflared' if action in ('TunnelRotate','TunnelUpgrade') else binary_location)
            old_binary.write_text('#!/usr/bin/env bash\necho "Komari Monitor 1.4.3"\n[[ "$1" == --help ]] || exit 1\n')
            old_binary.chmod(0o755)
            tunnel_binary = root / 'usr/local/bin/cloudflared'
            tunnel_unit = root / 'etc/systemd/system/cloudflared.service'
            if tunnel:
                tunnel_binary.write_text('archived-tunnel-binary'); tunnel_binary.chmod(0o755)
                tunnel_unit.write_text('archived-tunnel-unit')
            managed_token = root / 'etc/cloudflared/mxh-token'
            if token_file:
                managed_token.parent.mkdir(parents=True)
                managed_token.write_text('fixture-old-token')
                tunnel_unit.write_text('Type=notify\nUser=cloudflared\nExecStart=' + shell_path(tunnel_binary) + ' tunnel --metrics 127.0.0.1:20241 run --token-file ' + shell_path(managed_token) + '\n')
            original_unit = tunnel_unit.read_bytes() if tunnel_unit.exists() else None
            token_config = root / 'etc/komari-agent/config.json'
            token_config.write_text('{"token":"fixture-token","disable_web_ssh":true}')
            before_token = token_config.read_bytes()
            version = '1.5.11' if action == 'AgentUpgrade' else '2026.10.0' if action=='TunnelUpgrade' else '1.5.1'
            new_text = '#!/usr/bin/env bash\n# new-upgrade\necho "Komari Monitor ' + ('0.0.0' if bad_version else version) + '"\n[[ "$1" == --help ]] || exit 1\n'
            if action == 'AgentUpgrade':
                # The real Agent has no --version interface. Any direct invocation
                # of this fixture is a preflight bug, not a successful version check.
                new_text = '#!/usr/bin/env bash\n# new-upgrade\necho "agent-binary-executed" >> "$CALLS"\necho "unsupported agent preflight invocation" >&2\nexit 64\n'
            if action=='TunnelUpgrade':
                new_text='#!/usr/bin/env bash\n# new-upgrade\necho "cloudflared version '+('0.0.0' if bad_version else version)+'"\n[[ "$1" == --version ]] || exit 1\n'
            new_binary = root / 'new-binary'
            with new_binary.open('w', encoding='utf-8', newline='\n') as output:
                output.write(new_text)
            backup = root / 'root/komari-controller-20260930-010101.tar.gz'
            members = ['opt/komari']
            if not old_binary.is_relative_to(root / 'opt/komari') and action != 'AgentUpgrade':
                members.append(old_binary.relative_to(root).as_posix())
            if include_tunnel:
                members.append(tunnel_binary.relative_to(root).as_posix())
                if not incomplete_tunnel:
                    members.append(tunnel_unit.relative_to(root).as_posix())
            packed = subprocess.run([BASH, '-c', 'root="$1"; archive="$2"; shift 2; tar -czpf "$archive" -C "$root" "$@"', '--', shell_path(root), shell_path(backup), *members], capture_output=True, text=True)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            if action=='ControllerRestore':
                (root/'opt/komari/data/komari.db').write_text('new-db')
                (root/'opt/komari/data/metrics.db').write_text('new-metrics')
                if tunnel:
                    tunnel_binary.write_text('current-tunnel-binary'); tunnel_unit.write_text('current-tunnel-unit')
            if unsafe_archive:
                with tarfile.open(backup,'w:gz') as archive:
                    member=tarfile.TarInfo('../escape');member.size=1
                    archive.addfile(member,io.BytesIO(b'x'))
            environment = dict(os.environ, TEST_ROOT=shell_path(root), TEST_NATIVE_ROOT=root.as_posix(), CALLS=shell_path(root / 'calls'),
                TMPDIR=shell_path(root / 'tmp'), TEST_PYTHON=shell_path(sys.executable), WAS_ENABLED=str(enabled).lower(), MIGRATION_CODE=migration_code,
                MIGRATION_BODY=body, HOME_CODE=home_code, EXTRA_DB_ARGUMENTS=extra_db_arguments, VERSION_CODE=version_code,
                VERSION_BODY=version_body if version_body is not None else json.dumps({'data': {'version': version}}),
                SERVICE_BINARY=shell_path(old_binary), STALE_PID=str(stale_pid).lower(), VPS_PARAM_ACTION=action, VPS_PARAM_VERSION=version,
                CORRUPT_INSTALL=str(corrupt_install).lower(), SERVICE_START_FAILS=str(service_start_fails).lower(),
                SERVICE_STOP_STILL_ACTIVE=str(service_stop_still_active).lower(),
                TUNNEL_ENABLED=str(tunnel_enabled).lower(), TUNNEL_START_FAILS=str(tunnel_start_fails).lower(),
                TOKEN_FILE_LAYOUT=str(token_file).lower(),VPS_PARAM_CONTROLLER_PORT=controller_port,
                VPS_PARAM_FINAL_ACTIVE=str(final_active).lower(), VPS_PARAM_INCLUDE_TUNNEL='false',
                VPS_PARAM_TUNNEL_TOKEN='fixture-rotated-token',PATH=shell_path(root/'usr/local/bin')+os.pathsep+os.environ['PATH'],
                VPS_PARAM_ASSET_NAME='komari-agent-linux-amd64' if action == 'AgentUpgrade' else 'cloudflared-linux-amd64' if action=='TunnelUpgrade' else 'komari-linux-amd64',
                VPS_PARAM_SHA256='0' * 64 if bad_checksum else hashlib.sha256(new_binary.read_bytes()).hexdigest(), VPS_PARAM_BACKUP_FILE=shell_path(backup))
            if action == 'ControllerVerify':
                with old_binary.open('w', encoding='utf-8', newline='\n') as output:
                    output.write(new_text)
                old_binary.chmod(0o755)
            if download_url is not None:environment['VPS_PARAM_DOWNLOAD_URL']=download_url
            if action in ('AgentUpgrade','ControllerUpgrade','TunnelUpgrade'):shutil.copyfile(old_binary,root/'proc/123/exe')
            else:os.link(old_binary, root / 'proc/123/exe')
            if tunnel_binary.exists():
                if action=='TunnelUpgrade':shutil.copyfile(tunnel_binary,root/'proc/234/exe')
                else:os.link(tunnel_binary, root / 'proc/234/exe')
            if project_backup:
                (root/'opt/komari/data/komari.db').write_text('old-db')
                (root/'opt/komari/data/metrics.db').unlink()
                backup_env = dict(environment, VPS_PARAM_ACTION='ControllerBackup')
                backup_result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=PREAMBLE + script,
                    capture_output=True, text=True, encoding='utf-8', timeout=20, env=backup_env)
                self.assertEqual(backup_result.returncode, 0, backup_result.stderr)
                marker = next(line for line in backup_result.stdout.splitlines() if line.startswith('VPSDEPLOY_KOMARI_BACKUP_B64='))
                environment['VPS_PARAM_BACKUP_FILE'] = base64.b64decode(marker.split('=', 1)[1]).decode()
                (root/'opt/komari/data/komari.db').write_text('new-db')
                (root/'opt/komari/data/metrics.db').write_text('new-metrics')
            result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=PREAMBLE + script,
                                    capture_output=True, text=True, encoding='utf-8', timeout=20, env=environment)
            calls = (root / 'calls').read_text() if (root / 'calls').exists() else ''
            current = (root / 'opt/komari/data/komari.db').read_text()
            result.binary_contents = old_binary.read_text()
            result.service_active = (root / ('tunnel-active' if action in ('TunnelRotate','TunnelUpgrade') else 'active')).read_text().strip() == 'true'
            result.tunnel_active = (root / 'tunnel-active').read_text().strip() == 'true'
            result.tunnel_binary = tunnel_binary.read_text() if tunnel_binary.exists() else None
            result.tunnel_unit = tunnel_unit.read_text() if tunnel_unit.exists() else None
            result.unit_preserved = original_unit is not None and original_unit == tunnel_unit.read_bytes()
            result.managed_token = managed_token.read_text() if managed_token.exists() else None
            result.quarantined_metrics = len(list((root / 'root/vps-deploy-backups').glob('komari-failed-upgrade-*/**/metrics.db')))
            result.restore_quarantine_metrics=len(list((root/'root/vps-deploy-backups').glob('komari-controller-restore-*/previous-data-*/**/metrics.db')))
            return result, calls, current, (root / 'opt/komari/data/metrics.db').exists(), before_token == token_config.read_bytes()

    def marker(self, output):
        line = next(line for line in output.splitlines() if line.startswith('VPSDEPLOY_KOMARI_MIGRATION_REQUIRED_B64='))
        return base64.b64decode(line.split('=', 1)[1]).decode()

    def test_latest_tag_url_is_exact_and_untrusted_origin_is_refused(self):
        result,_,_,_,_=self.run_case('AgentUpgrade', download_url='https://github.com/komari-monitor/komari-agent/releases/download/v1.5.11/komari-agent-linux-amd64')
        self.assertEqual(result.returncode,0,result.stderr)
        result,calls,_,_,preserved=self.run_case('AgentUpgrade',download_url='https://example.com/program')
        self.assertNotEqual(result.returncode,0);self.assertNotIn('restart',calls);self.assertTrue(preserved)

    def test_controller_upgrade_reuses_custom_loopback_port(self):
        result,_,_,_,_=self.run_case('ControllerUpgrade',controller_port='35074')
        self.assertEqual(result.returncode,0,result.stderr)
        for invalid in ('0','65536','35074;echo bad'):
            result,calls,_,_,_=self.run_case('ControllerUpgrade',controller_port=invalid)
            self.assertNotEqual(result.returncode,0);self.assertNotIn('stop',calls)

    def test_tunnel_program_upgrade_preserves_token_unit_and_activation(self):
        result,calls,_,_,preserved=self.run_case('TunnelUpgrade',tunnel=True,token_file=True,tunnel_active=False,tunnel_enabled=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('new-upgrade',result.binary_contents);self.assertTrue(result.unit_preserved)
        self.assertEqual(result.managed_token,'fixture-old-token');self.assertFalse(result.tunnel_active)
        self.assertNotIn('restart cloudflared',calls);self.assertTrue(preserved)

    def test_tunnel_upgrade_bad_hash_or_version_never_restarts(self):
        for options in ({'bad_checksum':True},{'bad_version':True}):
            result,calls,_,_,_=self.run_case('TunnelUpgrade',tunnel=True,token_file=True,**options)
            self.assertNotEqual(result.returncode,0);self.assertNotIn('restart',calls)
            self.assertTrue(result.unit_preserved);self.assertEqual(result.managed_token,'fixture-old-token')

    def test_migration_guide_is_pending_not_completed(self):
        result, _, _, _, _ = self.run_case('ControllerUpgrade', migration_code='200', body=json.dumps({'data': {'mode': 'metric_store_restructure'}}))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker(result.stdout), 'true')

    def test_manual_restore_removes_new_metrics_and_reports_actual_old_version(self):
        result,_,database,metrics,_=self.run_case('ControllerRestore')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(database,'old-db');self.assertFalse(metrics)
        self.assertEqual(result.restore_quarantine_metrics,1)
        line=next(line for line in result.stdout.splitlines() if line.startswith('VPSDEPLOY_KOMARI_RESTORED_VERSION_B64='))
        self.assertEqual(base64.b64decode(line.split('=',1)[1]).decode(),'1.4.3')

    def test_failed_manual_restore_recovers_the_current_database_and_metrics(self):
        result,_,database,metrics,_=self.run_case('ControllerRestore',home_code='500')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(database,'new-db');self.assertTrue(metrics)

    def test_project_controller_only_backup_restore_leaves_current_tunnel_untouched(self):
        result,calls,database,_,_=self.run_case('ControllerRestore',tunnel=True,project_backup=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(database,'old-db')
        self.assertEqual(result.tunnel_binary,'current-tunnel-binary')
        self.assertEqual(result.tunnel_unit,'current-tunnel-unit')
        self.assertTrue(result.tunnel_active)
        self.assertNotIn('cloudflared.service',calls)

    def test_failed_controller_only_restore_does_not_restart_or_replace_tunnel(self):
        result,calls,database,metrics,_=self.run_case('ControllerRestore',tunnel=True,home_code='500')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(database,'new-db');self.assertTrue(metrics)
        self.assertEqual(result.tunnel_binary,'current-tunnel-binary')
        self.assertEqual(result.tunnel_unit,'current-tunnel-unit')
        self.assertTrue(result.tunnel_active)
        self.assertNotIn('cloudflared.service',calls)

    def test_controller_only_restore_preserves_inactive_tunnel_and_final_controller_state(self):
        result,calls,_,_,_=self.run_case('ControllerRestore',tunnel=True,tunnel_active=False,tunnel_enabled=False,final_active=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(result.tunnel_active);self.assertFalse(result.service_active)
        self.assertEqual(result.tunnel_unit,'current-tunnel-unit')
        self.assertNotIn('cloudflared.service',calls)

    def test_full_restore_replaces_and_restarts_only_included_tunnel(self):
        result,calls,database,_,_=self.run_case('ControllerRestore',tunnel=True,include_tunnel=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(database,'old-db')
        self.assertEqual(result.tunnel_binary,'archived-tunnel-binary')
        self.assertEqual(result.tunnel_unit,'archived-tunnel-unit')
        self.assertTrue(result.tunnel_active)
        self.assertIn('start cloudflared.service',calls)

    def test_full_restore_tunnel_restart_failure_rolls_back_current_files_and_data(self):
        result,_,database,metrics,_=self.run_case('ControllerRestore',tunnel=True,include_tunnel=True,tunnel_start_fails=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('VPSDEPLOY_KOMARI_LIFECYCLE_OK',result.stdout)
        self.assertEqual(database,'new-db');self.assertTrue(metrics)
        self.assertEqual(result.tunnel_binary,'current-tunnel-binary')
        self.assertEqual(result.tunnel_unit,'current-tunnel-unit')
        self.assertTrue(result.tunnel_active)

    def test_partial_tunnel_archive_is_rejected_before_stopping_services(self):
        result,calls,database,metrics,_=self.run_case('ControllerRestore',tunnel=True,include_tunnel=True,incomplete_tunnel=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('stop ',calls);self.assertNotIn('disable ',calls)
        self.assertEqual(database,'new-db');self.assertTrue(metrics)
        self.assertEqual(result.tunnel_unit,'current-tunnel-unit')

    def test_full_restore_does_not_start_an_inactive_tunnel(self):
        result,calls,_,_,_=self.run_case('ControllerRestore',tunnel=True,include_tunnel=True,tunnel_active=False,tunnel_enabled=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(result.tunnel_active)
        self.assertIn('disable cloudflared.service',calls)
        self.assertNotIn('start cloudflared.service',calls)

    def test_unsafe_manual_archive_is_rejected_before_service_changes(self):
        result,calls,database,metrics,_=self.run_case('ControllerRestore',unsafe_archive=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('stop ',calls);self.assertNotIn('enable ',calls)
        self.assertEqual(database,'new-db');self.assertTrue(metrics)

    def test_tunnel_rotation_restarts_the_live_process(self):
        result,calls,_,_,_=self.run_case('TunnelRotate')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('restart cloudflared.service',calls)
        self.assertNotIn('enable --now cloudflared.service',calls)

    def test_failed_tunnel_restart_cannot_commit_rotation(self):
        result,_,_,_,_=self.run_case('TunnelRotate',service_start_fails=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('VPSDEPLOY_KOMARI_LIFECYCLE_OK',result.stdout)

    def test_new_tunnel_token_file_rotation_preserves_service_and_keeps_token_out_of_unit(self):
        result,calls,_,_,_=self.run_case('TunnelRotate', token_file=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.unit_preserved)
        self.assertEqual(result.managed_token,'fixture-rotated-token')
        self.assertNotIn('fixture-rotated-token',result.tunnel_unit)
        self.assertIn('--token-file',result.tunnel_unit)
        self.assertIn('restart cloudflared.service',calls)

    def test_normal_controller_is_verified(self):
        result, _, _, _, _ = self.run_case('ControllerUpgrade')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker(result.stdout), 'false')

    def test_invalid_migration_response_rolls_back_database_and_binary(self):
        result, _, database, metrics, _ = self.run_case('ControllerUpgrade', migration_code='200', body='{"data":{"mode":"unknown"}}')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')
        self.assertFalse(metrics)
        self.assertIn('Komari Monitor 1.4.3', result.binary_contents)
        self.assertEqual(result.quarantined_metrics, 1)

    def test_normal_spa_fallback_requires_valid_version_api(self):
        result, _, _, _, _ = self.run_case('ControllerUpgrade', migration_code='200', body='<!doctype html><html>Komari</html>')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker(result.stdout), 'false')

    def test_spa_response_is_not_completion_when_version_api_is_html(self):
        result, _, database, metrics, _ = self.run_case('ControllerUpgrade', migration_code='200', body='<html>Komari</html>', version_body='<html>migration</html>')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')
        self.assertFalse(metrics)

    def test_version_api_mismatch_rolls_back(self):
        result, _, database, _, _ = self.run_case('ControllerUpgrade', version_body='{"data":{"version":"1.4.3"}}')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')

    def test_upgrade_uses_registered_service_binary(self):
        result, _, _, _, _ = self.run_case('ControllerUpgrade', binary_location='usr/local/bin/komari')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Komari Monitor 1.5.1', result.binary_contents)

    def test_running_process_must_use_replaced_binary(self):
        result, _, database, _, _ = self.run_case('ControllerUpgrade', stale_pid=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')

    def test_http_failure_restores_pre_migration_database(self):
        result, _, database, metrics, _ = self.run_case('ControllerUpgrade', home_code='500')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')
        self.assertFalse(metrics)

    def test_version_mismatch_rolls_back(self):
        result, _, database, metrics, _ = self.run_case('ControllerUpgrade', bad_version=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')
        self.assertFalse(metrics)

    def test_inactive_controller_stays_inactive_and_migration_is_deferred(self):
        result, calls, database, _, _ = self.run_case('ControllerUpgrade', active=False, enabled=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker(result.stdout), 'deferred')
        self.assertNotIn('start komari.service', calls)
        self.assertIn('disable komari.service', calls)
        self.assertEqual(database, 'old-db')

    def test_readonly_reverification_does_not_start_or_stop_controller(self):
        result, calls, _, _, _ = self.run_case('ControllerVerify')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker(result.stdout), 'false')
        self.assertNotIn('start ', calls)
        self.assertNotIn('stop ', calls)

    def test_agent_upgrade_preserves_token_and_enabled_state(self):
        result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade', enabled=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(token_unchanged)
        self.assertIn('restart komari-agent.service', calls)
        self.assertIn('disable komari-agent.service', calls)
        self.assertIn('show --property=MainPID --value komari-agent.service', calls)
        self.assertNotIn('agent-binary-executed', calls)
        self.assertTrue(result.service_active)

    def test_agent_upgrade_never_executes_unsupported_version_command(self):
        result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('agent-binary-executed', calls)
        self.assertNotIn('disable komari-agent.service', calls)
        self.assertTrue(token_unchanged)

    def test_inactive_agent_is_updated_without_starting_it(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade', active=False, enabled=enabled)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('new-upgrade', result.binary_contents)
                self.assertFalse(result.service_active)
                self.assertTrue(token_unchanged)
                self.assertNotIn('agent-binary-executed', calls)
                self.assertNotIn('restart komari-agent.service', calls)
                self.assertNotIn('start komari-agent.service', calls)
                self.assertNotIn('enable komari-agent.service', calls)

    def test_agent_checksum_mismatch_rejects_before_replacement(self):
        result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade', bad_checksum=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Komari Monitor 1.4.3', result.binary_contents)
        self.assertNotIn('restart komari-agent.service', calls)
        self.assertNotIn('agent-binary-executed', calls)
        self.assertTrue(token_unchanged)

    def test_agent_installed_checksum_mismatch_rejects_before_restart(self):
        result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade', corrupt_install=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('restart komari-agent.service', calls)
        self.assertTrue(token_unchanged)

    def test_agent_running_process_must_use_replaced_binary(self):
        result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade', stale_pid=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('restart komari-agent.service', calls)
        self.assertEqual(calls.count('sleep 1'), 20)
        self.assertNotIn('VPSDEPLOY_KOMARI_LIFECYCLE_OK', result.stdout)
        self.assertTrue(token_unchanged)

    def test_agent_restart_failure_is_not_reported_as_success(self):
        result, calls, _, _, token_unchanged = self.run_case('AgentUpgrade', service_start_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('restart komari-agent.service', calls)
        self.assertNotIn('VPSDEPLOY_KOMARI_LIFECYCLE_OK', result.stdout)
        self.assertFalse(result.service_active)
        self.assertTrue(token_unchanged)

    def test_external_database_is_rejected_before_any_service_change(self):
        result, calls, database, _, _ = self.run_case('ControllerUpgrade', extra_db_arguments='--database /external/komari.db')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')
        self.assertNotIn('stop ', calls)
        self.assertNotIn('start ', calls)

    def test_non_sqlite_database_is_rejected(self):
        result, calls, _, _, _ = self.run_case('ControllerPreflight', extra_db_arguments='--db-type mysql')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('stop ', calls)

    def test_compact_short_database_flags_are_checked(self):
        for arguments in ('-d/external/komari.db', '-tmysql', '--database=file:/external/komari.db'):
            with self.subTest(arguments=arguments):
                result, calls, _, _, _ = self.run_case('ControllerPreflight', extra_db_arguments=arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('stop ', calls)

    def test_backup_stops_and_restores_controller_without_changing_data(self):
        result, calls, database, _, _ = self.run_case('ControllerBackup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(calls.index('stop komari.service'), calls.index('start komari.service'))
        self.assertEqual(database, 'old-db')

    def test_backup_refuses_to_copy_database_if_service_did_not_stop(self):
        result, _, database, _, _ = self.run_case('ControllerBackup', service_stop_still_active=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'old-db')
        self.assertNotIn('VPSDEPLOY_KOMARI_BACKUP_B64=', result.stdout)

    def test_restore_refuses_to_replace_database_if_service_did_not_stop(self):
        result, _, database, metrics, _ = self.run_case('ControllerRestore', service_stop_still_active=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database, 'new-db')
        self.assertTrue(metrics)
        self.assertEqual(result.restore_quarantine_metrics, 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bash', required=True)
    arguments = parser.parse_args()
    BASH = arguments.bash
    (ROOT / '.tmp').mkdir(exist_ok=True)
    unittest.main(argv=[__file__], verbosity=2)
