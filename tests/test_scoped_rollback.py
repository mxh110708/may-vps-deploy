"""Real snapshot/archive restore in a disposable filesystem; services are fake."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASH=None


def shell_path(path):
    value=Path(path).as_posix()
    return '/'+value[0].lower()+value[2:] if os.name=='nt' and value[1:2]==':' else value


PREAMBLE=r'''
set -E
trap 'printf "Fixture command failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
flock(){ return 0; }
systemctl(){
  echo "$*" >> "$TEST_ROOT/calls"
  local service="${@: -1}" key
  key="${service//[^a-zA-Z0-9]/_}"
  case "$1" in
    cat) [[ "$service" == sing-box.service || "$service" == komari.service ]];;
    is-active) [[ -f "$TEST_ROOT/active-$key" ]];;
    is-enabled) [[ "$service" == sing-box.service || "$service" == komari.service ]];;
    stop|disable) [[ "$service" == "${MOCK_STOP_STILL_ACTIVE:-}" ]] || rm -f "$TEST_ROOT/active-$key"; return 0;;
    start|restart) touch "$TEST_ROOT/active-$key";;
    enable) [[ "$*" != *--now* ]] || touch "$TEST_ROOT/active-$key";;
    *) return 0;;
  esac
}
sysctl(){ echo "sysctl $*" >> "$TEST_ROOT/calls"; }
nft(){ echo "nft $*" >> "$TEST_ROOT/calls"; }
mxh_firewall(){
  # This suite isolates archive component selection. Firewall ownership and
  # scoped batches are exercised by test_review_repairs.py with the real helper.
  [[ "$1" == snapshot ]] || return 1
  printf '{"Version":1}\n' > "$2"
}
nginx(){ return 0; }
tar(){
  local args=()
  while (($#)); do if [[ "$1" == -C && "$2" == / ]]; then args+=(-C "$TEST_ROOT");shift 2; else args+=("$1");shift;fi;done
  command tar "${args[@]}"
}
'''
if os.name=='nt':
    # Git Bash cannot change NTFS ACLs inside the Windows sandbox; Linux CI keeps real modes.
    PREAMBLE+='\ninstall(){ mkdir -p "${@: -1}"; }\nchmod(){ return 0; }\n'


class ScopedRollbackTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory(prefix='scoped-rollback-',dir=ROOT/'.tmp')
        self.root=Path(self.folder.name)
        for relative,content in {'etc/sing-box/config.json':'old-protocol','usr/local/bin/sing-box':'fixture-binary','etc/systemd/system/sing-box.service':'fixture-unit','opt/komari/data/komari.db':'old-monitor','opt/komari/komari':'fixture-controller','etc/systemd/system/komari.service':'fixture-controller-unit'}.items():
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content);path.chmod(0o755)
        for name in ('sing_box_service','komari_service'):
            (self.root/('active-'+name)).touch()
        self.env=dict(os.environ,TEST_ROOT=shell_path(self.root),VPS_PARAM_SOURCE_ROLE='ShadowsocksLanding',VPS_PARAM_TARGET_ROLE='ShadowsocksLanding',VPS_PARAM_TIMEOUT_MINUTES='20')

    def tearDown(self):
        self.folder.cleanup()

    def run_payload(self,source):
        return subprocess.run([BASH,'--noprofile','--norc','-s'],input=PREAMBLE+source,text=True,encoding='utf-8',errors='replace',capture_output=True,timeout=20,env=self.env)

    def arm(self,components):
        source=(ROOT/'assets/remote/protocol-migration-arm-rollback.sh').read_text()
        for prefix in ('/usr/local','/usr/bin','/etc','/var/lib','/var/www','/opt','/root'):
            source=source.replace(prefix,shell_path(self.root)+prefix)
        source=source.replace('"/$relative"','"$TEST_ROOT/$relative"').replace('"/${relative:?}"','"$TEST_ROOT/${relative:?}"')
        self.env['VPS_PARAM_COMPONENTS']=components
        result=self.run_payload(source)
        self.assertEqual(result.returncode,0,result.stderr)
        self.backup=next((self.root/'root/vps-deploy-backups').glob('*/protocol-lifecycle'))
        return result

    def restore(self,argument='--transaction'):
        helper=self.root/'usr/local/libexec/mxh-protocol-migration-rollback'
        source=f'source "{shell_path(helper)}" "{shell_path(self.backup)}" {argument}\n'
        result=self.run_payload(source)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_protocol_snapshot_excludes_monitor_and_rollback_leaves_live_data(self):
        self.arm('Protocols,Firewall,Network')
        with tarfile.open(self.backup/'protocol-files.tar.gz') as archive:
            self.assertTrue(all('komari' not in item.name for item in archive.getmembers()))
        (self.root/'opt/komari/data/komari.db').write_text('new-monitor')
        (self.root/'opt/komari/data/metrics.db').write_text('new-metrics')
        (self.root/'etc/sing-box/config.json').write_text('new-protocol')
        (self.root/'calls').write_text('')
        self.restore()
        self.assertEqual((self.root/'etc/sing-box/config.json').read_text(),'old-protocol')
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'new-monitor')
        self.assertTrue((self.root/'opt/komari/data/metrics.db').exists())
        self.assertNotIn('komari.service',(self.root/'calls').read_text())

    def test_monitor_only_decommission_produces_downloadable_empty_archive(self):
        for relative in ('etc/sing-box/config.json','usr/local/bin/sing-box','etc/systemd/system/sing-box.service'):
            (self.root/relative).unlink()
        (self.root/'etc/sing-box').rmdir()
        (self.root/'active-sing_box_service').unlink()
        self.arm('Protocols,Network,Firewall,KomariAgent')
        archive_path=self.backup/'protocol-files.tar.gz'
        self.assertTrue(archive_path.is_file())
        with tarfile.open(archive_path) as archive:
            self.assertEqual(archive.getmembers(),[])
        (self.root/'opt/komari/data/komari.db').write_text('live-monitor')
        (self.root/'calls').write_text('')
        self.restore()
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'live-monitor')
        self.assertTrue((self.root/'active-komari_service').exists())
        self.assertNotIn('komari.service',(self.root/'calls').read_text())

    def test_controller_rollback_quarantines_new_metrics_before_restore(self):
        self.arm('KomariController')
        (self.root/'opt/komari/data/komari.db').write_text('migrated-monitor')
        (self.root/'opt/komari/data/metrics.db').write_text('new-metrics')
        self.restore()
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'old-monitor')
        self.assertFalse((self.root/'opt/komari/data/metrics.db').exists())
        self.assertEqual(len(list(self.backup.glob('failed-komari-data-*/**/metrics.db'))),1)

    def test_protocol_tls_snapshot_and_legacy_restore_preserve_unrelated_lineages(self):
        owned=self.root/'etc/mxh-tls/anytls/fullchain.pem'
        foreign=self.root/'etc/letsencrypt/archive/another-site/fullchain1.pem'
        for file,content in ((owned,'old-owned-cert'),(foreign,'old-foreign-cert')):
            file.parent.mkdir(parents=True,exist_ok=True);file.write_text(content)
        self.arm('Protocols')
        archive_path=self.backup/'protocol-files.tar.gz'
        with tarfile.open(archive_path) as archive:
            members=archive.getnames()
            self.assertIn('etc/mxh-tls/anytls/fullchain.pem',members)
            self.assertTrue(all('another-site' not in name for name in members))
        # Construct the historical broad TLS archive, exercising the installed
        # production rollback helper's member filter rather than a model.
        historical=self.backup/'old.tar.gz'
        with tarfile.open(archive_path) as old, tarfile.open(historical,'w:gz') as new:
            for item in old.getmembers():
                new.addfile(item,old.extractfile(item) if item.isfile() else None)
            new.add(foreign,arcname='etc/letsencrypt/archive/another-site/fullchain1.pem')
        archive_path.write_bytes(historical.read_bytes())
        owned.write_text('new-owned-cert');foreign.write_text('new-foreign-cert')
        self.restore('--protocol-files-only')
        self.assertEqual(owned.read_text(),'old-owned-cert')
        self.assertEqual(foreign.read_text(),'new-foreign-cert')

    def test_initial_baseline_tls_restore_preserves_unrelated_certificate(self):
        owned=self.root/'etc/mxh-tls/anytls/fullchain.pem'
        foreign=self.root/'etc/letsencrypt/archive/another-site/fullchain1.pem'
        for file,content in ((owned,'old-owned-cert'),(foreign,'old-foreign-cert')):
            file.parent.mkdir(parents=True,exist_ok=True);file.write_text(content)
        preamble=PREAMBLE+'''\nid(){ return 1; }\nsysctl(){ echo "sysctl $*" >> "$TEST_ROOT/baseline-sysctl-calls"; }\ndpkg-query(){ echo package; }\nsshd(){ return 0; }\nnft(){ [[ "$*" != 'list table inet filter' ]]; }\n'''
        def source(name):
            text=(ROOT/'assets/remote'/name).read_text()
            for prefix in ('/usr/local','/etc','/var/lib','/var/www','/var/log','/run/systemd','/root'):
                text=text.replace(prefix,shell_path(self.root)+prefix)
            return text.replace('"/$path"','"$TEST_ROOT/$path"').replace('"/${path:?}"','"$TEST_ROOT/${path:?}"')
        self.env.update(VPS_PARAM_TRANSACTION_ID='a'*32,VPS_PARAM_ADMIN_USER='synthetic-admin',VPS_PARAM_NETWORK_MANAGED='false',VPS_PARAM_RESTORE_NETWORK='false')
        result=subprocess.run([BASH,'--noprofile','--norc','-s'],input=preamble+source('deployment-baseline-arm.sh'),text=True,capture_output=True,timeout=20,env=self.env)
        self.assertEqual(result.returncode,0,result.stderr)
        baseline=self.root/'root/vps-deploy-transaction-baselines'/('a'*32)
        with tarfile.open(baseline/'files.tar.gz') as archive:
            self.assertTrue(all('another-site' not in name for name in archive.getnames()))
        owned.write_text('new-owned-cert');foreign.write_text('new-foreign-cert')
        network=self.root/'etc/sysctl.d/99-mxh-vps-deploy.conf';network.parent.mkdir(parents=True,exist_ok=True);network.write_text('external current network settings')
        # The controller also excludes network data in older native baselines.
        (baseline/'network.managed').unlink();(baseline/'sysctl.tsv').write_text('net.core.rmem_max\t1234\n')
        with (baseline/'absent.list').open('a') as absent: absent.write('etc/sysctl.d/99-mxh-vps-deploy.conf\n')
        self.env['VPS_PARAM_BASELINE_DIR']=shell_path(baseline)
        result=subprocess.run([BASH,'--noprofile','--norc','-s'],input=preamble+source('deployment-baseline-rollback.sh'),text=True,capture_output=True,timeout=20,env=self.env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(owned.read_text(),'old-owned-cert');self.assertEqual(foreign.read_text(),'new-foreign-cert')
        self.assertEqual(network.read_text(),'external current network settings');self.assertFalse((self.root/'baseline-sysctl-calls').exists())

    def test_historical_full_protocol_restore_filters_monitor_files(self):
        runner=self.root/'usr/local/libexec/mxh-certbot-dns'
        runner.parent.mkdir(parents=True,exist_ok=True)
        runner.write_text('old-api-transport')
        self.arm('Protocols,KomariController')
        runner.write_text('changed-api-transport')
        (self.root/'opt/komari/data/komari.db').write_text('new-monitor')
        (self.root/'etc/sing-box/config.json').write_text('new-protocol')
        (self.root/'calls').write_text('')
        self.restore('--protocol-only')
        self.assertEqual((self.root/'etc/sing-box/config.json').read_text(),'old-protocol')
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'new-monitor')
        self.assertNotIn('komari.service',(self.root/'calls').read_text())
        self.assertEqual(runner.read_text(),'old-api-transport')

    def test_controller_rollback_refuses_to_replace_live_database(self):
        self.arm('KomariController')
        (self.root/'opt/komari/data/komari.db').write_text('new-monitor')
        self.env['MOCK_STOP_STILL_ACTIVE']='komari.service'
        helper=self.root/'usr/local/libexec/mxh-protocol-migration-rollback'
        result=self.run_payload(f'source "{shell_path(helper)}" "{shell_path(self.backup)}" --transaction\n')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'new-monitor')
        self.assertFalse((self.backup/'rollback-executed').exists())
        self.assertFalse(list(self.backup.glob('failed-komari-data-*')))

    def test_desktop_protocol_restore_preserves_network_firewall_and_monitor(self):
        network=self.root/'etc/sysctl.d/99-mxh-vps-deploy.conf'
        firewall=self.root/'etc/nftables.conf'
        network.parent.mkdir(parents=True,exist_ok=True)
        network.write_text('old-network')
        firewall.write_text('old-firewall')
        self.arm('Protocols,Network,Firewall,KomariController')
        network.write_text('current-network')
        firewall.write_text('current-firewall')
        (self.root/'opt/komari/data/komari.db').write_text('current-monitor')
        (self.root/'etc/sing-box/config.json').write_text('current-protocol')
        (self.root/'calls').write_text('')
        self.restore('--protocol-files-only')
        self.assertEqual((self.root/'etc/sing-box/config.json').read_text(),'old-protocol')
        self.assertEqual(network.read_text(),'current-network')
        self.assertEqual(firewall.read_text(),'current-firewall')
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'current-monitor')
        calls=(self.root/'calls').read_text()
        self.assertNotIn('sysctl ',calls)
        self.assertNotIn('nft ',calls)
        self.assertNotIn('komari.service',calls)

    def test_protocol_rollback_refuses_to_replace_config_of_unstopped_service(self):
        self.arm('Protocols')
        (self.root/'etc/sing-box/config.json').write_text('new-protocol')
        self.env['MOCK_STOP_STILL_ACTIVE']='sing-box.service'
        helper=self.root/'usr/local/libexec/mxh-protocol-migration-rollback'
        result=self.run_payload(f'source "{shell_path(helper)}" "{shell_path(self.backup)}" --transaction\n')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.root/'etc/sing-box/config.json').read_text(),'new-protocol')
        self.assertFalse((self.backup/'rollback-executed').exists())

    def test_new_anytls_rollback_does_not_touch_existing_protocol_or_monitor(self):
        self.arm('AnyTlsEntry')
        for relative in ('usr/local/bin/sing-box-anytls', 'etc/sing-box-anytls/config.json', 'etc/systemd/system/sing-box-anytls.service'):
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('new-anytls')
        (self.root/'calls').write_text('')
        self.restore()
        self.assertFalse((self.root/'etc/sing-box-anytls').exists())
        self.assertEqual((self.root/'etc/sing-box/config.json').read_text(),'old-protocol')
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'old-monitor')
        calls=(self.root/'calls').read_text()
        self.assertNotIn('sing-box.service',calls)
        self.assertNotIn('komari.service',calls)

    def test_new_certbot_runner_is_removed_only_with_trusted_tls_scope(self):
        self.arm('AnyTlsEntry,TrustedTls')
        runner=self.root/'usr/local/libexec/mxh-certbot-dns'
        runner.write_text('new-private-dns-transport')
        self.restore()
        self.assertFalse(runner.exists())
        self.assertEqual((self.root/'etc/sing-box/config.json').read_text(),'old-protocol')
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'old-monitor')

    def test_new_tunnel_rollback_removes_private_token_only_in_tunnel_scope(self):
        self.arm('Cloudflared')
        for relative in ('usr/local/bin/cloudflared', 'etc/systemd/system/cloudflared.service', 'etc/cloudflared/mxh-token'):
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic-tunnel')
        (self.root/'calls').write_text('')
        self.restore()
        self.assertFalse((self.root/'etc/cloudflared').exists())
        self.assertEqual((self.root/'opt/komari/data/komari.db').read_text(),'old-monitor')
        self.assertNotIn('komari.service',(self.root/'calls').read_text())


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--bash',required=True)
    args,remaining=parser.parse_known_args();BASH=args.bash
    (ROOT/'.tmp').mkdir(exist_ok=True)
    unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
