"""Maintainer-only Google source build on an isolated Linux builder.

Run as root on the builder, never on the VPS being tuned:
  python3 scripts/build-kernel-prebuilt.py start --config /boot/config-$(uname -r)
  python3 scripts/build-kernel-prebuilt.py export --id <id> --output <empty-directory>
The build never installs a kernel or changes the builder's boot configuration.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

PROJECT = Path(__file__).resolve().parent.parent
BASE = Path('/var/lib/mxh-vps-deploy/kernel-prebuild')


def sha(path):
    with path.open('rb') as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''): result.update(block)
    return result.hexdigest()


def run(args):
    return subprocess.check_output(args, text=True, env=dict(os.environ, LC_ALL='C')).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'status', 'export'))
    parser.add_argument('--config')
    parser.add_argument('--id')
    parser.add_argument('--output')
    args = parser.parse_args()
    if os.geteuid() != 0: raise RuntimeError('Root is required only to create the unprivileged build sandbox')
    if args.action == 'start':
        for tool in ('git', 'make', 'gcc', 'bc', 'bison', 'flex', 'dpkg-deb', 'fakeroot', 'rsync', 'xz', 'systemd-run'):
            if not shutil.which(tool): raise RuntimeError('Install Debian build dependencies first: '+tool)
        config = Path(args.config)
        if config.is_symlink() or not config.is_file() or config.stat().st_size > 1048576: raise RuntimeError('Invalid generic input config')
        if shutil.disk_usage('/var/lib').free < 20*1024**3: raise RuntimeError('20 GiB free build space required')
        identity = uuid.uuid4().hex; name = 'mxh-google-bbr-build-'+identity
        target = BASE/identity; target.mkdir(parents=True, mode=0o700)
        shutil.copyfile(config, target/'input.config'); (target/'input.config').chmod(0o600)
        cat = json.loads((PROJECT/'config/kernel-catalog.json').read_text())
        cat.pop('Prebuilt', None)
        sources = ['scripts/kernel-source.py', 'scripts/kernel-build.py', 'scripts/build-kernel-prebuilt.py']
        receipt = {'Id': identity, 'Catalog': cat, 'BuildFiles': {p: sha(PROJECT/p) for p in sources},
                   'InputConfigSha256': sha(target/'input.config'), 'HostKernel': os.uname().release,
                   'HostBootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
        (target/'receipt.json').write_text(json.dumps(receipt, sort_keys=True))
        program = '\n'.join((PROJECT/p).read_text() for p in sources[:2])
        run(['systemd-run', '--unit='+name, '--description=MXH maintainer Google BBR prebuild',
             '--property=Type=exec', '--property=DynamicUser=yes', '--property=StateDirectory='+name,
             '--property=StateDirectoryMode=0700', '--property=ExecPaths=/var/lib/'+name,
             '--property=ProtectSystem=strict', '--property=ProtectHome=yes', '--property=PrivateTmp=yes',
             '--property=NoNewPrivileges=yes', '--property=KillMode=control-group', '--property=TasksMax=512',
             '--property=RuntimeMaxSec=21600', '--property=MemoryMax=6442450944', '--property=CPUQuota=300%',
             '--property=LoadCredential=kernel.config:'+str(target/'input.config'),
             '--setenv=VPS_BUILD_ID='+identity, '--setenv=VPS_BUILD_GENERIC=1', '--setenv=VPS_BUILD_JOBS=4',
             '--setenv=VPS_BUILD_CONFIG_SHA256='+receipt['InputConfigSha256'],
             '--setenv=VPS_BUILD_CATALOG='+base64.b64encode(json.dumps(cat).encode()).decode(),
             '--', '/usr/bin/python3', '-c', program])
        print(json.dumps({'Id': identity, 'Unit': name, 'Kernel': cat['Kernel']})); return
    if not re.fullmatch('[a-f0-9]{32}', args.id or ''): raise RuntimeError('Invalid build identity')
    receipt = json.loads((BASE/args.id/'receipt.json').read_text())
    root = Path('/var/lib/private')/('mxh-google-bbr-build-'+args.id)
    if root.is_symlink(): raise RuntimeError('Linked build directory')
    unit = 'mxh-google-bbr-build-'+args.id
    active = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True).stdout.strip()
    if active in ('active', 'activating', 'deactivating'):
        print(json.dumps({'Id': args.id, 'State': active})); return
    result_path = root/'build-result.json'
    if not result_path.is_file():
        print(json.dumps({'Id': args.id, 'State': 'Failed', 'Log': str(root/'build.log')})); return
    result = json.loads(result_path.read_text())
    cat = receipt['Catalog']; package = root/result['Package']
    if (result['SourceCommit'] != cat['Commit'] or result['SourceTree'] != cat['Tree']
        or result['InputConfigSha256'] != receipt['InputConfigSha256'] or not result['GitFsckPassed']
        or result['PackageSha256'] != sha(package) or result['BuiltConfigSha256'] != sha(root/'kernel.config')):
        raise RuntimeError('Build receipt or package drift')
    if run(['dpkg-deb', '-f', str(package), 'Package']) != cat['Package']: raise RuntimeError('Package identity drift')
    if os.uname().release != receipt['HostKernel'] or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != receipt['HostBootId']:
        raise RuntimeError('Builder unexpectedly rebooted or changed its running kernel')
    if args.action == 'status':
        print(json.dumps({'Id': args.id, 'State': 'Completed', 'Result': result})); return
    output = Path(args.output).resolve()
    if output.exists(): raise RuntimeError('Export directory must not exist')
    output.mkdir(mode=0o755)
    for src, name in ((package, 'kernel.deb'), (root/'kernel.config', 'kernel.config'),
                      (root/'source.tar.xz', 'source.tar.xz'), (BASE/args.id/'input.config', 'input.config')):
        shutil.copyfile(src, output/name); (output/name).chmod(0o644)
    manifest = {'SchemaVersion': 1, 'SourceCommit': cat['Commit'], 'SourceTree': cat['Tree'],
                'SourceMaterialsSha256': cat['Sha256'], 'Kernel': cat['Kernel'], 'Package': cat['Package'],
                'PackageVersion': cat['PackageVersion'], 'Architecture': 'amd64', 'BuildProfile': 'debian-generic-amd64-v1',
                'BuildFiles': receipt['BuildFiles'], 'InputConfigSha256': receipt['InputConfigSha256'],
                'ConfigSha256': result['BuiltConfigSha256'], 'PackageSha256': result['PackageSha256'],
                'PackageBytes': package.stat().st_size, 'SourceArchiveSha256': sha(output/'source.tar.xz'),
                'SourceArchiveBytes': (output/'source.tar.xz').stat().st_size, 'GitFsckPassed': True}
    (output/'build-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    (output/'build-manifest.json').chmod(0o644)
    print(json.dumps({'Id': args.id, 'State': 'Exported', 'Manifest': manifest}))


if __name__ == '__main__': main()
