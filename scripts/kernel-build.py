"""Runs only inside a bounded, unprivileged systemd DynamicUser build unit."""
import os
import pathlib
import shutil
import signal
import subprocess
import time


def build_execute(args, root, env, log, cwd=None, capture=False, timeout=1800):
    def space_check():
        if shutil.disk_usage(root).free < 2*1024**3: raise KernelFailure('KernelBuildDiskLow')
    space_check()
    process = subprocess.Popen(args, cwd=cwd or root, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE if capture else log, stderr=log, start_new_session=True)
    deadline = time.monotonic()+timeout
    try:
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise KernelFailure('KernelBuildTimeout')
            try:
                output, _ = process.communicate(timeout=min(5, remaining))
                break
            except subprocess.TimeoutExpired:
                space_check()
        if process.returncode:
            log.write(('\nBuild command exited '+str(process.returncode)+': '+pathlib.Path(args[0]).name+'\n').encode()); log.flush()
            raise KernelFailure('KernelSourceBuildFailed')
        return output.decode().strip() if capture else ''
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
        raise


def build_google_kernel():
    if os.geteuid() == 0: raise RuntimeError('Kernel compilation as root refused')
    cat = json.loads(base64.b64decode(os.environ['VPS_BUILD_CATALOG'], validate=True)); catalog_validate(cat)
    identity = os.environ['VPS_BUILD_ID']
    if not re.fullmatch('[a-f0-9]{32}', identity): raise RuntimeError('Invalid build identity')
    root = pathlib.Path(os.environ['STATE_DIRECTORY'])
    if root.name != 'mxh-google-bbr-build-'+identity or list(root.iterdir()): raise RuntimeError('Build replay refused')
    credential = pathlib.Path(os.environ['CREDENTIALS_DIRECTORY'])/'kernel.config'
    config = credential.read_bytes()
    if len(config) > 1048576 or hashlib.sha256(config).hexdigest() != os.environ['VPS_BUILD_CONFIG_SHA256']: raise RuntimeError('Build configuration drift')
    env = dict(os.environ, LC_ALL='C', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    log = (root/'build.log').open('wb')
    def execute(args, cwd=root, capture=False, timeout=1800):
        return build_execute(args, root, env, log, cwd, capture, timeout)
    try:
        source = root/'source'; source.mkdir()
        git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'http.lowSpeedLimit=1024', '-c', 'http.lowSpeedTime=90']
        execute(git+['init', '--quiet', str(source)])
        execute(git+['-C', str(source), 'fetch', '--depth=1', '--no-tags', GOOGLE_REPOSITORY+'.git', cat['Commit']])
        if execute(git+['-C', str(source), 'rev-parse', 'FETCH_HEAD'], capture=True) != cat['Commit']: raise RuntimeError('Fetched commit mismatch')
        if execute(git+['-C', str(source), 'rev-parse', 'FETCH_HEAD^{tree}'], capture=True) != cat['Tree']: raise RuntimeError('Fetched source tree mismatch')
        execute(git+['-C', str(source), 'fsck', '--full', '--strict'])
        execute(git+['-C', str(source), 'checkout', '--detach', cat['Commit']])
        for name, path in [('Makefile', source/'Makefile'), ('tcp_bbr.c', source/'net/ipv4/tcp_bbr.c')]:
            if hashlib.sha256(path.read_bytes()).hexdigest() != cat['SourceFiles'][name]: raise RuntimeError('Fetched official source mismatch')
        (source/'.config').write_bytes(config)
        configure = [str(source/'scripts/config'), '--file', str(source/'.config')]
        for key in ('LOCALVERSION_AUTO', 'DEBUG_INFO', 'DEBUG_INFO_BTF', 'DEBUG_INFO_BTF_MODULES', 'DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT', 'DEBUG_INFO_DWARF4', 'DEBUG_INFO_DWARF5', 'MODULE_SIG_ALL'):
            execute(configure+['--disable', key])
        for key in ('DEBUG_INFO_NONE', 'TCP_CONG_BBR', 'NET_SCH_FQ', 'BLK_DEV_INITRD'):
            execute(configure+['--enable', key])
        for key in ('LOCALVERSION', 'SYSTEM_TRUSTED_KEYS', 'SYSTEM_REVOCATION_KEYS'):
            execute(configure+['--set-str', key, ''])
        if os.environ.get('VPS_BUILD_GENERIC') == '1':
            for key in ('GENERIC_CPU', 'SMP', 'MODULES', 'DEVTMPFS', 'DEVTMPFS_MOUNT', 'PCI', 'INET', 'IPV6'):
                execute(configure+['--enable', key])
        local = 'LOCALVERSION=-mxh-bbr3-'+cat['Commit'][:12]
        # Stable build identity; no workstation hostname, clock or CPU-specific flags.
        env['SOURCE_DATE_EPOCH'] = str(int(datetime.datetime.fromisoformat(cat['SourceDate'].replace('Z', '+00:00')).timestamp()))
        make = ['make', local, 'KDEB_PKGVERSION='+cat['PackageVersion'], 'KDEB_SOURCENAME=linux-google-bbr', 'KBUILD_BUILD_USER=mxh', 'KBUILD_BUILD_HOST=google-bbr-source', 'KBUILD_BUILD_VERSION=1', 'KBUILD_BUILD_TIMESTAMP='+cat['SourceDate']]
        execute(make+['olddefconfig'], cwd=source)
        built_config = (source/'.config').read_bytes()
        for required in (b'CONFIG_TCP_CONG_BBR=y', b'CONFIG_NET_SCH_FQ=y', b'CONFIG_BLK_DEV_INITRD=y'):
            if required not in built_config.splitlines(): raise RuntimeError('Required kernel configuration absent')
        if os.environ.get('VPS_BUILD_GENERIC') == '1':
            settings = dict(line.split(b'=', 1) for line in built_config.splitlines() if line.startswith(b'CONFIG_') and b'=' in line)
            for option in ('X86_64', 'GENERIC_CPU', 'SMP', 'MODULES', 'DEVTMPFS', 'DEVTMPFS_MOUNT', 'PCI', 'INET', 'IPV6', 'VIRTIO_PCI', 'VIRTIO_BLK', 'VIRTIO_NET', 'SCSI_VIRTIO', 'BLK_DEV_SD', 'ATA', 'SATA_AHCI', 'BLK_DEV_NVME', 'EXT4_FS', 'HYPERV', 'HYPERV_STORAGE', 'HYPERV_NET', 'VMWARE_PVSCSI', 'VMXNET3'):
                if settings.get(('CONFIG_'+option).encode()) not in (b'y', b'm'): raise RuntimeError('Generic VPS driver absent: '+option)
            if settings.get(b'CONFIG_GENERIC_CPU') != b'y': raise RuntimeError('Generic x86-64 CPU required')
        (root/'kernel.config').write_bytes(built_config)
        if os.environ.get('VPS_BUILD_GENERIC') == '1':
            # Corresponding pristine source is exported alongside the binary, never
            # copied from a compiler tree containing generated/private files.
            execute(git+['-C', str(source), 'archive', '--format=tar', '--prefix=linux-google-bbr/', '--output='+str(root/'source.tar'), cat['Commit']])
            execute(['xz', '-T2', '-3', str(root/'source.tar')], timeout=1800)
        if execute(make+['-s', 'kernelrelease'], cwd=source, capture=True) != cat['Kernel']: raise RuntimeError('Built kernel release mismatch')
        jobs = int(os.environ['VPS_BUILD_JOBS'])
        if not 1 <= jobs <= 4: raise RuntimeError('Unbounded compilation refused')
        execute(make+['-j'+str(jobs), 'bindeb-pkg'], cwd=source, timeout=21600)
        images = []
        for package in root.glob('*.deb'):
            fields = execute(['dpkg-deb', '-f', str(package), 'Package', 'Version', 'Architecture'], capture=True)
            parsed = dict(line.split(': ', 1) for line in fields.splitlines())
            if parsed == {'Package': cat['Package'], 'Version': cat['PackageVersion'], 'Architecture': 'amd64'}: images.append(package)
        if len(images) != 1: raise RuntimeError('Unique built image package absent')
        package = images[0]; checksum = hashlib.sha256()
        with package.open('rb') as stream:
            for part in iter(lambda: stream.read(1048576), b''): checksum.update(part)
        result = {'SchemaVersion': 1, 'BuildRecipe': 1, 'SourceCommit': cat['Commit'], 'SourceTree': cat['Tree'], 'SourceMaterialsSha256': cat['Sha256'],
                  'InputConfigSha256': hashlib.sha256(config).hexdigest(), 'BuiltConfigSha256': hashlib.sha256(built_config).hexdigest(),
                  'Kernel': cat['Kernel'], 'Package': package.name, 'PackageBytes': package.stat().st_size, 'PackageSha256': checksum.hexdigest(), 'GitFsckPassed': True}
        (root/'build-result.json').write_text(json.dumps(result, sort_keys=True))
        print('Google official source compiled into a local image package; no kernel was installed by the build unit.')
    except Exception as error:
        code = error.code if isinstance(error, KernelFailure) else 'KernelSourceBuildFailed'
        log.write(('\n'+type(error).__name__+': '+str(error)+'\n').encode()); log.flush()
        (root/'build-failure.json').write_text(json.dumps({'Code': code}))
        raise
    finally: log.close()


if __name__ == '__main__': build_google_kernel()
