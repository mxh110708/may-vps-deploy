"""Root-owned fixed kernel lifecycle. Mutation acknowledgements are never replayed."""
import base64
import datetime
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

BASE = Path('/var/lib/may-vps-deploy/kernel-google-v3')
DEFAULT = Path('/etc/default/grub.d/99-mxh-bbr-kernel.cfg')
UNIT = Path('/etc/systemd/system/mxh-kernel-boot-guard.service')
TERMINAL = ('Committed', 'RolledBack', 'Aborted')




def run(args, timeout=30, allow=False):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False, env=dict(os.environ, LC_ALL='C', DEBIAN_FRONTEND='noninteractive'))
    if p.returncode and not allow:
        raise RuntimeError('Command failed: '+args[0])
    return p.stdout.strip()


def regular(p, missing=False):
    for ancestor in [p, *p.parents]:
        try:
            st = ancestor.lstat()
        except FileNotFoundError:
            if ancestor == p and not missing:
                raise
            continue
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError('Linked kernel path refused')
        if ancestor == p and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
            raise RuntimeError('Non-regular kernel file refused')


def digest(p):
    regular(p); h = hashlib.sha256()
    with p.open('rb') as f:
        for part in iter(lambda: f.read(1048576), b''):
            h.update(part)
    return h.hexdigest()


def put(p, data, mode=0o600):
    regular(p, True); p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_name(p.name+'.new'); regular(tmp, True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, p)
    fd = os.open(p.parent, os.O_RDONLY); os.fsync(fd); os.close(fd)


def save(s):
    put(BASE / s['Id'] / 'state.json', json.dumps(s, sort_keys=True).encode())


def load(identity):
    if not re.fullmatch('[a-f0-9]{32}', identity):
        raise RuntimeError('Invalid kernel transaction identity')
    p = BASE / identity / 'state.json'; regular(p)
    st = p.stat()
    if st.st_uid != 0 or st.st_mode & 0o077:
        raise RuntimeError('Kernel state ownership refused')
    s = json.loads(p.read_text())
    if s.get('SchemaVersion') != 2 or s.get('Id') != identity or s.get('Owner') != 'mxh-google-bbr-v3':
        raise RuntimeError('Unknown kernel transaction refused')
    if s.get('Phase') not in ('Preparing', 'Installing', 'InstallFailed', 'Prepared', 'BootRequested', 'Booted', 'Committed', 'RollbackRequested', 'RolledBack', 'AutoRolledBack', 'Aborted'):
        raise RuntimeError('Unknown kernel phase refused')
    catalog_validate(s['Catalog'], fresh=False)
    return s


def entry(kernel):
    text = Path('/boot/grub/grub.cfg').read_text()
    sub = re.findall(r"^submenu .*?\$menuentry_id_option '([^']+)' \{", text, re.M)
    ids = re.findall(r"^\s+menuentry .*?\$menuentry_id_option '(gnulinux-"+re.escape(kernel)+r"-advanced-[^']+)' \{", text, re.M)
    if len(sub) != 1 or len(ids) != 1 or not re.fullmatch('[a-zA-Z0-9_.+>:-]+', sub[0]+'>'+ids[0]):
        raise RuntimeError('Ambiguous GRUB entry refused')
    return sub[0]+'>'+ids[0]


def boot_environment():
    return dict(l.split('=', 1) for l in run(['grub-editenv', '/boot/grub/grubenv', 'list']).splitlines() if '=' in l)


def config_fingerprint():
    files = [Path('/etc/default/grub'), *sorted(Path('/etc/default/grub.d').glob('*.cfg')),
             *[p for p in sorted(Path('/etc/grub.d').iterdir()) if p.is_file()]]
    items = {str(p): digest(p) for p in files if p != DEFAULT}
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()


def runtime():
    result = {'Kernel': platform.release(), 'BootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    result.update(bbr_runtime())
    return result


def audit():
    result = runtime(); reasons = []
    info = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distro = info.get('VERSION_ID', '').strip('"')
    if info.get('ID', '').strip('"') != 'debian' or distro not in ('12', '13'):
        reasons.append('仅支持 Debian 12 / 13')
    if platform.machine() != 'x86_64': reasons.append('仅支持 amd64')
    virt = run(['systemd-detect-virt'], allow=True)
    if virt not in ('kvm', 'qemu', 'vmware', 'microsoft', 'none', ''):
        reasons.append('不支持此虚拟化或容器启动环境')
    if Path('/sys/firmware/efi').exists(): reasons.append('EFI / Secure Boot 启动布局尚未适配')
    for tool in ('grub-reboot', 'grub-set-default', 'grub-editenv', 'update-grub', 'dpkg-deb', 'apt-get', 'systemd-run', 'systemctl'):
        if not shutil.which(tool): reasons.append('缺少 '+tool)
    try:
        old = platform.release(); regular(Path('/boot/vmlinuz-'+old)); regular(Path('/boot/initrd.img-'+old))
        result['CurrentEntry'] = entry(old)
        env = boot_environment()
        if any(env.get(k) for k in ('next_entry', 'prev_saved_entry')): reasons.append('已有 GRUB 单次启动计划')
        if run(['findmnt', '-n', '-o', 'FSTYPE', '--target', '/boot/grub/grubenv']) not in ('ext2', 'ext3', 'ext4'):
            reasons.append('GRUB 环境块的文件系统未适配')
        if run(['findmnt', '-n', '-o', 'SOURCE', '--target', '/boot/grub/grubenv']).startswith('/dev/mapper/'):
            reasons.append('LVM / 加密启动布局未适配')
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        reasons.append('当前内核或 GRUB 布局无法明确识别')
    if Path('/var/lib/dkms').exists() and any(Path('/var/lib/dkms').iterdir()): reasons.append('存在 DKMS 驱动')
    result['FreeRootBytes'] = shutil.disk_usage('/').free; result['FreeBootBytes'] = shutil.disk_usage('/boot').free
    root_required = 2*1024**3
    if result['FreeRootBytes'] < root_required or result['FreeBootBytes'] < 512*1024**2:
        reasons.append('根目录至少 2 GiB、启动目录至少 512 MiB 可用空间')
    memory = dict((k, int(v.split()[0])) for k, v in (line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines()))
    result['MemoryAvailableKiB'] = memory.get('MemAvailable', 0)
    result['MemoryTotalKiB'] = memory.get('MemTotal', 0)
    # A nominal 512 MiB guest reports less MemTotal after kernel reservations.
    if result['MemoryTotalKiB'] < 384*1024 or result['MemoryAvailableKiB'] < 256*1024:
        reasons.append('预编译包安装建议至少 512 MiB 内存；系统识别总量需 384 MiB、当前可用需 256 MiB')
    try:
        config = Path('/boot/config-'+platform.release()); regular(config)
        result['BuildConfigSha256'] = digest(config)
        if config.stat().st_size > 1048576: reasons.append('当前内核配置过大')
    except (OSError, RuntimeError): reasons.append('缺少可读取的当前内核配置，拒绝猜测启动驱动')
    result.update({'Compatible': not reasons, 'Reasons': reasons, 'Distribution': distro, 'Virtualization': virt,
                   'Delivery': 'Prebuilt'})
    return result




def owned_boot(s):
    if config_fingerprint() != s['BootConfigFingerprint'] or digest(DEFAULT) != s['OwnedDefaultSha256']:
        raise RuntimeError('Boot configuration drift; refuse write')
    env = boot_environment()
    if env.get('saved_entry', '') != s['SavedEntry'] or env.get('next_entry', '') not in ('', s.get('NextEntry', '')):
        raise RuntimeError('Unrelated boot request refused')


def set_default(s, value):
    text = '# Managed by MXH kernel transaction '+s['Id']+'\nGRUB_DEFAULT=saved\nGRUB_SAVEDEFAULT=false\n'
    put(DEFAULT, text.encode(), 0o644); s['OwnedDefaultSha256'] = digest(DEFAULT); save(s)
    run(['update-grub'], 120); run(['grub-set-default', value]); s['SavedEntry'] = value; save(s)
    cfg = Path('/boot/grub/grub.cfg').read_text()
    if boot_environment().get('saved_entry') != value or 'set default="${saved_entry}"' not in cfg or 'save_env next_entry' not in cfg:
        raise RuntimeError('One-shot GRUB configuration verification failed')


def sources_verify(s):
    root = BASE/s['Id']
    verify_materials(s['Catalog'], {name: (root/name).read_bytes() for name in SOURCE_NAMES})


def retained_package(s):
    cat = s['Catalog']
    installed = run(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', cat['Package']], allow=True)
    if not installed: return None
    if installed != 'installed '+cat['PackageVersion']: raise RuntimeError('Unmanaged installed package collision')
    identity = s.get('PreviousTransaction', ''); visited = set()
    while identity and identity not in visited and len(visited) < 16:
        visited.add(identity); previous = load(identity)
        if previous['Phase'] in TERMINAL and previous['Catalog'].get('Sha256') == cat['Sha256'] and previous['Catalog'].get('Kernel') == cat['Kernel'] and previous['Catalog'].get('Prebuilt') == cat.get('Prebuilt') and previous.get('NewImageSha256') and previous.get('NewInitrdSha256'):
            if digest(Path('/boot/vmlinuz-'+cat['Kernel'])) != previous['NewImageSha256'] or digest(Path('/boot/initrd.img-'+cat['Kernel'])) != previous['NewInitrdSha256']: raise RuntimeError('Retained image drift')
            return previous
        identity = previous.get('PreviousTransaction', '')
    raise RuntimeError('Installed target has no matching managed artifact history')


def take_prebuilt(cat, target):
    item = prebuilt_validate(cat)
    uploaded = Path(os.environ.get('VPS_PARAM_PACKAGE_PATH', ''))
    if not re.fullmatch(r'/tmp/mxh-vps\.[a-zA-Z0-9]{10}/kernel\.deb', str(uploaded)):
        raise KernelFailure('KernelPrebuiltRejected')
    regular(uploaded)
    parent = uploaded.parent.stat(); st = uploaded.stat()
    if parent.st_uid != 0 or parent.st_mode & 0o077 or st.st_uid != 0 or st.st_mode & 0o077:
        raise KernelFailure('KernelPrebuiltRejected')
    if st.st_size != item['Bytes'] or digest(uploaded) != item['Sha256']:
        raise KernelFailure('KernelPrebuiltRejected')
    destination = target/'kernel.deb'; regular(destination, True)
    # Copy rather than rename: /tmp may be mounted on a different filesystem.
    with uploaded.open('rb') as source, destination.open('xb') as output:
        shutil.copyfileobj(source, output, 1048576); output.flush(); os.fsync(output.fileno())
    destination.chmod(0o600)
    if digest(destination) != item['Sha256']: raise KernelFailure('KernelPrebuiltRejected')
    uploaded.unlink(); uploaded.parent.rmdir()
    return destination

def committed_running_kernel(previous, kernel):
    visited = set()
    while previous and previous['Id'] not in visited and len(visited) < 16:
        visited.add(previous['Id'])
        if previous['Phase'] == 'Committed' and previous['Catalog']['Kernel'] == kernel: return previous
        identity = previous.get('PreviousTransaction', '')
        if not identity: break
        previous = load(identity)
    raise RuntimeError('Running BBR v3 has no committed managed history')


def prepare(identity):
    cat = json.loads(os.environ['VPS_PARAM_CATALOG']); catalog_validate(cat); prebuilt_validate(cat)
    a = audit()
    if not a['Compatible']: raise RuntimeError('Kernel preflight refused')
    if kernel_version(cat['Kernel']) < kernel_version(a['Kernel']): raise RuntimeError('Kernel downgrade refused; use an explicit rollback first')
    current = BASE/'current.json'; previous = None
    if current.exists():
        regular(current); previous = load(json.loads(current.read_text())['Id'])
        if previous['Phase'] not in TERMINAL: raise RuntimeError('Unfinished kernel transaction refused')
        if os.environ.get('VPS_PARAM_PREVIOUS_TRANSACTION', '') != previous['Id']: raise RuntimeError('Previous kernel identity mismatch')
        if 'OwnedDefaultSha256' in previous: owned_boot(previous)
        else:
            if config_fingerprint() != previous['BootConfigFingerprint'] or (DEFAULT.read_bytes() if DEFAULT.exists() else None) != (base64.b64decode(previous['OriginalDefault']) if previous['OriginalDefault'] else None) or boot_environment().get('saved_entry', '') != previous['SavedEntry']:
                raise RuntimeError('Previous preparation boot drift')
    elif os.environ.get('VPS_PARAM_PREVIOUS_TRANSACTION', ''): raise RuntimeError('Previous kernel transaction missing')
    if cat['Kernel'] == a['Kernel']: raise RuntimeError('Target kernel already running')
    if a['BbrVersion'] == 'v3':
        if not previous or previous['Phase'] not in TERMINAL:
            raise RuntimeError('Unmanaged BBR v3 upgrade refused')
        accepted = committed_running_kernel(previous, a['Kernel'])
        if digest(Path('/boot/vmlinuz-'+a['Kernel'])) != accepted.get('NewImageSha256') or digest(Path('/boot/initrd.img-'+a['Kernel'])) != accepted.get('NewInitrdSha256'):
            raise RuntimeError('Previous committed kernel image drift')
        old_catalog = accepted['Catalog']
        if kernel_version(cat['Kernel']) == kernel_version(a['Kernel']):
            if datetime.datetime.fromisoformat(cat['SourceDate'].replace('Z', '+00:00')) <= datetime.datetime.fromisoformat(old_catalog['SourceDate'].replace('Z', '+00:00')):
                raise RuntimeError('Fixed artifact is not newer; use explicit rollback')
    target = BASE/identity
    if target.exists(): raise RuntimeError('Kernel transaction already exists; reconcile only')
    expected_default = previous.get('OwnedDefaultSha256') if previous else None
    if previous and not expected_default and previous.get('OriginalDefault'):
        expected_default = hashlib.sha256(base64.b64decode(previous['OriginalDefault'])).hexdigest()
    if DEFAULT.exists() and digest(DEFAULT) != expected_default:
        raise RuntimeError('Unmanaged boot default collision')
    if UNIT.exists(): raise RuntimeError('Existing kernel boot guard refused')
    target.mkdir(mode=0o700); env = boot_environment()
    s = {'SchemaVersion': 2, 'Owner': 'mxh-google-bbr-v3', 'Id': identity, 'Phase': 'Preparing', 'Catalog': cat,
         'OldKernel': a['Kernel'], 'OldBootId': a['BootId'], 'OldEntry': a['CurrentEntry'], 'OriginalGrubEnvironment': env,
         'OriginalDefault': base64.b64encode(DEFAULT.read_bytes()).decode() if DEFAULT.exists() else None,
         'BootConfigFingerprint': config_fingerprint(), 'SavedEntry': env.get('saved_entry', ''), 'InstallInvocations': 0,
         'Services': [unit for unit in ('ssh.service', 'sshd.service', 'xray.service', 'sing-box.service', 'sing-box-anytls.service', 'sing-box-shadowsocks.service', 'komari-agent.service', 'komari.service', 'cloudflared.service') if run(['systemctl', 'is-active', unit], allow=True) == 'active']}
    s['OldImageSha256'] = digest(Path('/boot/vmlinuz-'+s['OldKernel'])); s['OldInitrdSha256'] = digest(Path('/boot/initrd.img-'+s['OldKernel']))
    s['PreviousTransaction'] = previous['Id'] if previous else ''
    for field in ('Kernel', 'Entry', 'ImageSha256', 'InitrdSha256'):
        s['Original'+field] = previous.get('Original'+field, previous['Old'+field]) if previous else s['Old'+field]
    save(s); put(current, json.dumps({'Id': identity}).encode())
    put(target/'engine.py', (os.environ['VPS_BBR_PROGRAM']+'\n'+os.environ['VPS_KERNEL_PROGRAM']).encode())
    for name in SOURCE_NAMES:
        data = base64.b64decode(os.environ['VPS_PARAM_SOURCE_'+name.replace('.', '_').upper()], validate=True)
        if hashlib.sha256(data).hexdigest() != cat['SourceFiles'][name]: raise RuntimeError('Public source file mismatch')
        put(target/name, data)
    sources_verify(s)
    s['Delivery'] = 'Prebuilt'
    take_prebuilt(cat, target)
    s['BuiltPackageSha256'] = cat['Prebuilt']['Sha256']
    save(s); set_default(s, s['OldEntry']); s['Phase'] = 'Installing'; save(s)
    # Client waiting is bounded separately. Never kill dpkg halfway through a package write.
    run(['systemd-run', '--unit=mxh-kernel-install-'+identity, '--property=Type=exec',
         '--', '/usr/bin/python3', str(target/'engine.py'), 'InstallWorker', identity])
    return s


def install_worker(s):
    if s['Phase'] != 'Installing' or s['InstallInvocations'] != 0: raise RuntimeError('Install replay refused')
    s['InstallInvocations'] = 1; save(s)
    stage = 'SourceVerification'
    try:
        owned_boot(s); sources_verify(s); cat = s['Catalog']
        retained = retained_package(s)
        if retained:
            s['ReusedRetainedPackage'] = True; save(s)
        else:
            if Path('/boot/vmlinuz-'+cat['Kernel']).exists() or Path('/boot/initrd.img-'+cat['Kernel']).exists(): raise RuntimeError('Unmanaged target image collision')
            stage = 'PrebuiltVerification'; s['BuildStage'] = stage; save(s)
            package = BASE/s['Id']/'kernel.deb'; item = prebuilt_validate(cat)
            if s.get('Delivery') != 'Prebuilt' or package.stat().st_size != item['Bytes'] or digest(package) != item['Sha256'] or s.get('BuiltPackageSha256') != item['Sha256']:
                raise KernelFailure('KernelPrebuiltRejected')
            stage = 'PackageIdentity'; s['BuildStage'] = stage; save(s)
            fields = dict(line.split(': ', 1) for line in run(['dpkg-deb', '-f', str(package), 'Package', 'Version', 'Architecture']).splitlines())
            if fields != {'Package': cat['Package'], 'Version': cat['PackageVersion'], 'Architecture': 'amd64'}: raise RuntimeError('Local package identity mismatch')
            preview = run(['apt-get', '-s', '--no-remove', 'install', str(package)], 90)
            changes = [line for line in preview.splitlines() if line.startswith(('Inst ', 'Remv '))]
            if len(changes) != 1 or not changes[0].startswith('Inst '+cat['Package']+' '): raise RuntimeError('Unexpected package dependency mutation refused')
            stage = 'PackageInstall'; s['BuildStage'] = stage; save(s)
            if digest(package) != s['BuiltPackageSha256']: raise RuntimeError('Package changed before installation')
            run(['apt-get', '-y', '--no-remove', '-o', 'DPkg::Lock::Timeout=30', 'install', str(package)], None)
        stage = 'InstalledArtifacts'
        if run(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', cat['Package']]) != 'installed '+cat['PackageVersion']: raise RuntimeError('Kernel installation unconfirmed')
        s['NewEntry'] = entry(cat['Kernel']); s['NewImageSha256'] = digest(Path('/boot/vmlinuz-'+cat['Kernel'])); s['NewInitrdSha256'] = digest(Path('/boot/initrd.img-'+cat['Kernel']))
        if digest(Path('/boot/vmlinuz-'+s['OldKernel'])) != s['OldImageSha256']: raise RuntimeError('Old kernel changed')
        owned_boot(s); s['Phase'] = 'Prepared'; s['BuildStage'] = 'Complete'; save(s)
    except Exception as error:
        s['Phase'] = 'InstallFailed'; s['FailureStage'] = stage
        s['FailureCode'] = error.code if isinstance(error, KernelFailure) else 'KernelOperationRefused'; save(s)
        raise

def status(s):
    s['Runtime'] = runtime()
    if s['Phase'] == 'Installing':
        active = run(['systemctl', 'is-active', 'mxh-kernel-install-'+s['Id']], allow=True)
        if active not in ('active', 'activating'): s['Phase'] = 'InstallFailed'; save(s)
    if s['Phase'] in ('BootRequested', 'RollbackRequested') and s['Runtime']['BootId'] != s['OldBootId']:
        expected = s['Catalog']['Kernel'] if s['Phase'] == 'BootRequested' else s.get('RollbackKernel', s['OldKernel'])
        if s['Runtime']['Kernel'] == expected:
            s['Phase'] = 'Booted' if expected == s['Catalog']['Kernel'] else 'RolledBack'; save(s)
        elif s['Runtime']['Kernel'] == s['OldKernel']:
            s['Phase'] = 'AutoRolledBack'; save(s)
    s['ServicesHealthy'] = all(run(['systemctl', 'is-active', unit], allow=True) == 'active' for unit in s['Services'])
    return s


def boot(s):
    running = platform.release()
    if s['Phase'] not in ('Prepared', 'RolledBack', 'Aborted') or not s.get('NewImageSha256') or running not in (s['OldKernel'], s.get('OriginalKernel', s['OldKernel'])): raise RuntimeError('Kernel boot phase refused')
    owned_boot(s)
    fallback_original = running != s['OldKernel']
    prefix = 'Original' if fallback_original else 'Old'
    if digest(Path('/boot/vmlinuz-'+running)) != s[prefix+'ImageSha256'] or digest(Path('/boot/initrd.img-'+running)) != s[prefix+'InitrdSha256']: raise RuntimeError('Activation fallback image drift')
    if digest(Path('/boot/vmlinuz-'+s['Catalog']['Kernel'])) != s['NewImageSha256'] or digest(Path('/boot/initrd.img-'+s['Catalog']['Kernel'])) != s['NewInitrdSha256']:
        raise RuntimeError('Installed boot image drift')
    guard = '[Unit]\nDescription=MXH bounded kernel boot acceptance\nAfter=network.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 '+str(BASE/s['Id']/'engine.py')+' Watchdog '+s['Id']+'\n[Install]\nWantedBy=multi-user.target\n'
    put(UNIT, guard.encode(), 0o644); s['GuardSha256'] = digest(UNIT)
    run(['systemctl', 'daemon-reload']); run(['systemctl', 'enable', 'mxh-kernel-boot-guard.service'])
    s['ActivationFallbackOriginal'] = fallback_original
    s['OldBootId'] = runtime()['BootId']; s['Phase'] = 'BootRequested'; s['NextEntry'] = s['NewEntry']; save(s)
    run(['grub-reboot', s['NewEntry']])
    if boot_environment().get('next_entry') != s['NewEntry']: raise RuntimeError('One-shot boot verification failed')
    run(['systemd-run', '--unit=mxh-kernel-reboot-'+s['Id'], '--on-active=3s', '--', '/usr/bin/systemctl', 'reboot'])
    return s


def remove_guard(s):
    if UNIT.exists():
        if digest(UNIT) != s.get('GuardSha256'): raise RuntimeError('Boot guard ownership drift')
        run(['systemctl', 'disable', 'mxh-kernel-boot-guard.service']); UNIT.unlink(); run(['systemctl', 'daemon-reload'])


def confirm(s):
    s = status(s)
    if s['Phase'] == 'Committed': return s
    if s['Phase'] != 'Booted' or s['Runtime']['BbrVersion'] != 'v3' or not s['ServicesHealthy']:
        raise RuntimeError('New kernel runtime acceptance refused')
    owned_boot(s)
    if digest(Path('/boot/vmlinuz-'+s['Catalog']['Kernel'])) != s['NewImageSha256']: raise RuntimeError('New image changed')
    set_default(s, s['NewEntry']); s['Phase'] = 'Committed'; save(s); remove_guard(s)
    return s


def rollback(s, original=False):
    s = status(s)
    if s['Phase'] == 'Installing': raise RuntimeError('Package installer still active; reconcile first')
    if s['Phase'] == 'RollbackRequested': return s
    prefix = 'Original' if original else 'Old'
    target = {field: s.get(prefix+field, s['Old'+field]) for field in ('Kernel', 'Entry', 'ImageSha256', 'InitrdSha256')}
    if s['Phase'] in ('RolledBack', 'Aborted') and platform.release() == target['Kernel']: return s
    if digest(Path('/boot/vmlinuz-'+target['Kernel'])) != target['ImageSha256'] or digest(Path('/boot/initrd.img-'+target['Kernel'])) != target['InitrdSha256']:
        raise RuntimeError('Old boot image drift; refuse reboot')
    if 'OwnedDefaultSha256' not in s:
        # Preparation failed before touching GRUB: exact original state must still match.
        original = base64.b64decode(s['OriginalDefault']) if s['OriginalDefault'] else None
        if config_fingerprint() != s['BootConfigFingerprint'] or (DEFAULT.read_bytes() if DEFAULT.exists() else None) != original:
            raise RuntimeError('Preparing transaction boot drift')
        s['Phase'] = 'Aborted'; save(s); return s
    owned_boot(s); set_default(s, target['Entry']); run(['grub-editenv', '/boot/grub/grubenv', 'unset', 'next_entry'])
    s['RollbackKernel'] = target['Kernel']; s['RollbackToOriginal'] = original
    s['NextEntry'] = ''; save(s); remove_guard(s)
    if platform.release() == target['Kernel']:
        s['Phase'] = 'Aborted' if s['Phase'] in ('Preparing', 'InstallFailed', 'Prepared') else 'RolledBack'; save(s)
    else:
        s['OldBootId'] = runtime()['BootId']; s['Phase'] = 'RollbackRequested'; save(s)
        run(['systemd-run', '--unit=mxh-kernel-rollback-'+s['Id'], '--on-active=3s', '--', '/usr/bin/systemctl', 'reboot'])
    return s


def watchdog(identity):
    # Cannot recover a kernel which never starts user space; one-shot default remains old.
    s = load(identity)
    if platform.release() != s['Catalog']['Kernel']: return
    time.sleep(300)
    with (BASE/'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX); s = load(identity)
        if s['Phase'] in ('BootRequested', 'Booted'): rollback(s, s.get('ActivationFallbackOriginal', False))


def main():
    action = sys.argv[1]; identity = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('VPS_PARAM_TRANSACTION', '')
    if os.geteuid() != 0: raise RuntimeError('Root kernel operation required')
    if action == 'Audit': result = audit()
    elif action == 'Watchdog': watchdog(identity); return
    else:
        if not re.fullmatch('[a-f0-9]{32}', identity): raise RuntimeError('Invalid kernel transaction identity')
        for p in [BASE, *BASE.parents]:
            if p.is_symlink(): raise RuntimeError('Linked kernel directory refused')
        BASE.mkdir(parents=True, exist_ok=True, mode=0o700); regular(BASE/'lock', True)
        if BASE.stat().st_uid != 0 or BASE.stat().st_mode & 0o022: raise RuntimeError('Kernel directory ownership refused')
        with (BASE/'lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if action == 'Status' else 0))
            except BlockingIOError:
                if action != 'Status': raise
                regular(BASE/'current.json')
                if json.loads((BASE/'current.json').read_text()).get('Id') != identity: raise RuntimeError('Superseded kernel transaction refused')
                s = load(identity); s['Runtime'] = runtime(); s['ServicesHealthy'] = False
                print('VPSDEPLOY_KERNEL_RESULT_B64='+base64.b64encode(json.dumps(s, sort_keys=True).encode()).decode()); return
            if action == 'Prepare': result = prepare(identity)
            else:
                if action == 'Status' and not (BASE/identity).exists():
                    for managed in (DEFAULT, UNIT):
                        if managed.exists():
                            regular(managed)
                            if identity in managed.read_text(): raise RuntimeError('Kernel record missing while owned changes remain')
                    current = BASE/'current.json'
                    if current.exists():
                        regular(current); prior = load(json.loads(current.read_text())['Id'])
                        if prior['Phase'] not in TERMINAL: raise RuntimeError('Unfinished other kernel transaction refused')
                    cat = json.loads(os.environ['VPS_PARAM_CATALOG']); catalog_validate(cat, fresh=False)
                    result = {'SchemaVersion': 2, 'Owner': 'mxh-google-bbr-v3', 'Id': identity, 'Catalog': cat,
                              'Phase': 'Aborted', 'NoMutationConfirmed': True, 'OldKernel': platform.release(), 'Runtime': runtime(), 'ServicesHealthy': True}
                    print('VPSDEPLOY_KERNEL_RESULT_B64='+base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()); return
                s = load(identity)
                regular(BASE/'current.json')
                if json.loads((BASE/'current.json').read_text()).get('Id') != identity: raise RuntimeError('Superseded kernel transaction refused')
                if action == 'InstallWorker': install_worker(s); return
                if action == 'Status': result = status(s)
                elif action == 'Boot': result = boot(s)
                elif action == 'Confirm': result = confirm(s)
                elif action == 'Rollback': result = rollback(s, os.environ.get('VPS_PARAM_ROLLBACK_TARGET', 'Previous') == 'Original')
                else: raise RuntimeError('Unknown kernel action')
    print('VPSDEPLOY_KERNEL_RESULT_B64='+base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode())


def failure_code(error, action):
    if isinstance(error, KernelFailure): return error.code
    return 'KernelOperationRefused'


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = failure_code(error, sys.argv[1] if len(sys.argv) > 1 else '')
        print('VPSDEPLOY_KERNEL_FAILURE_CODE_B64='+base64.b64encode(code.encode()).decode())
        print('VPSDEPLOY_KERNEL_OPERATION_REFUSED', file=sys.stderr)
        raise SystemExit(1)
