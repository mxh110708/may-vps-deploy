"""Root-owned fixed kernel lifecycle. Mutation acknowledgements are never replayed."""
import base64
import datetime
import email.utils
import fcntl
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

BASE = Path('/var/lib/mxh-vps-deploy/kernel')
DEFAULT = Path('/etc/default/grub.d/99-mxh-bbr-kernel.cfg')
UNIT = Path('/etc/systemd/system/mxh-kernel-boot-guard.service')
TERMINAL = ('Committed', 'RolledBack', 'Aborted')


class KernelFailure(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def signature_verifier():
    for tool in ('sqv', 'gpgv'):
        if shutil.which(tool): return tool
    raise KernelFailure('KernelVerifierMissing')


def run(args, timeout=30, allow=False):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
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
    if s.get('SchemaVersion') != 1 or s.get('Id') != identity or s.get('Owner') != 'mxh-dotnet-kernel-v1':
        raise RuntimeError('Unknown kernel transaction refused')
    if s.get('Phase') not in ('Preparing', 'Installing', 'InstallFailed', 'Prepared', 'BootRequested', 'Booted', 'Committed', 'RollbackRequested', 'RolledBack', 'AutoRolledBack', 'Aborted'):
        raise RuntimeError('Unknown kernel phase refused')
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
    try: result['SignatureVerifier'] = signature_verifier()
    except KernelFailure: reasons.append('缺少签名验证工具（gpgv / sqv）')
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
    if result['FreeRootBytes'] < 1600000000 or result['FreeBootBytes'] < 350000000:
        reasons.append('根目录需至少 1.6 GB，启动目录需至少 350 MB 可用空间')
    result.update({'Compatible': not reasons, 'Reasons': reasons, 'Distribution': distro, 'Virtualization': virt})
    return result


def catalog_validate(cat, fresh=True):
    if cat.get('SchemaVersion') != 1 or cat.get('Architecture') != 'amd64' or cat.get('BbrVersion') != 3:
        raise RuntimeError('Unsupported kernel catalog')
    pattern = r'[0-9]+\.[0-9]+\.[0-9]+-x64v1-xanmod[0-9]+' if cat.get('Selection') == 'Latest' else r'6\.18\.[0-9]+-x64v1-xanmod1'
    if cat.get('Repository') != 'https://deb.xanmod.org/' or not re.fullmatch(pattern, cat.get('Kernel', '')):
        raise RuntimeError('Unsupported kernel source')
    if cat.get('Package') != 'linux-image-'+cat['Kernel'] or not re.fullmatch('[a-f0-9]{64}', cat.get('Sha256', '')):
        raise RuntimeError('Invalid package identity')
    if not re.fullmatch(r'pool/main/l/linux-upstream/[a-zA-Z0-9_.~+-]+\.deb', cat.get('Filename', '')):
        raise RuntimeError('Invalid package source path')
    age = datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(cat['SignedAt'].replace('Z', '+00:00'))
    if fresh and (age.total_seconds() < -86400 or age.days > 120):
        raise RuntimeError('Pinned catalog expired; update the application')


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


def signed_index(root, fingerprint):
    verifier = signature_verifier()
    with tempfile.TemporaryDirectory(prefix='mxh-kernel-signature-') as directory:
        authenticated = Path(directory)/'Release'
        if verifier == 'sqv':
            args = ['sqv', '--keyring', str(root/'xanmod.gpg'), '--cleartext', '--output', str(authenticated), str(root/'InRelease')]
        else:
            args = ['gpgv', '--status-fd', '1', '--keyring', str(root/'xanmod.gpg'), '--output', str(authenticated), str(root/'InRelease')]
        try: out = run(args)
        except FileNotFoundError: raise KernelFailure('KernelVerifierMissing') from None
        except (OSError, RuntimeError, subprocess.TimeoutExpired): raise KernelFailure('KernelSignatureRejected') from None
        valid = fingerprint in out.splitlines() if verifier == 'sqv' else '[GNUPG:] VALIDSIG '+fingerprint+' ' in out
        if not valid: raise KernelFailure('KernelSigningKeyMismatch')
        if not authenticated.is_file(): raise KernelFailure('KernelSignatureRejected')
        release = authenticated.read_text()
    pbytes = (root/'Packages.gz').read_bytes()
    pat = r'^ '+hashlib.sha256(pbytes).hexdigest()+r'\s+'+str(len(pbytes))+r'\s+main/binary-amd64/Packages.gz$'
    if not re.search(pat, release, re.M): raise KernelFailure('KernelIndexHashMismatch')
    date = re.findall(r'^Date: (.+)$', release, re.M)
    code = re.findall(r'^Codename: (.+)$', release, re.M)
    if len(date) != 1 or len(code) != 1: raise RuntimeError('Ambiguous signed release metadata')
    signed_at = email.utils.parsedate_to_datetime(date[0]).astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    with gzip.GzipFile(fileobj=__import__('io').BytesIO(pbytes)) as zipped:
        decoded = zipped.read(20971521)
    if len(decoded) > 20971520: raise RuntimeError('Oversized package index')
    entries = [dict(l.split(': ', 1) for l in p.splitlines() if ': ' in l and not l.startswith(' ')) for p in decoded.decode().split('\n\n')]
    return entries, signed_at, code[0]


def sources_verify(s):
    root = BASE / s['Id']; cat = s['Catalog']; catalog_validate(cat)
    entries, signed_at, code = signed_index(root, cat['SigningFingerprint'])
    if signed_at != cat['SignedAt'] or cat.get('Distribution', code) != code:
        raise RuntimeError('Signed date or distribution mismatch')
    entries = [p for p in entries if p.get('Package') == cat['Package'] and p.get('Version') == cat['PackageVersion']]
    if len(entries) != 1: raise RuntimeError('Pinned package absent from signed index')
    p = entries[0]
    if p.get('SHA256') != cat['Sha256'] or p.get('Filename') != cat['Filename'] or int(p.get('Size', 0)) != cat['Bytes']:
        raise RuntimeError('Pinned package differs from signed index')


def latest_candidate():
    # Read-only repository query. Never adds an APT source or installs a metapackage.
    anchor = json.loads(os.environ['VPS_PARAM_CATALOG']); catalog_validate(anchor, fresh=False)
    key = base64.b64decode(os.environ['VPS_PARAM_KEY'], validate=True)
    if hashlib.sha256(key).hexdigest() != anchor['SourceFiles']['xanmod.gpg']:
        raise RuntimeError('Signing trust anchor mismatch')
    signature_verifier()  # Refuse before network access when no verifier is available.
    info = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distribution = {'12': 'bookworm', '13': 'trixie'}.get(info.get('VERSION_ID', '').strip('"'))
    if info.get('ID', '').strip('"') != 'debian' or not distribution: raise RuntimeError('Latest kernel distribution unsupported')
    with tempfile.TemporaryDirectory(prefix='mxh-kernel-query-') as directory:
        root = Path(directory); (root/'xanmod.gpg').write_bytes(key)
        for name, suffix in [('InRelease', 'InRelease'), ('Packages.gz', 'main/binary-amd64/Packages.gz')]:
            url = 'https://deb.xanmod.org/dists/'+distribution+'/'+suffix
            request = urllib.request.Request(url, headers={'User-Agent': 'Debian APT-HTTP/1.3 (2.6.1)'})
            try:
                with urllib.request.urlopen(request, timeout=25) as response:
                    if not response.geturl().startswith('https://deb.xanmod.org/'): raise KernelFailure('KernelMetadataRejected')
                    data = response.read(2097153)
            except urllib.error.HTTPError as error:
                raise KernelFailure('KernelRepositoryForbidden' if error.code == 403 else 'KernelRepositoryRateLimited' if error.code == 429 else 'KernelRepositoryHttpFailed') from None
            except urllib.error.URLError as error:
                code = 'KernelRepositoryDnsFailed' if isinstance(error.reason, socket.gaierror) else 'KernelRepositoryTimeout' if isinstance(error.reason, TimeoutError) else 'KernelRepositoryUnavailable'
                raise KernelFailure(code) from None
            except TimeoutError: raise KernelFailure('KernelRepositoryTimeout') from None
            if len(data) > 2097152: raise RuntimeError('Oversized signed metadata')
            (root/name).write_bytes(data)
        entries, signed_at, code = signed_index(root, anchor['SigningFingerprint'])
        if code != distribution: raise RuntimeError('Repository distribution mismatch')
        metas = [p for p in entries if p.get('Package') == 'linux-xanmod-lts-x64v1' and p.get('Architecture') == 'amd64']
        if len(metas) != 1: raise RuntimeError('Ambiguous compatible LTS release')
        images = re.findall(r'(?:^|,\s*)(linux-image-([0-9]+\.[0-9]+\.[0-9]+-x64v1-xanmod[0-9]+))(?=,|$|\s)', metas[0].get('Depends', ''))
        if len(images) != 1: raise RuntimeError('Compatible LTS image dependency unavailable')
        package, kernel = images[0]
        images = [p for p in entries if p.get('Package') == package and p.get('Architecture') == 'amd64']
        if len(images) != 1: raise RuntimeError('Ambiguous latest LTS image')
        image = images[0]
        sources = {name: base64.b64encode((root/name).read_bytes()).decode() for name in ('xanmod.gpg', 'InRelease', 'Packages.gz')}
        cat = {'SchemaVersion': 1, 'Id': 'xanmod-lts-'+kernel, 'Vendor': 'XanMod LTS', 'Kernel': kernel,
               'Package': package, 'PackageVersion': image['Version'], 'Architecture': 'amd64', 'BbrVersion': 3,
               'Repository': anchor['Repository'], 'Filename': image['Filename'], 'Bytes': int(image['Size']), 'Sha256': image['SHA256'],
               'SignedAt': signed_at, 'SigningFingerprint': anchor['SigningFingerprint'], 'Selection': 'Latest', 'Distribution': distribution,
               'SourceFiles': {name: hashlib.sha256(base64.b64decode(data)).hexdigest() for name, data in sources.items()}}
        catalog_validate(cat)
        return {'Catalog': cat, 'Sources': sources, 'FetchedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def prepare(identity):
    cat = json.loads(os.environ['VPS_PARAM_CATALOG']); catalog_validate(cat); a = audit()
    if not a['Compatible']: raise RuntimeError('Kernel preflight refused')
    if a['BbrVersion'] == 'v3': raise RuntimeError('BBR v3 already available')
    current = BASE/'current.json'; previous = None
    if current.exists():
        regular(current); previous = load(json.loads(current.read_text())['Id'])
        if previous['Phase'] not in TERMINAL: raise RuntimeError('Unfinished kernel transaction refused')
    target = BASE/identity
    if target.exists(): raise RuntimeError('Kernel transaction already exists; reconcile only')
    if DEFAULT.exists() and (not previous or digest(DEFAULT) != previous.get('OwnedDefaultSha256')):
        raise RuntimeError('Unmanaged boot default collision')
    if UNIT.exists(): raise RuntimeError('Existing kernel boot guard refused')
    target.mkdir(mode=0o700); env = boot_environment()
    s = {'SchemaVersion': 1, 'Owner': 'mxh-dotnet-kernel-v1', 'Id': identity, 'Phase': 'Preparing', 'Catalog': cat,
         'OldKernel': a['Kernel'], 'OldBootId': a['BootId'], 'OldEntry': a['CurrentEntry'], 'OriginalGrubEnvironment': env,
         'OriginalDefault': base64.b64encode(DEFAULT.read_bytes()).decode() if DEFAULT.exists() else None,
         'BootConfigFingerprint': config_fingerprint(), 'SavedEntry': env.get('saved_entry', ''), 'InstallInvocations': 0,
         'Services': [unit for unit in ('ssh.service', 'sshd.service', 'xray.service', 'sing-box.service', 'sing-box-anytls.service', 'sing-box-shadowsocks.service', 'komari-agent.service', 'komari.service', 'cloudflared.service') if run(['systemctl', 'is-active', unit], allow=True) == 'active']}
    s['OldImageSha256'] = digest(Path('/boot/vmlinuz-'+s['OldKernel'])); s['OldInitrdSha256'] = digest(Path('/boot/initrd.img-'+s['OldKernel']))
    save(s); put(current, json.dumps({'Id': identity}).encode())
    put(target/'engine.py', (os.environ['VPS_BBR_PROGRAM']+'\n'+os.environ['VPS_KERNEL_PROGRAM']).encode())
    for name in ('xanmod.gpg', 'InRelease', 'Packages.gz'):
        data = base64.b64decode(os.environ['VPS_PARAM_SOURCE_'+name.replace('.', '_').upper()], validate=True)
        if hashlib.sha256(data).hexdigest() != cat['SourceFiles'][name]: raise RuntimeError('Public source file mismatch')
        put(target/name, data)
    sources_verify(s); set_default(s, s['OldEntry']); s['Phase'] = 'Installing'; save(s)
    # Client waiting is bounded separately. Never kill dpkg halfway through a package write.
    run(['systemd-run', '--unit=mxh-kernel-install-'+identity, '--property=Type=exec',
         '--', '/usr/bin/python3', str(target/'engine.py'), 'InstallWorker', identity])
    return s


def install_worker(s):
    if s['Phase'] != 'Installing' or s['InstallInvocations'] != 0: raise RuntimeError('Install replay refused')
    s['InstallInvocations'] = 1; save(s)
    stage = 'SourceVerification'
    try:
        owned_boot(s); sources_verify(s); cat = s['Catalog']; package = BASE/s['Id']/'kernel.deb'
        stage = 'PackageDownload'
        request = urllib.request.Request(cat['Repository']+cat['Filename'], headers={'User-Agent': 'Debian APT-HTTP/1.3 (2.6.1)'})
        with urllib.request.urlopen(request, timeout=30) as r:
            if not r.geturl().startswith('https://deb.xanmod.org/'): raise RuntimeError('Untrusted package redirect')
            count = 0; h = hashlib.sha256(); regular(package, True)
            with package.open('xb') as f:
                for part in iter(lambda: r.read(1048576), b''):
                    count += len(part)
                    if count > cat['Bytes']: raise RuntimeError('Oversized package')
                    h.update(part); f.write(part)
                f.flush(); os.fsync(f.fileno())
        if count != cat['Bytes'] or h.hexdigest() != cat['Sha256']: raise RuntimeError('Package digest mismatch')
        stage = 'PackageIdentity'
        fields = dict(line.split(': ', 1) for line in run(['dpkg-deb', '-f', str(package), 'Package', 'Version', 'Architecture']).splitlines())
        if fields != {'Package': cat['Package'], 'Version': cat['PackageVersion'], 'Architecture': 'amd64'}:
            raise RuntimeError('Debian package identity mismatch')
        stage = 'DependencyPlan'
        preview = run(['apt-get', '-s', '--no-remove', 'install', str(package)], 90)
        changes = [line for line in preview.splitlines() if line.startswith(('Inst ', 'Remv '))]
        if len(changes) != 1 or not changes[0].startswith('Inst '+cat['Package']+' '):
            raise RuntimeError('Unexpected package dependency mutation refused')
        stage = 'PackageInstall'
        run(['apt-get', '-y', '--no-remove', '-o', 'DPkg::Lock::Timeout=30', 'install', str(package)], None)
        stage = 'InstalledArtifacts'
        if run(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', cat['Package']]) != 'installed '+cat['PackageVersion']:
            raise RuntimeError('Kernel installation unconfirmed')
        s['NewEntry'] = entry(cat['Kernel']); s['NewImageSha256'] = digest(Path('/boot/vmlinuz-'+cat['Kernel']))
        s['NewInitrdSha256'] = digest(Path('/boot/initrd.img-'+cat['Kernel']))
        if digest(Path('/boot/vmlinuz-'+s['OldKernel'])) != s['OldImageSha256']: raise RuntimeError('Old kernel changed')
        owned_boot(s); s['Phase'] = 'Prepared'; save(s)
    except Exception:
        s['Phase'] = 'InstallFailed'; s['FailureStage'] = stage; save(s)
        raise


def status(s):
    s['Runtime'] = runtime()
    if s['Phase'] == 'Installing':
        active = run(['systemctl', 'is-active', 'mxh-kernel-install-'+s['Id']], allow=True)
        if active not in ('active', 'activating'): s['Phase'] = 'InstallFailed'; save(s)
    if s['Phase'] in ('BootRequested', 'RollbackRequested') and s['Runtime']['BootId'] != s['OldBootId']:
        expected = s['Catalog']['Kernel'] if s['Phase'] == 'BootRequested' else s['OldKernel']
        if s['Runtime']['Kernel'] == expected:
            s['Phase'] = 'Booted' if expected == s['Catalog']['Kernel'] else 'RolledBack'; save(s)
        elif s['Runtime']['Kernel'] == s['OldKernel']:
            s['Phase'] = 'AutoRolledBack'; save(s)
    s['ServicesHealthy'] = all(run(['systemctl', 'is-active', unit], allow=True) == 'active' for unit in s['Services'])
    return s


def boot(s):
    if s['Phase'] not in ('Prepared', 'RolledBack', 'Aborted') or not s.get('NewImageSha256') or platform.release() != s['OldKernel']: raise RuntimeError('Kernel boot phase refused')
    owned_boot(s)
    if digest(Path('/boot/vmlinuz-'+s['Catalog']['Kernel'])) != s['NewImageSha256'] or digest(Path('/boot/initrd.img-'+s['Catalog']['Kernel'])) != s['NewInitrdSha256']:
        raise RuntimeError('Installed boot image drift')
    guard = '[Unit]\nDescription=MXH bounded kernel boot acceptance\nAfter=network.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 '+str(BASE/s['Id']/'engine.py')+' Watchdog '+s['Id']+'\n[Install]\nWantedBy=multi-user.target\n'
    put(UNIT, guard.encode(), 0o644); s['GuardSha256'] = digest(UNIT)
    run(['systemctl', 'daemon-reload']); run(['systemctl', 'enable', 'mxh-kernel-boot-guard.service'])
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


def rollback(s):
    s = status(s)
    if s['Phase'] == 'Installing': raise RuntimeError('Package installer still active; reconcile first')
    if s['Phase'] in ('RollbackRequested', 'RolledBack', 'Aborted'): return s
    if digest(Path('/boot/vmlinuz-'+s['OldKernel'])) != s['OldImageSha256'] or digest(Path('/boot/initrd.img-'+s['OldKernel'])) != s['OldInitrdSha256']:
        raise RuntimeError('Old boot image drift; refuse reboot')
    if 'OwnedDefaultSha256' not in s:
        # Preparation failed before touching GRUB: exact original state must still match.
        original = base64.b64decode(s['OriginalDefault']) if s['OriginalDefault'] else None
        if config_fingerprint() != s['BootConfigFingerprint'] or (DEFAULT.read_bytes() if DEFAULT.exists() else None) != original:
            raise RuntimeError('Preparing transaction boot drift')
        s['Phase'] = 'Aborted'; save(s); return s
    owned_boot(s); set_default(s, s['OldEntry']); run(['grub-editenv', '/boot/grub/grubenv', 'unset', 'next_entry'])
    s['NextEntry'] = ''; save(s); remove_guard(s)
    if platform.release() == s['OldKernel']:
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
        if s['Phase'] in ('BootRequested', 'Booted'): rollback(s)


def main():
    action = sys.argv[1]; identity = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('VPS_PARAM_TRANSACTION', '')
    if os.geteuid() != 0: raise RuntimeError('Root kernel operation required')
    if action == 'Audit': result = audit()
    elif action == 'Latest': result = latest_candidate()
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
                    result = {'SchemaVersion': 1, 'Owner': 'mxh-dotnet-kernel-v1', 'Id': identity, 'Catalog': cat,
                              'Phase': 'Aborted', 'NoMutationConfirmed': True, 'OldKernel': platform.release(), 'Runtime': runtime(), 'ServicesHealthy': True}
                    print('VPSDEPLOY_KERNEL_RESULT_B64='+base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()); return
                s = load(identity)
                regular(BASE/'current.json')
                if json.loads((BASE/'current.json').read_text()).get('Id') != identity: raise RuntimeError('Superseded kernel transaction refused')
                if action == 'InstallWorker': install_worker(s); return
                if action == 'Status': result = status(s)
                elif action == 'Boot': result = boot(s)
                elif action == 'Confirm': result = confirm(s)
                elif action == 'Rollback': result = rollback(s)
                else: raise RuntimeError('Unknown kernel action')
    print('VPSDEPLOY_KERNEL_RESULT_B64='+base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode())


def failure_code(error, action):
    if isinstance(error, KernelFailure): return error.code
    return 'KernelMetadataRejected' if action == 'Latest' else 'KernelOperationRefused'


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = failure_code(error, sys.argv[1] if len(sys.argv) > 1 else '')
        print('VPSDEPLOY_KERNEL_FAILURE_CODE_B64='+base64.b64encode(code.encode()).decode())
        print('VPSDEPLOY_KERNEL_OPERATION_REFUSED', file=sys.stderr)
        raise SystemExit(1)
