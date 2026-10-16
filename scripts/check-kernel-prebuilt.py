"""Verify the embedded kernel and its corresponding-source release attachment."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile


def digest(path):
    with path.open('rb') as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''): result.update(block)
    return result.hexdigest()


def package_identity(path):
    # Read only the small Debian control member; do not unpack executables.
    with path.open('rb') as stream:
        if stream.read(8) != b'!<arch>\n': raise ValueError('Not a Debian ar package')
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b'`\n': raise ValueError('Invalid Debian ar member')
            name = header[:16].decode().strip().rstrip('/'); size = int(header[48:58])
            if name.startswith('control.tar'):
                if not 0 < size <= 1048576: raise ValueError('Oversized package control')
                with tarfile.open(fileobj=io.BytesIO(stream.read(size)), mode='r:*') as archive:
                    info = archive.getmember('./control')
                    if not info.isfile() or info.size > 65536: raise ValueError('Invalid package control')
                    fields = {}
                    for line in archive.extractfile(info).read().decode().splitlines():
                        if line and not line[0].isspace() and ': ' in line:
                            key, value = line.split(': ', 1); fields[key] = value
                    return {key: fields.get(key) for key in ('Package', 'Version', 'Architecture')}
            stream.seek(size+size%2, 1)
    raise ValueError('No package control')


def verify(project, source_archive=None):
    catalog = json.loads((project/'config/kernel-catalog.json').read_text(encoding='utf-8-sig'))
    root = project/'assets/kernel'; item = catalog['Prebuilt']
    for path in (root, *root.parents):
        if path.is_symlink(): raise ValueError('Linked artifact path')
    for path in root.iterdir():
        if path.is_symlink(): raise ValueError('Linked artifact')
    if item['File'] != 'kernel.deb' or digest(root/'build-manifest.json') != item['ManifestSha256']: raise ValueError('Manifest drift')
    manifest = json.loads((root/'build-manifest.json').read_text())
    if manifest['SchemaVersion'] != 1 or manifest['BuildProfile'] != 'debian-generic-amd64-v1' or manifest['GitFsckPassed'] is not True: raise ValueError('Unknown build profile')
    for key in ('Kernel', 'Package', 'PackageVersion', 'Architecture'):
        if manifest[key] != catalog[key]: raise ValueError('Source/package identity drift')
    for key, field in (('SourceCommit','Commit'), ('SourceTree','Tree'), ('SourceMaterialsSha256','Sha256')):
        if manifest[key] != catalog[field]: raise ValueError('Source provenance drift')
    for name, key in (('kernel.deb','PackageSha256'), ('kernel.config','ConfigSha256'), ('input.config','InputConfigSha256')):
        if not re.fullmatch('[a-f0-9]{64}', manifest[key]) or digest(root/name) != manifest[key]: raise ValueError('Artifact digest mismatch: '+name)
    if item['Sha256'] != manifest['PackageSha256'] or item['Bytes'] != manifest['PackageBytes'] or (root/'kernel.deb').stat().st_size != item['Bytes']: raise ValueError('Package size/digest drift')
    if package_identity(root/'kernel.deb') != {'Package':catalog['Package'], 'Version':catalog['PackageVersion'], 'Architecture':'amd64'}: raise ValueError('Debian package identity drift')
    if set(manifest['BuildFiles']) != {'scripts/kernel-source.py','scripts/kernel-build.py','scripts/build-kernel-prebuilt.py'}: raise ValueError('Incomplete build recipe')
    config = (root/'kernel.config').read_bytes().splitlines()
    for required in (b'CONFIG_GENERIC_CPU=y', b'CONFIG_TCP_CONG_BBR=y', b'CONFIG_NET_SCH_FQ=y', b'CONFIG_DEVTMPFS_MOUNT=y'):
        if required not in config: raise ValueError('Generic VPS build configuration mismatch')
    for name, expected in manifest['BuildFiles'].items():
        if name not in ('scripts/kernel-source.py','scripts/kernel-build.py','scripts/build-kernel-prebuilt.py') or digest(project/name) != expected: raise ValueError('Build recipe drift')
    if source_archive is not None:
        if source_archive.is_symlink() or source_archive.stat().st_size != manifest['SourceArchiveBytes'] or digest(source_archive) != manifest['SourceArchiveSha256']: raise ValueError('Corresponding source archive drift')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--source-archive', type=Path)
    args = parser.parse_args(); result = verify(args.project, args.source_archive)
    print(json.dumps({'Verified':True, 'Kernel':result['Kernel'], 'PackageSha256':result['PackageSha256'], 'SourceArchiveVerified':args.source_archive is not None}))
