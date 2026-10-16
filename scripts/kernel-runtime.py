"""Offline identity validation for the fixed embedded Google-source kernel. No compiler or version query."""
import base64
import datetime
import hashlib
import json
import re

GOOGLE_REPOSITORY = 'https://github.com/google/bbr'
SOURCE_NAMES = ('commit.json', 'Makefile', 'tcp_bbr.c')
CATALOG_OWNER = 'Google BBR v3 source / MXH local build'


class KernelFailure(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def source_digest(files):
    return hashlib.sha256('\n'.join(name+':'+files[name] for name in sorted(SOURCE_NAMES)).encode()).hexdigest()


def source_catalog(materials):
    if set(materials) != set(SOURCE_NAMES) or any(not isinstance(v, bytes) or not 0 < len(v) <= 1048576 for v in materials.values()):
        raise KernelFailure('KernelMetadataRejected')
    commit = json.loads(materials['commit.json']); sha = commit.get('sha', ''); tree = commit.get('tree', {}).get('sha', '')
    if not re.fullmatch('[a-f0-9]{40}', sha) or not re.fullmatch('[a-f0-9]{40}', tree): raise KernelFailure('KernelMetadataRejected')
    makefile = materials['Makefile'].decode(); values = {}
    for key in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL', 'EXTRAVERSION'):
        matches = re.findall(r'^'+key+r'[ \t]*=[ \t]*([^\n]*)$', makefile, re.M)
        if len(matches) != 1: raise KernelFailure('KernelMetadataRejected')
        values[key] = matches[0].strip()
    if values['EXTRAVERSION'] or any(not re.fullmatch('[0-9]+', values[k]) for k in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL')):
        raise KernelFailure('KernelSourcePrerelease')
    if not re.search(r'^#define\s+BBR_VERSION\s+3\s*$', materials['tcp_bbr.c'].decode(), re.M): raise KernelFailure('KernelSourceNotV3')
    date = commit.get('committer', {}).get('date', '')
    parsed = datetime.datetime.fromisoformat(date.replace('Z', '+00:00'))
    if parsed.utcoffset() is None or parsed > datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5): raise KernelFailure('KernelMetadataRejected')
    version = '.'.join(values[k] for k in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL'))
    kernel = version+'-mxh-bbr3-'+sha[:12]
    files = {name: hashlib.sha256(materials[name]).hexdigest() for name in SOURCE_NAMES}
    return {'SchemaVersion': 2, 'Id': 'google-bbr-v3-'+sha[:12], 'Vendor': CATALOG_OWNER,
            'Repository': GOOGLE_REPOSITORY, 'Branch': 'v3', 'Commit': sha, 'Tree': tree, 'SourceDate': date,
            'BaseKernel': version, 'Kernel': kernel, 'Package': 'linux-image-'+kernel,
            'PackageVersion': version+'-1.mxh'+sha[:12], 'Architecture': 'amd64', 'BbrVersion': 3,
            'BuildRecipe': 1, 'SourceFiles': files, 'Sha256': source_digest(files)}


def prebuilt_validate(cat):
    item = cat.get('Prebuilt')
    if (not isinstance(item, dict) or item.get('File') != 'kernel.deb'
        or not re.fullmatch('[a-f0-9]{64}', item.get('Sha256', ''))
        or not re.fullmatch('[a-f0-9]{64}', item.get('ManifestSha256', ''))
        or type(item.get('Bytes')) is not int or not 0 < item['Bytes'] <= 1073741824):
        raise KernelFailure('KernelPrebuiltRejected')
    return item


def catalog_validate(cat, fresh=True):
    prebuilt_validate(cat)
    if 'Selection' in cat: raise KernelFailure('KernelSourceRejected')
    sha = cat.get('Commit', ''); version = cat.get('BaseKernel', '')
    if cat.get('SchemaVersion') != 2 or cat.get('Repository') != GOOGLE_REPOSITORY or cat.get('Branch') != 'v3' or cat.get('Vendor') != CATALOG_OWNER or cat.get('Architecture') != 'amd64' or cat.get('BbrVersion') != 3 or cat.get('BuildRecipe') != 1:
        raise KernelFailure('KernelSourceRejected')
    if not re.fullmatch('[a-f0-9]{40}', sha) or not re.fullmatch('[a-f0-9]{40}', cat.get('Tree', '')) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version): raise KernelFailure('KernelMetadataRejected')
    kernel = version+'-mxh-bbr3-'+sha[:12]
    if cat.get('Id') != 'google-bbr-v3-'+sha[:12] or cat.get('Kernel') != kernel or cat.get('Package') != 'linux-image-'+kernel or cat.get('PackageVersion') != version+'-1.mxh'+sha[:12]: raise KernelFailure('KernelMetadataRejected')
    files = cat.get('SourceFiles', {})
    if set(files) != set(SOURCE_NAMES) or any(not re.fullmatch('[a-f0-9]{64}', value) for value in files.values()) or cat.get('Sha256') != source_digest(files): raise KernelFailure('KernelMetadataRejected')
    date = datetime.datetime.fromisoformat(cat.get('SourceDate', '').replace('Z', '+00:00'))
    if date.utcoffset() is None or date > datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5): raise KernelFailure('KernelMetadataRejected')


def verify_materials(cat, materials):
    catalog_validate(cat)
    expected = source_catalog(materials)
    if any(cat.get(key) != value for key, value in expected.items()): raise KernelFailure('KernelMetadataRejected')


def kernel_version(kernel):
    match = re.match(r'^([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+]|$)', kernel)
    if not match: raise KernelFailure('KernelMetadataRejected')
    return tuple(map(int, match.groups()))
