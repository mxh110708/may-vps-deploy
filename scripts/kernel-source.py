"""Google BBR v3 source identity. No third-party kernel binary is accepted."""
import base64
import datetime
import hashlib
import json
import re
import socket
import urllib.error
import urllib.request

GOOGLE_REPOSITORY = 'https://github.com/google/bbr'
GOOGLE_API = 'https://api.github.com/repos/google/bbr/'
GOOGLE_RAW = 'https://raw.githubusercontent.com/google/bbr/'
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


def catalog_validate(cat, fresh=True):
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


def official_read(url, limit=1048576):
    if not (url.startswith(GOOGLE_API) or url.startswith(GOOGLE_RAW)): raise KernelFailure('KernelSourceRejected')
    request = urllib.request.Request(url, headers={'User-Agent': 'MXH-Google-BBR-Source/1', 'Accept': 'application/vnd.github+json'})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            if response.geturl() != url: raise KernelFailure('KernelSourceRejected')
            data = response.read(limit+1)
    except urllib.error.HTTPError as error:
        rate = error.code == 429 or error.code == 403 and error.headers.get('X-RateLimit-Remaining') == '0'
        raise KernelFailure('KernelRepositoryRateLimited' if rate else 'KernelRepositoryForbidden' if error.code == 403 else 'KernelRepositoryHttpFailed') from None
    except urllib.error.URLError as error:
        raise KernelFailure('KernelRepositoryDnsFailed' if isinstance(error.reason, socket.gaierror) else 'KernelRepositoryTimeout' if isinstance(error.reason, TimeoutError) else 'KernelRepositoryUnavailable') from None
    except TimeoutError: raise KernelFailure('KernelRepositoryTimeout') from None
    if not data or len(data) > limit: raise KernelFailure('KernelMetadataRejected')
    return data


def latest_candidate():
    import os
    catalog_validate(json.loads(os.environ['VPS_PARAM_CATALOG']))
    ref = json.loads(official_read(GOOGLE_API+'git/ref/heads/v3')); sha = ref.get('object', {}).get('sha', '')
    if ref.get('ref') != 'refs/heads/v3' or ref.get('object', {}).get('type') != 'commit' or not re.fullmatch('[a-f0-9]{40}', sha): raise KernelFailure('KernelMetadataRejected')
    materials = {'commit.json': official_read(GOOGLE_API+'git/commits/'+sha),
                 'Makefile': official_read(GOOGLE_RAW+sha+'/Makefile'),
                 'tcp_bbr.c': official_read(GOOGLE_RAW+sha+'/net/ipv4/tcp_bbr.c')}
    cat = source_catalog(materials)
    if cat['Commit'] != sha: raise KernelFailure('KernelMetadataRejected')
    cat['Selection'] = 'Latest'
    return {'Catalog': cat, 'Sources': {name: base64.b64encode(data).decode() for name, data in materials.items()},
            'FetchedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def kernel_version(kernel):
    match = re.match(r'^([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+]|$)', kernel)
    if not match: raise KernelFailure('KernelMetadataRejected')
    return tuple(map(int, match.groups()))
