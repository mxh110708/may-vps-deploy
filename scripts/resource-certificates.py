"""Bounded, read-only certificate observations for explicitly archived consumers.

No issuance, renewal, private-key output, service action or arbitrary path input.
The controller compares these observations with its archived resource identities.
"""
import base64
import datetime
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess


FIXED = {'anytls': '/etc/mxh-tls/anytls/fullchain.pem',
         'reality': '/etc/mxh-tls/reality-target/fullchain.pem'}
LIMIT = 4 * 1024 * 1024


def request(value):
    if not isinstance(value, dict) or set(value) != {'Version', 'Items'} or value['Version'] != 1:
        raise ValueError('Unsupported certificate request.')
    items = value['Items']
    if not isinstance(items, list) or len(items) > 18:
        raise ValueError('Certificate request exceeds its scope.')
    keys = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {'Key', 'ServerNames'}:
            raise ValueError('Unexpected certificate request fields.')
        key, names = item['Key'], item['ServerNames']
        if not isinstance(key, str) or (key not in FIXED and not re.fullmatch('inbound:[a-f0-9]{32}', key)) or key in keys:
            raise ValueError('Invalid or duplicate certificate identity.')
        keys.add(key)
        if not isinstance(names, list) or not 1 <= len(names) <= 2 or not all(isinstance(n, str) for n in names) or len(set(names)) != len(names):
            raise ValueError('Explicit certificate consumers are required.')
        for name in names:
            if not isinstance(name, str) or len(name) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', name):
                raise ValueError('Invalid certificate hostname.')
    return items


def read_regular(root, absolute):
    path = root.joinpath(*PurePosixPath(absolute).parts[1:])
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise ValueError('Linked certificate resource.')
        if parent == root:
            break
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError('Certificate resource is not a bounded regular file.')
        data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError('Certificate resource grew past its bound.')
        return data


def certificate_bytes(root, key):
    if key in FIXED:
        data = read_regular(root, FIXED[key])
        if b'PRIVATE KEY' in data:
            raise ValueError('Certificate path contains private key material.')
        return data
    identifier = key.split(':')[1]
    config = json.loads(read_regular(root, '/etc/may-inbounds/' + identifier + '.json'))
    inbound, = config['inbounds']
    if inbound.get('tag') != identifier:
        raise ValueError('Certificate consumer identity changed.')
    if 'streamSettings' in inbound:
        if inbound['streamSettings'].get('security') != 'tls':
            raise ValueError('Consumer does not use a local TLS certificate.')
        material, = inbound['streamSettings']['tlsSettings']['certificates']
        material = material['certificate']
    else:
        material = inbound['tls']['certificate']
    if isinstance(material, list) and all(isinstance(line, str) for line in material):
        material = '\n'.join(material)
    if not isinstance(material, str) or 'PRIVATE KEY' in material or len(material) > 1024 * 1024:
        raise ValueError('Invalid public certificate material.')
    return material.encode('ascii')


def command(run, arguments, pem):
    result = run(['openssl', 'x509', *arguments], input=pem, capture_output=True, timeout=3)
    if len(result.stdout) > 16384:
        raise ValueError('Unexpected certificate output.')
    return result


def collect(value, root=Path('/'), run=subprocess.run, now=None):
    items = request(value)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    results = []
    for item in items:
        entry = {'Key': item['Key'], 'Status': 'Unreadable'}
        try:
            try:
                pem = certificate_bytes(root, item['Key'])
            except FileNotFoundError:
                entry['Status'] = 'Missing'
                results.append(entry)
                continue
            dates = command(run, ['-noout', '-dates', '-sha256', '-fingerprint'], pem)
            if dates.returncode != 0:
                raise ValueError('Invalid public certificate.')
            fields = dict(line.split('=', 1) for line in dates.stdout.decode('ascii').splitlines() if '=' in line)
            def date(name):
                return datetime.datetime.strptime(fields[name], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).isoformat()
            digest = fields.get('sha256 Fingerprint', fields.get('SHA256 Fingerprint', '')).replace(':', '').lower()
            if not re.fullmatch('[a-f0-9]{64}', digest):
                raise ValueError('Missing certificate identity.')
            matches = []
            for name in item['ServerNames']:
                check = command(run, ['-noout', '-checkhost', name], pem)
                # Some OpenSSL versions return zero even when checkhost fails.
                matches.append(check.returncode == 0 and check.stdout.decode('ascii').strip() == 'Hostname ' + name + ' does match certificate')
            entry.update(Status='Observed', NotBefore=date('notBefore'), NotAfter=date('notAfter'), Sha256=digest, HostnameMatches=all(matches))
        except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.TimeoutExpired):
            pass  # No raw exceptions, PEM, configuration or command stderr leave the host.
        results.append(entry)
    return {'Version': 1, 'CollectedAt': now.isoformat(), 'Items': results}


if __name__ == '__main__':
    value = json.loads(os.environ.get('VPS_PARAM_CERTIFICATE_REQUEST', '{}'))
    result = collect(value)
    print('VPSDEPLOY_RESOURCE_CERTIFICATES_B64=' + base64.b64encode(json.dumps(result, separators=(',', ':')).encode()).decode())
    print('VPSDEPLOY_RESOURCE_READ_OK')
