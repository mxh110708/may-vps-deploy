#!/usr/bin/env bash
set -euo pipefail

[[ -n "${VPS_PARAM_COMPONENTS:-${VPS_PARAM_COMPONENT:-}}" ]]
python3 <<'PY'
import base64, configparser, hashlib, json, os, pathlib, subprocess

components = os.environ.get('VPS_PARAM_COMPONENTS', os.environ.get('VPS_PARAM_COMPONENT', '')).split(',')
definitions = {
 'RealityEntry': ('xray.service', '/usr/local/bin/xray', ['/usr/local/etc/xray', '/usr/local/share/xray', '/etc/systemd/system/xray@.service', '/etc/systemd/system/xray.service.d']),
 'AnyTlsEntry': ('sing-box-anytls.service', '/usr/local/bin/sing-box-anytls', ['/etc/sing-box-anytls', '/var/lib/sing-box-anytls']),
 'ShadowsocksLanding': ('sing-box.service', '/usr/local/bin/sing-box', ['/etc/sing-box', '/var/lib/sing-box', '/etc/systemd/system/sing-box.service.d']),
 'KomariAgent': ('komari-agent.service', '/usr/local/bin/komari-agent', ['/etc/komari-agent', '/var/lib/komari-agent']),
 'KomariController': ('komari.service', '/usr/local/bin/komari', ['/usr/bin/komari', '/opt/komari', '/var/lib/komari']),
 'Tunnel': ('cloudflared.service', '/usr/local/bin/cloudflared', ['/usr/bin/cloudflared', '/etc/cloudflared', '/root/.cloudflared']),
}
if not components or len(set(components)) != len(components) or any(component not in definitions for component in components): raise SystemExit('Unsupported installation components')

def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15)

def digest(path):
    p = pathlib.Path(path)
    if not p.is_file() or p.is_symlink(): return None
    h = hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''): h.update(block)
    return h.hexdigest()

def reusable_anytls_certificate():
    # Normal uninstall deliberately retains shared TLS. Only the exact managed
    # lineage and credential layout for the requested domains may be reused.
    requested = set(filter(None, os.environ.get('VPS_PARAM_ANYTLS_DOMAINS', '').split(',')))
    if not requested: return False
    renewal = pathlib.Path('/etc/letsencrypt/renewal/mxh-anytls.conf')
    runner = pathlib.Path('/usr/local/libexec/mxh-certbot-dns')
    if any(not p.is_file() or p.is_symlink() or p.stat().st_uid != 0 or any(parent.is_symlink() for parent in p.parents) for p in (renewal, runner)): return False
    if '# MXH managed Cloudflare DNS API transport' not in runner.read_text().splitlines(): return False
    parser = configparser.ConfigParser(interpolation=None); parser.read_string('[lineage]\n' + renewal.read_text())
    section = parser['renewalparams']
    if section.get('authenticator') != 'dns-cloudflare' or section.get('dns_cloudflare_credentials') not in ('/etc/letsencrypt/cloudflare.ini', '/etc/letsencrypt/mxh-anytls-cloudflare.ini'): return False
    for leaf in ('fullchain.pem', 'privkey.pem'):
        live = pathlib.Path('/etc/letsencrypt/live/mxh-anytls') / leaf
        local = pathlib.Path('/etc/mxh-tls/anytls') / leaf
        if not live.is_file() or not local.is_file() or local.is_symlink() or local.stat().st_uid != 0 or any(parent.is_symlink() for parent in local.parents) or any(parent.is_symlink() for parent in live.parents): return False
        resolved = live.resolve()
        if resolved.parent != pathlib.Path('/etc/letsencrypt/archive/mxh-anytls') or resolved.is_symlink() or any(parent.is_symlink() for parent in resolved.parents): return False
        if local.read_bytes() != live.read_bytes(): return False
    names = run('openssl', 'x509', '-in', '/etc/mxh-tls/anytls/fullchain.pem', '-noout', '-ext', 'subjectAltName')
    if names.returncode != 0: return False
    import re
    return set(re.findall(r'DNS:([^,\s]+)', names.stdout)) == requested

def snapshot(name):
    unit, binary, paths = definitions[name]
    configs = {'RealityEntry': '/usr/local/etc/xray/config.json', 'AnyTlsEntry': '/etc/sing-box-anytls/config.json', 'ShadowsocksLanding': '/etc/sing-box/config.json', 'KomariAgent': '/etc/komari-agent/config.json', 'Tunnel': '/etc/cloudflared/mxh-token'}
    return {'Unit': run('systemctl', 'cat', unit).returncode == 0,
            'Enabled': run('systemctl', 'is-enabled', '--quiet', unit).returncode == 0,
            'Active': run('systemctl', 'is-active', '--quiet', unit).returncode == 0,
            'BinaryHash': digest(binary), 'ConfigHash': digest(configs.get(name, '/nonexistent-mxh-config')),
            'UnitHash': digest('/etc/systemd/system/' + unit)}

result = {'Allowed': False, 'Code': 'InstallationCheckIncomplete'}
try:
    services = {name: snapshot(name) for name in definitions}
    candidates = []
    for component in components:
        unit, binary, paths = definitions[component]
        candidates += [binary, '/etc/systemd/system/' + unit, '/etc/systemd/system/' + unit + '.d', *paths]
        if component == 'AnyTlsEntry' and os.environ.get('VPS_PARAM_CERTIFICATE_PREPARED') != 'true' and not reusable_anytls_certificate(): candidates += ['/etc/mxh-tls/anytls', '/etc/letsencrypt/live/mxh-anytls', '/etc/letsencrypt/renewal/mxh-anytls.conf']
    if os.environ.get('VPS_PARAM_VERIFY_ONLY') == 'true':
        baseline = json.loads(os.environ['VPS_PARAM_BEFORE_JSON'])
        if baseline['Components'] != components: raise ValueError('Installation scope changed')
        before = baseline['Services']
        preserved = all(services[name] == before[name] for name in definitions if name not in components)
        running = all(services[name]['Unit'] and services[name]['Enabled'] and services[name]['Active'] and services[name]['BinaryHash'] is not None for name in components)
        result['Code'] = 'ExistingComponentChanged' if not preserved else 'ComponentNotRunning'
        result['Allowed'] = preserved and running
        if result['Allowed']: result['Code'] = ''
    elif any(services[name]['Unit'] or services[name]['Enabled'] or services[name]['Active'] for name in components) or any(pathlib.Path(p).exists() or pathlib.Path(p).is_symlink() or any(parent.is_symlink() for parent in pathlib.Path(p).parents) for p in candidates):
        result['Code'] = 'ComponentExists'
    else:
        ports = [int(port) for port in os.environ.get('VPS_PARAM_PORTS', '').split(',') if port]
        if len(set(ports)) != len(ports) or any(not 1 <= port <= 65535 for port in ports): raise ValueError('Invalid port')
        listeners = [run('ss', '-H', '-lntup', f'sport = :{port}') for port in ports]
        if any(item.returncode != 0 for item in listeners): raise ValueError('Listener check unavailable')
        result['Allowed'] = all(not item.stdout.strip() for item in listeners)
        result['Code'] = 'PortBusy' if not result['Allowed'] else ''
    result['Services'] = services
    result['Components'] = components
    result['NftablesSha256'] = digest('/etc/nftables.conf') or ''
except (OSError, ValueError, KeyError, configparser.Error, subprocess.TimeoutExpired):
    pass
print('VPSDEPLOY_INSTALLATION_CHECK_B64=' + base64.b64encode(json.dumps(result, separators=(',', ':')).encode()).decode())
if os.environ.get('VPS_PARAM_REQUIRE_ABSENT') == 'true' and not result['Allowed']: raise SystemExit(1)
PY
