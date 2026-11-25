"""Two actual WireGuard slots and frozen recovery, in an identified VM only."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--fixture-id', required=True)
    p.add_argument('--after-reboot', action='store_true')
    args = p.parse_args()
    if os.geteuid() != 0 or Path('/etc/may-address39-fixture').read_text().strip() != args.fixture_id or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != args.fixture_id:
        raise RuntimeError('Disposable guest identity did not match.')
    root = Path('/opt/may-address39')
    spec = importlib.util.spec_from_file_location('address39wg', root / 'scripts/instance-address.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.ADDRESS_SOURCES = {x.stem: x.read_text() for x in (root / 'scripts').glob('*.py')}
    fw = (root / 'assets/remote/firewall-tools.sh').read_text()
    m.ADDRESS_SOURCES['firewall-canonical'] = 'import re, ipaddress, subprocess\n' + fw[fw.index('def table('):fw.index('def identity(')]
    lab = Path('/root/may-address39-wg')
    lab.mkdir(mode=0o700, exist_ok=True)
    ns = 'may39-peer'
    def cmd(argv, **kw):
        r = subprocess.run(argv, capture_output=True, text=True, timeout=25, **kw)
        if r.returncode:
            raise RuntimeError('Disposable WireGuard command failed: ' + argv[0] + ' ' + r.stderr[-250:])
        return r.stdout.strip()
    def peer(argv, **kw):
        return cmd(['ip', 'netns', 'exec', ns, *argv], **kw)
    def run(action):
        env = dict(os.environ, VPS_PARAM_ADDRESS_DOCUMENT_FILE=str(lab / 'document.json'), VPS_PARAM_ADDRESS_ACTION=action, VPS_ADDRESS_PROGRAM_FILE=str(lab / 'current.py'))
        out = cmd(['python3', str(root / 'scripts/instance-address-launcher.py')], env=env)
        return json.loads(base64.b64decode(out.split('VPSDEPLOY_ADDRESS_STATE_B64=')[1].splitlines()[0]))
    cmd(['ip', 'netns', 'add', ns])
    cmd(['ip', 'link', 'add', 'may39-host', 'type', 'veth', 'peer', 'name', 'may39-peer'])
    cmd(['ip', 'link', 'set', 'may39-peer', 'netns', ns])
    cmd(['ip', 'address', 'add', '198.18.40.1/24', 'dev', 'may39-host'])
    cmd(['ip', 'link', 'set', 'may39-host', 'up'])
    peer(['ip', 'link', 'set', 'lo', 'up'])
    for addr in ['198.18.40.20', '198.18.40.21']:
        peer(['ip', 'address', 'add', addr + '/24', 'dev', 'may39-peer'])
    peer(['ip', 'link', 'set', 'may39-peer', 'up'])
    resources, peers = [], []
    mapping = {'198.18.40.20': '198.18.40.21'}
    if args.after_reboot:
        saved = json.loads((lab / 'peers.json').read_text())
        document = json.loads((lab / 'document.json').read_text())
        resources, peers = document['Resources'], saved
    else:
        for slot, kind in enumerate(['WireGuardTunnel', 'WireGuardTunnel2']):
            own_key, peer_key = cmd(['wg', 'genkey']) + '\n', cmd(['wg', 'genkey']) + '\n'
            own_pub, peer_pub = cmd(['wg', 'pubkey'], input=own_key), cmd(['wg', 'pubkey'], input=peer_key)
            c = dict(Version=1, Id=secrets.token_hex(16), Family='IPv4', Endpoint='198.18.40.20', SourceAddress='198.18.40.1', ListenPort=51880 + slot,
                     EndpointPort=51980 + slot, LocalAddress='10.239.' + str(slot) + '.1', PeerAddress='10.239.' + str(slot) + '.2',
                     Mtu=1380, KeepaliveSeconds=0, PublicKey=own_pub, PeerPublicKey=peer_pub)
            resource = dict(Kind=kind, Component=kind, ExpectedHash='0' * 64, Before=c, After=m.rewrite(c, mapping))
            a = m.Adapter(resource, Path('/'), subprocess.run, mapping)
            a.host.write(a.ns['WG_KEY'], own_key)
            for name, content in a.host.material(c).items():
                a.host.write(name, content)
            a.host.activate(c)
            resource['ExpectedHash'] = a.read()['Hash']
            resources.append(resource)
            peers.append(dict(Key=peer_key, Config=c))
        program = ('ADDRESS_SOURCES = ' + repr(m.ADDRESS_SOURCES) + '\n' + (root / 'scripts/instance-address.py').read_text()).encode()
        document = dict(Task=secrets.token_hex(16), ProgramSha256=m.sha(program), Addresses=mapping, Resources=resources)
        (lab / 'current.py').write_bytes(program)
        (lab / 'current.py').chmod(0o600)
        (lab / 'document.json').write_text(m.compact(document))
        (lab / 'peers.json').write_text(m.compact(peers))
        for name in ['document.json', 'peers.json']:
            (lab / name).chmod(0o600)
    for slot, saved in enumerate(peers):
        c, name = saved['Config'], 'peerwg' + str(slot)
        peer(['ip', 'link', 'add', name, 'type', 'wireguard'])
        configuration = '[Interface]\nPrivateKey = ' + saved['Key'].strip() + '\nListenPort = ' + str(c['EndpointPort']) + '\n[Peer]\nPublicKey = ' + c['PublicKey'] + '\nAllowedIPs = ' + c['LocalAddress'] + '/32\nEndpoint = 198.18.40.1:' + str(c['ListenPort']) + '\n'
        peer(['wg', 'setconf', name, '/dev/stdin'], input=configuration)
        peer(['ip', 'address', 'add', c['PeerAddress'] + '/32', 'dev', name])
        peer(['ip', 'link', 'set', name, 'mtu', '1380', 'up'])
        peer(['ip', 'route', 'add', c['LocalAddress'] + '/32', 'dev', name, 'src', c['PeerAddress']])
    def proofs():
        for slot, resource in enumerate(resources):
            a = m.Adapter(resource, Path('/'), subprocess.run, mapping)
            c = json.loads(Path(a.ns['WG_CONFIG']).read_text())
            nonce, port = secrets.token_hex(32), 40000 + secrets.randbelow(19000)
            server_code = m.ADDRESS_SOURCES['wireguard-runtime'].split('\nif __name__ ==', 1)[0] + '\nwg_serve(' + repr(c['PeerAddress']) + ',' + repr(c['LocalAddress']) + ',' + str(port) + ',' + repr(nonce) + ')\n'
            server = subprocess.Popen(['ip', 'netns', 'exec', ns, 'python3', '-c', server_code], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                time.sleep(.25)
                if server.poll() is not None:
                    raise RuntimeError('Disposable WireGuard challenge failed to start: ' + server.stderr.read().decode()[-200:])
                result = a.ns['wg_probe'](c, str(port), nonce)
                if not result.get('TCP') or not result.get('UDP') or not result.get('ResponseMatched'):
                    raise RuntimeError('WireGuard application response did not match.')
            finally:
                server.terminate()
                server.wait(timeout=4)
    try:
        proofs()
        if args.after_reboot:
            if not run('Status')['Consistent']:
                raise RuntimeError('WireGuard slots differ after reboot.')
            if run('Rollback')['Phase'] != 'RolledBack':
                raise RuntimeError('Frozen WireGuard restore incomplete.')
            proofs()
            print(json.dumps(dict(stage='wireguard-after-reboot', slots=2, tcpUdpProofs=4, frozenRestore=True)))
        else:
            run('Inspect')
            run('Prepare')
            run('Bridge')
            run('Apply')
            proofs()
            run('Finalize')
            if not run('Status')['Consistent']:
                raise RuntimeError('Finalized WireGuard slots differ.')
            (lab / 'current.py').write_text('# synthetic newer application version\n')
            if not run('Status')['Consistent']:
                raise RuntimeError('Frozen status failed after app source change.')
            print(json.dumps(dict(stage='wireguard-before-reboot', slots=2, tcpUdpProofs=4, endpointsChanged=True, frozenProgram=True)))
    finally:
        cmd(['ip', 'netns', 'delete', ns])


if __name__ == '__main__':
    main()
