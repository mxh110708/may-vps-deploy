"""Real Linux cores in a disposable directory, with loopback TCP/UDP/TLS only.

The project installers and rollback actor run against remapped paths and mocked
service/user commands. This is NOT a real systemd, production VPS or WAN test.
--fixture-directory additionally validates configs made by the PowerShell builders.
"""
import argparse
import base64
import contextlib
import gzip
import hashlib
import http.server
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def command(args, **kwargs):
    result = subprocess.run([str(x) for x in args], text=True, capture_output=True, timeout=60, **kwargs)
    if result.returncode:
        raise AssertionError(f"command failed: {Path(str(args[0])).name}: {result.stderr[-2000:]}")
    return result.stdout


def port(family=socket.AF_INET, kind=socket.SOCK_STREAM):
    with socket.socket(family, kind) as sock:
        sock.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', 0))
        return sock.getsockname()[1]


def write_json(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')
    return path


@contextlib.contextmanager
def running(binary, config, root, listening_port):
    log = root / (config.stem + '-runtime.log')
    with log.open('w') as output:
        args = [str(binary), 'run', '-c', str(config)] if binary.name != 'mihomo' else [str(binary), '-d', str(root), '-f', str(config)]
        process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT, cwd=root)
        try:
            deadline = time.monotonic() + 8
            while True:
                if process.poll() is not None:
                    raise AssertionError('core exited: ' + log.read_text()[-2000:])
                try:
                    with socket.create_connection(('127.0.0.1', listening_port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError('core not ready: ' + log.read_text()[-2000:])
                    time.sleep(.05)
            yield
        except BaseException:
            output.flush()
            print(f'Core runtime failure ({binary.name}, {config.name}):\n{log.read_text()[-4000:]}', flush=True)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)


class HttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'MXH_LOOPBACK_OK')

    def log_message(self, *args):
        pass


class HttpServer6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def socks_http(proxy_port, target_port, ipv6=False, timeout=5):
    with socket.create_connection(('127.0.0.1', proxy_port), timeout=timeout) as sock:
        sock.sendall(b'\x05\x01\x00')
        assert sock.recv(2) == b'\x05\x00', 'SOCKS authentication failed'
        address = b'\x04' + socket.inet_pton(socket.AF_INET6, '::1') if ipv6 else b'\x01\x7f\x00\x00\x01'
        sock.sendall(b'\x05\x01\x00' + address + target_port.to_bytes(2, 'big'))
        reply = sock.recv(64)
        assert len(reply) >= 2 and reply[1] == 0, 'SOCKS connect failed'
        sock.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        response = b''
        while True:
            block = sock.recv(65536)
            if not block:
                break
            response += block
        assert b'MXH_LOOPBACK_OK' in response, f'TCP payload did not complete ({len(response)} response bytes)'


def wait_proxy_ready(proxy_port, target_port, ipv6=False):
    # Mihomo creates its listeners before provider loading, GC and OnRunning.
    # A listening socket alone can accept SOCKS and then drop external traffic.
    # Only this bounded, read-only fixture readiness probe may repeat; the actual
    # TCP/UDP upgrade and rollback acceptance below still runs without retries.
    deadline = time.monotonic() + 8
    while True:
        try:
            socks_http(proxy_port, target_port, ipv6, timeout=1)
            return
        except (OSError, AssertionError) as error:
            if time.monotonic() >= deadline:
                raise AssertionError('Mihomo loopback data plane did not become ready') from error
            time.sleep(.05)


def fetch_asset(entry, assets):
    name = entry['name']
    assert re.fullmatch(r'[A-Za-z0-9.-]+\.(?:tar\.gz|gz)', name)
    target = assets / name
    if not target.exists():
        with urllib.request.urlopen(entry['source'], timeout=120) as response, target.open('wb') as output:
            shutil.copyfileobj(response, output)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == entry['sha256'], 'release archive hash mismatch'
    return target


def unpack(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as packed:
        entries = [x for x in packed.getmembers() if x.isfile() and Path(x.name).name == 'sing-box']
        assert len(entries) == 1
        binary = destination / 'sing-box'
        with packed.extractfile(entries[0]) as source, binary.open('wb') as output:
            shutil.copyfileobj(source, output)
    binary.chmod(0o755)
    return binary


def replace_paths(value, directory):
    if isinstance(value, dict):
        result = {key: replace_paths(item, directory) for key, item in value.items()}
        for key in ('certificate_path', 'key_path'):
            if key in result:
                result[key] = str(directory / PureWindowsPath(result[key]).name)
        return result
    if isinstance(value, list):
        return [replace_paths(item, directory) for item in value]
    return value


def run_installer(root, archive, version, sha256, name='sing-box-install.sh'):
    source = (ROOT / 'assets/remote' / name).read_text()
    for prefix in ('/usr/local', '/usr/sbin', '/etc', '/var/lib', '/root'):
        source = source.replace(prefix, str(root) + prefix)
    preamble = r'''
systemctl(){ printf '%s\n' "$*" >> "$TEST_CALLS"; }
getent(){ return 0; }
id(){ return 0; }
install(){
  local args=()
  while (($#)); do case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac; done
  command install "${args[@]}"
}
curl(){ while (($#)); do if [[ "$1" == --output ]]; then cp "$TEST_ARCHIVE" "$2"; return; fi; shift; done; return 1; }
'''
    env = dict(os.environ, TEST_CALLS=str(root / 'service-calls'), TEST_ARCHIVE=str(archive),
               VPS_PARAM_VERSION=version, VPS_PARAM_ASSET_NAME=archive.name, VPS_PARAM_SHA256=sha256)
    return subprocess.run(['/bin/bash', '-s'], input=preamble + source, text=True, capture_output=True, timeout=60, env=env)


def run_program_upgrade(root, archive, version, sha256, role='ShadowsocksLanding'):
    source=(ROOT/'assets/remote/proxy-core-upgrade.sh').read_text()
    for prefix in ('/usr/local','/etc','/root'):
        source=source.replace(prefix,str(root)+prefix)
    source=source.replace('st.st_uid!=0','st.st_uid!='+str(os.getuid()))
    preamble=r'''
install(){ local args=();while (($#));do case "$1" in -o|-g) shift 2;; *) args+=("$1");shift;; esac;done;command install "${args[@]}"; }
curl(){ while (($#));do if [[ "$1" == --output ]];then cp "$TEST_ARCHIVE" "$2";return;fi;shift;done;return 1; }
'''
    env=dict(os.environ,TEST_ARCHIVE=str(archive),VPS_PARAM_ROLE=role,VPS_PARAM_VERSION=version,
             VPS_PARAM_ASSET_NAME=archive.name,VPS_PARAM_SHA256=sha256)
    return subprocess.run(['/bin/bash','-s'],input=preamble+source,text=True,capture_output=True,timeout=60,env=env)


def rollback_snapshot(root, binary, config):
    backup=root/'root/vps-deploy-backups/20000101-000000/protocol-lifecycle';backup.mkdir(parents=True)
    (backup/'components').write_text('Protocols')
    for role in ('RealityEntry','AnyTlsEntry','ShadowsocksLanding'):
        for field in ('installed','enabled','active'):
            (backup/f'{role}.{field}').write_text('true' if role=='ShadowsocksLanding' and field=='installed' else 'false')
    for field in ('enabled','active'):
        (backup/f'NginxRealityTarget.{field}').write_text('false')
    with tarfile.open(backup/'protocol-files.tar.gz','w:gz') as archive:
        archive.add(binary,arcname='usr/local/bin/sing-box')
        archive.add(config,arcname='etc/sing-box/config.json')
    return backup


def project_rollback(root,backup):
    source=(ROOT/'assets/remote/protocol-migration-arm-rollback.sh').read_text().split("<<'ROLLBACK'\n",1)[1].split('\nROLLBACK',1)[0]
    for prefix in ('/usr/local','/usr/bin','/etc','/var/lib','/var/www','/opt','/root'):
        source=source.replace(prefix,str(root)+prefix)
    source=source.replace('"/${relative:?}"','"$TEST_ROOT/${relative:?}"')
    preamble=r'''
systemctl(){ case "$1" in is-active|is-enabled) return 1;; *) return 0;; esac; }
nginx(){ return 0; }
tar(){ local args=();while (($#));do if [[ "$1" == -C && "$2" == / ]];then args+=(-C "$TEST_ROOT");shift 2;else args+=("$1");shift;fi;done;command tar "${args[@]}"; }
'''
    (root/'var/lib/may-vps-deploy').mkdir(exist_ok=True)
    env=dict(os.environ,TEST_ROOT=str(root))
    result=subprocess.run(['/bin/bash','-s','--',str(backup)],input=preamble+source,text=True,capture_output=True,timeout=30,env=env)
    assert result.returncode==0,result.stderr
    assert (backup/'rollback-executed').exists()


def anytls_fixture(binary,root):
    command(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'anytls-key.pem','-out',root/'anytls-cert.pem',
             '-subj','/CN=edge.example.invalid','-addext','subjectAltName=DNS:edge.example.invalid,DNS:www.example.invalid','-days','3'])
    ech=command([binary,'generate','ech-keypair','www.example.invalid'])
    configs=re.search(r'-----BEGIN ECH CONFIGS-----.*?-----END ECH CONFIGS-----',ech,re.S).group()
    keys=re.search(r'-----BEGIN ECH KEYS-----.*?-----END ECH KEYS-----',ech,re.S).group()
    (root/'ech-key.pem').write_text(keys+'\n')
    tls={'enabled':True,'server_name':'edge.example.invalid','min_version':'1.3','certificate_path':str(root/'anytls-cert.pem')}
    server={'inbounds':[{'type':'anytls','listen':'127.0.0.1','listen_port':port(),'users':[{'name':'primary','password':'fixture-only'}],
                        'tls':dict(tls,key_path=str(root/'anytls-key.pem'),ech={'enabled':True,'key_path':str(root/'ech-key.pem')})}],
            'outbounds':[{'type':'direct','tag':'direct'}],'route':{'final':'direct'}}
    client={'outbounds':[{'type':'anytls','tag':'anytls','server':'127.0.0.1','server_port':server['inbounds'][0]['listen_port'],
                         'password':'fixture-only','tls':dict(tls,ech={'enabled':True,'config':configs.splitlines()})}],'route':{'final':'anytls'}}
    write_json(root/'anytls-server.json',server);write_json(root/'anytls-client.json',client)


def exercise_ss(binary, root, server, client, http_port, echo_port, mihomo=None, ipv6=False):
    server_path = write_json(root / 'server-run.json', server)
    tcp_port = port(); udp_port = port(kind=socket.SOCK_DGRAM)
    client['inbounds'] = [
        {'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': tcp_port},
        {'type': 'direct', 'listen': '127.0.0.1', 'listen_port': udp_port, 'network': 'udp', 'override_address': '::1' if ipv6 else '127.0.0.1', 'override_port': echo_port}]
    client_path = write_json(root / 'client-run.json', client)
    with running(binary, server_path, root, server['inbounds'][0]['listen_port']):
        with running(binary, client_path, root, tcp_port):
            socks_http(tcp_port, http_port, ipv6)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5); sock.sendto(b'MXH_UDP_OK', ('127.0.0.1', udp_port))
                assert sock.recv(4096) == b'MXH_UDP_OK', 'SS UDP round trip failed'
        if mihomo:
            mixed = port()
            outbound = client['outbounds'][-1]
            config = {'mixed-port': mixed, 'bind-address': '127.0.0.1', 'mode': 'rule', 'log-level': 'info', 'ipv6': True,
                      'proxies': [{'name': 'fixture', 'type': 'ss', 'server': '127.0.0.1', 'port': outbound['server_port'],
                                   'cipher': outbound['method'], 'password': outbound['password'], 'udp': True}],
                      'rules': ['MATCH,fixture']}
            profile = write_json(root / 'mihomo-run.json', config)
            command([mihomo, '-t', '-d', root, '-f', profile])
            with running(mihomo, profile, root, mixed):
                wait_proxy_ready(mixed, http_port, ipv6)
                socks_http(mixed, http_port, ipv6)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--asset-directory', type=Path)
    parser.add_argument('--fixture-directory', type=Path)
    args = parser.parse_args()
    assert os.name != 'nt' and os.uname().machine in ('x86_64', 'amd64'), 'requires Linux amd64'
    catalog = json.loads((ROOT / 'config/versions.json').read_text())
    old_entry = json.loads((ROOT / 'tests/fixtures/linux-upgrade-baseline.json').read_text())
    new_entry = dict(catalog['sing_box']['assets']['amd64'])
    new_entry['source'] = f"https://github.com/SagerNet/sing-box/releases/download/v{catalog['sing_box']['version']}/{new_entry['name']}"
    mihomo_entry = dict(catalog['mihomo']['assets']['amd64'])
    mihomo_entry['source'] = f"https://github.com/MetaCubeX/mihomo/releases/download/v{catalog['mihomo']['version']}/{mihomo_entry['name']}"
    with tempfile.TemporaryDirectory(prefix='mxh-linux-upgrade-') as temporary:
        root = Path(temporary)
        assets = args.asset_directory or root / 'assets'; assets.mkdir(exist_ok=True)
        old_archive = fetch_asset(old_entry, assets); new_archive = fetch_asset(new_entry, assets)
        old_binary = unpack(old_archive, root / 'old'); new_binary = unpack(new_archive, root / 'new')
        mihomo_archive = fetch_asset(mihomo_entry, assets)
        mihomo = root / 'mihomo'
        with gzip.open(mihomo_archive, 'rb') as source, mihomo.open('wb') as output:
            shutil.copyfileobj(source, output)
        mihomo.chmod(0o755)
        assert f"sing-box version {old_entry['version']}" in command([old_binary, 'version'])
        assert f"sing-box version {catalog['sing_box']['version']}" in command([new_binary, 'version'])
        assert f"v{catalog['mihomo']['version']}" in command([mihomo, '-v'])
        for relative in ('usr/local/bin', 'etc/sing-box', 'etc/systemd/system', 'var/lib/sing-box', 'root'):
            (root / relative).mkdir(parents=True)
        if args.fixture_directory:
            for file in args.fixture_directory.iterdir():
                if file.is_file() and file.suffix in ('.json', '.pem'):
                    shutil.copy2(file, root / file.name)
            for file in root.glob('*.json'):
                write_json(file, replace_paths(json.loads(file.read_text()), root))
            server = json.loads((root / 'server.json').read_text())
        else:
            key = base64.b64encode(bytes(range(1, 17))).decode()
            server = {'inbounds': [{'type': 'shadowsocks', 'listen': '127.0.0.1', 'listen_port': port(), 'method': '2022-blake3-aes-128-gcm',
                                   'password': key, 'users': [{'name': 'ipv4-client', 'password': key},
                                    {'name': 'ipv6-client', 'password': base64.b64encode(bytes(range(17, 33))).decode()}]}],
                      'outbounds': [{'type': 'direct', 'tag': 'direct-ipv4'}, {'type': 'direct', 'tag': 'direct-ipv6', 'inet6_bind_address': '::1'}],
                      'route': {'final': 'direct-ipv4', 'rules': [
                          {'auth_user': ['ipv4-client'], 'ip_version': 6, 'action': 'reject'},
                          {'auth_user': ['ipv4-client'], 'action': 'route', 'outbound': 'direct-ipv4'},
                          {'auth_user': ['ipv6-client'], 'ip_version': 4, 'action': 'reject'},
                          {'auth_user': ['ipv6-client'], 'action': 'route', 'outbound': 'direct-ipv6'}]}}
        server['inbounds'][0]['listen'] = '127.0.0.1'; server['inbounds'][0]['listen_port'] = port()
        for outbound in server['outbounds']:
            if outbound.get('tag') == 'direct-ipv6':
                outbound['inet6_bind_address'] = '::1'; outbound.pop('bind_interface', None)
        selected = server['inbounds'][0]
        client = {'outbounds': [{'type': 'shadowsocks', 'tag': 'landing', 'server': '127.0.0.1', 'server_port': selected['listen_port'],
                                'method': selected['method'], 'password': selected['password'] + ':' + selected['users'][0]['password']}],
                  'route': {'final': 'landing'}}
        server_path = write_json(root / 'etc/sing-box/config.json', server)
        for core in (old_binary, new_binary):
            command([core, 'check', '-c', server_path])
        if args.fixture_directory:
            for file in root.glob('*-server.json'):
                command([new_binary, 'check', '-c', file])
            command([new_binary, 'check', '-c', root / 'anytls-client.json'])
        else:
            anytls_fixture(new_binary,root)
        mihomo_data=root/'mihomo-data';mihomo_data.mkdir()
        for name in ('GeoSite.dat','GeoIP.dat'):
            shutil.copy2(ROOT/'vendor/test-cores/windows-amd64/mihomo-geodata'/name,mihomo_data/name)
        command([mihomo,'-t','-d',mihomo_data,'-f',ROOT/'templates/client/clash-general.template.yaml'])
        httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), HttpHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); echo.bind(('127.0.0.1', 0)); echo.settimeout(.2)
        stopped = threading.Event()
        def echo_loop(sock):
            while not stopped.is_set():
                try:
                    data, peer = sock.recvfrom(4096); sock.sendto(data, peer)
                except socket.timeout:
                    pass
        thread = threading.Thread(target=echo_loop, args=(echo,)); thread.start()
        httpd6 = None; echo6 = None; thread6 = None
        secondary = next((user for user in selected['users'] if user.get('name') == 'ipv6-client'), None)
        if secondary:
            try:
                httpd6 = HttpServer6(('::1', 0), HttpHandler)
                echo6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); echo6.bind(('::1', 0)); echo6.settimeout(.2)
                threading.Thread(target=httpd6.serve_forever, daemon=True).start()
                thread6 = threading.Thread(target=echo_loop, args=(echo6,)); thread6.start()
            except OSError:
                if httpd6: httpd6.server_close()
                if echo6: echo6.close()
                httpd6 = None; echo6 = None
                print('SKIP: IPv6 loopback is unavailable in this environment; IPv6 acceptance is not passed')

        def exercise_both(core, mihomo_core=None):
            exercise_ss(core, root, server, client, httpd.server_port, echo.getsockname()[1], mihomo_core)
            if httpd6:
                client6 = json.loads(json.dumps(client))
                client6['outbounds'][0]['password'] = selected['password'] + ':' + secondary['password']
                exercise_ss(core, root, server, client6, httpd6.server_port, echo6.getsockname()[1], mihomo_core, ipv6=True)

        try:
            installed = root / 'usr/local/bin/sing-box'; shutil.copy2(old_binary, installed)
            snapshot=rollback_snapshot(root,installed,server_path)
            exercise_both(installed)
            before = installed.read_bytes()
            program_failed=run_program_upgrade(root,new_archive,catalog['sing_box']['version'],'0'*64)
            assert program_failed.returncode!=0 and installed.read_bytes()==before,'program upgrade bad digest replaced core'
            old_config=server_path.read_bytes();server_path.write_text('{"unsupported_qa_field":true}')
            program_bad_config=run_program_upgrade(root,new_archive,catalog['sing_box']['version'],new_entry['sha256'])
            assert program_bad_config.returncode!=0 and installed.read_bytes()==before,'incompatible config replaced core'
            server_path.write_bytes(old_config)
            program_updated=run_program_upgrade(root,new_archive,catalog['sing_box']['version'],new_entry['sha256'])
            assert program_updated.returncode==0,program_updated.stderr
            assert server_path.read_bytes()==old_config,'program upgrade rewrote configuration'
            exercise_both(installed,mihomo)
            project_rollback(root,snapshot);exercise_both(installed)
            print('PASS: real program-only core upgrade and scoped rollback; exact archive hash, configuration refusal and preserved configuration')
            failed = run_installer(root, new_archive, catalog['sing_box']['version'], '0' * 64)
            assert failed.returncode != 0 and installed.read_bytes() == before, 'bad checksum overwrote old core'
            time.sleep(1.05)  # installer backup names have one-second resolution
            result = run_installer(root, new_archive, catalog['sing_box']['version'], new_entry['sha256'])
            assert result.returncode == 0, result.stderr
            command([installed, 'check', '-c', server_path])
            assert catalog['sing_box']['version'] in command([installed, 'version'])
            exercise_both(installed, mihomo)
            backup = list((root / 'root/vps-deploy-backups').glob('*/sing-box-install/sing-box'))[-1]
            assert hashlib.sha256(backup.read_bytes()).digest() == hashlib.sha256(before).digest()
            project_rollback(root,snapshot)
            assert old_entry['version'] in command([installed,'version'])
            exercise_both(installed)
            print('PASS: real sing-box old -> new -> project rollback; TCP + UDP; bad checksum refuses replacement; Mihomo template + TCP')
            if httpd6: print('PASS: IPv6 user + explicit ::1 source binding, TCP/UDP before upgrade, after upgrade and after rollback; Mihomo IPv6 TCP')
            if (root/'anytls-server.json').exists():
                any_server = json.loads((root / 'anytls-server.json').read_text())
                any_server['inbounds'][0]['listen'] = '127.0.0.1'; any_server['inbounds'][0]['listen_port'] = port()
                any_client = json.loads((root / 'anytls-client.json').read_text())
                node = any_client['outbounds'][0]; node.update(server='127.0.0.1', server_port=any_server['inbounds'][0]['listen_port'])
                node['tls']['certificate_path'] = str(root / 'anytls-cert.pem')
                mixed = port(); any_client['inbounds'] = [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': mixed}]
                sp = write_json(root / 'anytls-runtime-server.json', any_server); cp = write_json(root / 'anytls-runtime-client.json', any_client)
                any_installed=root/'usr/local/bin/sing-box-anytls';shutil.copy2(old_binary,any_installed)
                before_any=any_installed.read_bytes()
                bad=run_installer(root,new_archive,catalog['sing_box']['version'],'0'*64,'sing-box-anytls-install.sh')
                assert bad.returncode!=0 and any_installed.read_bytes()==before_any
                time.sleep(1.05)
                upgraded=run_installer(root,new_archive,catalog['sing_box']['version'],new_entry['sha256'],'sing-box-anytls-install.sh')
                assert upgraded.returncode==0,upgraded.stderr
                command([any_installed,'check','-c',sp]);command([any_installed,'check','-c',cp])
                with running(any_installed, sp, root, any_server['inbounds'][0]['listen_port']):
                    with running(any_installed, cp, root, mixed):
                        socks_http(mixed, httpd.server_port)
                print('PASS: AnyTLS installer upgrade + verified TLS + ECH real loopback handshake')
        finally:
            stopped.set(); thread.join(timeout=2); echo.close(); httpd.shutdown(); httpd.server_close()
            if thread6: thread6.join(timeout=2)
            if echo6: echo6.close()
            if httpd6: httpd6.shutdown(); httpd6.server_close()


if __name__ == '__main__':
    main()
