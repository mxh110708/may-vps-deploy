"""Finite checks of the pinned, already installed inbound's native outbounds.

Composed with inbound-host.py by RemoteAssets. No service or host networking
mutation: only owned loopback probe cores and private temporary configuration.
The installed policy is not replaced by this diagnostic routing configuration.
"""
import datetime
import http.client
import signal
import ssl
import secrets

POLICY_HOSTS = {'IPv4': 'api.ipify.org', 'IPv6': 'api6.ipify.org', 'Auto': 'api64.ipify.org'}
POLICY_PORT = 443


def policy_paths(model, item):
    policy = item.get('Routing', {})
    if not policy.get('Rules'):
        return []
    ids = [item['OutboundId']]
    for rule in policy['Rules']:
        if rule.get('Target') and rule['Target'] not in ids:
            ids.append(rule['Target'])
    targets = {o['Id']: o for o in model['Outbounds']}
    result = [{'Id': i, 'Tag': 'egress' if i == item['OutboundId'] else 'policy-' + i,
               'Family': targets[i]['Family'], 'ExpectedAddress': targets[i]['ExpectedAddress']} for i in ids]
    if any(r['Action'] == 'Direct' for r in policy['Rules']):
        result.append({'Id': 'Direct', 'Tag': 'policy-direct', 'Family': targets[item['OutboundId']]['Family'], 'ExpectedAddress': ''})
    return result


def validate_request(request, state):
    if not isinstance(request, dict) or set(request) != {'InboundId', 'ConfigurationSha256', 'PolicyFingerprint', 'Paths'}:
        raise ValueError('Invalid inbound policy probe request.')
    identifier = identity(request['InboundId'])
    for name in ('ConfigurationSha256', 'PolicyFingerprint'):
        if not isinstance(request[name], str) or not re.fullmatch('[a-f0-9]{64}', request[name]):
            raise ValueError('Invalid policy probe identity.')
    registry = state['Registry']
    item = next(i for i in registry['Model']['Inbounds'] if i['Id'] == identifier)
    binding = next(b for b in registry['Bindings'] if b['Id'] == identifier)
    if not item['Enabled'] or state['Runtime'][identifier] != {'Active': True, 'Enabled': True} or request['ConfigurationSha256'] != binding['Sha256']:
        raise ValueError('Installed policy is inactive or changed after review.')
    expected = policy_paths(registry['Model'], item)
    paths = request['Paths']
    if not expected or len(expected) > 9 or not isinstance(paths, list) or len(paths) != len(expected):
        raise ValueError('Policy probe paths are incomplete.')
    for actual, wanted in zip(paths, expected):
        if not isinstance(actual, dict) or set(actual) != set(wanted) | {'OutboundFingerprint'} or {k: actual[k] for k in wanted} != wanted or not re.fullmatch('[a-f0-9]{64}', actual['OutboundFingerprint']):
            raise ValueError('Policy probe differs from installed outbound references.')
    return item, selected_core(registry, identifier)


def policy_exact(stream, count):
    result = b''
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise ValueError('Incomplete SOCKS response.')
        result += chunk
    return result


def policy_query(port, hostname, timeout):
    # Fixed HTTPS IP echo services; no caller-controlled URL or shell command.
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(bytes([5, 1, 0]))
        if policy_exact(stream, 2) != bytes([5, 0]):
            raise ValueError('SOCKS negotiation failed.')
        name = hostname.encode('ascii')
        stream.sendall(bytes([5, 1, 0, 3, len(name)]) + name + POLICY_PORT.to_bytes(2, 'big'))
        header = policy_exact(stream, 4)
        if header[:3] != bytes([5, 0, 0]):
            raise ValueError('Native outbound connection failed.')
        size = 4 if header[3] == 1 else 16 if header[3] == 4 else policy_exact(stream, 1)[0] if header[3] == 3 else 0
        if not size:
            raise ValueError('Invalid SOCKS response address.')
        policy_exact(stream, size + 2)
        with ssl.create_default_context().wrap_socket(stream, server_hostname=hostname) as tls:
            connection = http.client.HTTPSConnection(hostname, POLICY_PORT, timeout=timeout)
            connection.sock = tls
            try:
                connection.request('GET', '/', headers={'Connection': 'close', 'User-Agent': 'May-Deploy-Inbound-Policy'})
                response = connection.getresponse()
                body = response.read(129)
                if response.status != 200 or len(body) > 128:
                    raise ValueError('Invalid HTTPS egress response.')
                return str(ipaddress.ip_address(body.decode('ascii').strip()))
            finally:
                connection.close()


def probe_path(binary, xray, source, path):
    # The mixed listener may reserve both transports. Check both without
    # changing any host port reservation or networking setting.
    for attempt in range(100):
        port = 20000 + secrets.randbelow(29000)
        try:
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                tcp.bind(('127.0.0.1', port));udp.bind(('127.0.0.1', port))
            break
        except OSError:
            pass
    else:
        raise ValueError('No paired loopback probe port available.')
    # Only TCP CONNECT is exercised; this does not claim application UDP proof.
    if xray:
        config = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
                  'outbounds': [source], 'routing': {'domainStrategy': 'AsIs', 'rules': [{'type': 'field', 'network': 'tcp', 'outboundTag': source['tag']}]}}
    else:
        config = {'log': {'disabled': True}, 'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
                  'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}],
                  'outbounds': [source], 'route': {'final': source['tag']}}
    with tempfile.TemporaryDirectory(prefix='may-inbound-policy-') as directory:
        filename = Path(directory) / 'probe.json'
        filename.write_text(encoded(config), encoding='utf-8')
        process = subprocess.Popen([str(binary), 'run', '-config' if xray else '-c', str(filename)], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            deadline = time.monotonic() + 6
            while True:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise ValueError('Pinned loopback probe core did not start.')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            host = POLICY_HOSTS[path['Family']]
            address = ipaddress.ip_address(policy_query(port, host, 10))
            if path['ExpectedAddress'] and address != ipaddress.ip_address(path['ExpectedAddress']) or path['Family'] != 'Auto' and address.version != (6 if path['Family'] == 'IPv6' else 4):
                raise ValueError('Native outbound egress or address family differs.')
            return {'Id': path['Id'], 'OutboundFingerprint': path['OutboundFingerprint'], 'Status': 'Passed', 'From': 'EntryServer',
                    'Scope': 'NativeOutboundHttps', 'Network': 'TCP', 'Egress': str(address)}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            process.wait(timeout=2)


def run_policy(host, request):
    before = host.read()
    item, core = validate_request(request, before)
    source_bytes = host.regular(config_path(item['Id'])).read_bytes()
    if digest(source_bytes) != request['ConfigurationSha256']:
        raise ValueError('Policy configuration changed before probing.')
    configuration = json.loads(source_bytes)
    outputs = configuration['outbounds']
    results = []
    started = time.monotonic()
    for path in request['Paths']:
        if time.monotonic() - started > 150:
            raise TimeoutError('Inbound policy probe budget exhausted.')
        matches = [o for o in outputs if o.get('tag') == path['Tag']]
        if len(matches) != 1:
            raise ValueError('Requested installed outbound is missing or ambiguous.')
        results.append(probe_path(host.regular(core_path(core)), core['Engine'] == 'xray', matches[0], path))
    if host.read()['Hash'] != before['Hash']:
        raise ValueError('Inbound resources changed during policy probes.')
    return {'InboundId': item['Id'], 'ConfigurationSha256': request['ConfigurationSha256'], 'PolicyFingerprint': request['PolicyFingerprint'],
            'Status': 'Passed', 'Items': results, 'At': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def policy_main():
    os.umask(0o077)
    def interrupted(*_):
        raise InterruptedError('Inbound policy probe interrupted.')
    for name in ('SIGTERM', 'SIGHUP', 'SIGALRM'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    if hasattr(signal, 'alarm'):
        signal.alarm(175)
    try:
        filename = Path(os.environ['VPS_PARAM_INBOUND_DOCUMENT_FILE'])
        if filename.stat().st_size > 65536:
            raise ValueError('Policy probe request exceeds its bound.')
        result = run_policy(Host(), json.loads(filename.read_text(encoding='utf-8')))
        print('VPSDEPLOY_INBOUND_POLICY_RESULT_B64=' + base64.b64encode(encoded(result).encode()).decode())
        print('VPSDEPLOY_INBOUND_POLICY_PASSED')
    except Exception:
        print('Inbound policy path verification failed; installed configuration was not changed by this probe.', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    policy_main()
