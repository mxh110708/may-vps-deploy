"""Per-identity Xray/sing-box inbounds; scoped files/services and pinned recovery.

The caller supplies the reviewed catalogue and rendered configs over the private
SSH script channel. No public API, background controller or arbitrary commands.
"""
import base64
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

DIRECTORY = '/etc/may-inbounds'
REGISTRY = DIRECTORY + '/model.json'
CORE_DIRECTORY = '/usr/local/lib/may-inbound-cores'
HEADER = '# Managed by May VPS Deploy inbound identities.\n'
JOURNAL = 'inbound-state.json'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def identity(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{32}', value):
        raise ValueError('Invalid inbound identity.')
    return value


def core_spec(value):
    fields={'Engine','Version','Artifact','Sha256'}
    if set(value) not in (fields,fields|{'Reality'}) or value['Engine'] not in ('sing-box','xray') or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['Version']) or not re.fullmatch('[a-f0-9]{64}', value['Sha256']) or value['Artifact'] != ('sing-box-' + value['Version'] + '-linux-amd64.tar.gz' if value['Engine']=='sing-box' else 'Xray-linux-64.zip'):
        raise ValueError('Invalid pinned inbound core.')
    if 'Reality' in value:
        if value['Engine']!='sing-box' or set(value['Reality'])!=fields or core_spec(value['Reality'])['Engine']!='xray': raise ValueError('Invalid Reality core identity.')
    return value


def core_path(value):
    return CORE_DIRECTORY + '/' + core_spec(value)['Sha256'] + '/' + value['Engine']


def selected_core(payload, identifier):
    item=next(i for i in payload['Model']['Inbounds'] if i['Id']==identifier)
    return payload['Core']['Reality'] if item['Protocol'] in ('Reality','VLESS') else payload['Core']


def unit_name(identifier):
    return 'may-inbound-' + identity(identifier) + '.service'


def config_path(identifier):
    return DIRECTORY + '/' + identity(identifier) + '.json'


def unit_path(identifier):
    return '/etc/systemd/system/' + unit_name(identifier)


def udp_only(item):
    return item['Protocol'] in ('Hysteria2','TuicV5') or item['Protocol']=='VLESS' and item['Options']['Transport'].get('HTTPVersion','2')=='3'


def listener_ports(item, binding):
    options = item.get('Options', {})
    if item['Protocol'] != 'Hysteria2' or 'HopPorts' not in options and 'HopIntervalSeconds' not in options:
        return [binding['Port']]
    text, interval = options.get('HopPorts'), options.get('HopIntervalSeconds')
    if not isinstance(text, str) or not 1 <= len(text) <= 1024 or len(text.split(',')) > 32 or type(interval) is not int or not 5 <= interval <= 3600:
        raise ValueError('Invalid Hysteria port hopping parameters.')
    ports = set()
    for part in text.split(','):
        match = re.fullmatch(r'([0-9]{1,5})(?:-([0-9]{1,5}))?', part)
        if not match: raise ValueError('Invalid Hysteria port range.')
        start, end = int(match[1]), int(match[2] or match[1])
        if not 1 <= start <= end <= 65535 or end-start+1 > 256: raise ValueError('Hysteria port range exceeds its bound.')
        ports.update(range(start, end+1))
        if len(ports) > 256: raise ValueError('Too many Hysteria listener ports.')
    if binding['Port'] not in ports or len(ports) < 2: raise ValueError('Hopping ports must include the owned listener and an alternative.')
    return sorted(ports)


def unit(identifier, core):
    argument='-config' if core['Engine']=='xray' else '-c'
    return HEADER + '[Unit]\nDescription=May inbound ' + identity(identifier) + '\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nLoadCredential=config.json:' + config_path(identifier) + '\nExecStart=' + core_path(core) + ' run '+argument+' %d/config.json\nRestart=on-failure\nRestartSec=3s\nDynamicUser=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nTimeoutStopSec=15s\n\n[Install]\nWantedBy=multi-user.target\n'



def validate_xhttp_extra(extra):
    ranges={'xPaddingBytes','scMaxEachPostBytes','scMinPostsIntervalMs','scStreamUpServerSecs','uplinkChunkSize'}
    switches={'noGRPCHeader','noSSEHeader','xPaddingObfsMode'}
    integers={'scMaxBufferedPosts','serverMaxHeaderBytes'}
    strings={'xPaddingKey','xPaddingHeader','xPaddingPlacement','xPaddingMethod','uplinkHTTPMethod','sessionPlacement','sessionKey','seqPlacement','seqKey','uplinkDataPlacement','uplinkDataKey'}
    def bounds(value):
        if type(value) is int: result=(value,value)
        elif isinstance(value,str) and re.fullmatch(r'\d+(?:-\d+)?',value):
            parts=value.split('-');result=(int(parts[0]),int(parts[-1]))
        elif isinstance(value,dict) and set(value)=={'from','to'} and all(type(v) is int for v in value.values()): result=(value['from'],value['to'])
        else: raise ValueError('Invalid XHTTP range.')
        if not 0<=result[0]<=result[1]<=2147483647: raise ValueError('Invalid XHTTP range bounds.')
        return result
    if not isinstance(extra,dict) or set(extra)-ranges-switches-integers-strings-{'headers','xmux'}: raise ValueError('Unknown XHTTP extra.')
    for key,value in extra.items():
        if key in ranges and bounds(value)[1]>16*1024*1024: raise ValueError('XHTTP range exceeds its resource bound.')
        if key in switches and type(value) is not bool: raise ValueError('Invalid XHTTP switch.')
        if key in integers and (type(value) is not int or value<0): raise ValueError('Invalid XHTTP server limit.')
        if key in strings and (not isinstance(value,str) or any(ord(c)<32 for c in value)): raise ValueError('Invalid XHTTP text.')
        if key=='headers':
            if not isinstance(value,dict) or len(value)>64 or len({k.lower() for k in value})!=len(value): raise ValueError('Invalid XHTTP headers.')
            for k,v in value.items():
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",k) or k.lower() in ('host','content-length','transfer-encoding','connection') or not isinstance(v,str) or any(c in v for c in '\r\n\x00'): raise ValueError('Unsafe XHTTP header.')
        if key=='xmux':
            fields={'maxConcurrency','maxConnections','cMaxReuseTimes','hMaxRequestTimes','hMaxReusableSecs','hKeepAlivePeriod'}
            if not isinstance(value,dict) or set(value)-fields: raise ValueError('Invalid XHTTP XMux.')
            for k,v in value.items():
                if k=='hKeepAlivePeriod':
                    if type(v) is not int: raise ValueError('Invalid XMux keepalive.')
                else: bounds(v)
            if bounds(value.get('maxConcurrency',0))[1]>0 and bounds(value.get('maxConnections',0))[1]>0: raise ValueError('Conflicting XMux limits.')


def validate_xhttp(model, item, source):
    outbound = [o for o in model['Outbounds'] if o['Id'] == item['OutboundId']]
    if len(outbound) != 1 or outbound[0].get('Kind') != 'Direct':
        raise ValueError('Bounded XHTTP requires a direct server outbound.')
    options = item['Options']; transport = options.get('Transport', {})
    if set(options) != {'ServerName','Security','Transport','Reality'} or not {'Type','Path','Host','Mode'} <= set(transport) or set(transport)-{'Type','Path','Host','Mode','HTTPVersion','Extra'} or transport['Type']!='XHTTP' or transport['Mode'] not in ('auto','stream-one','stream-up','packet-up') or not isinstance(transport['Path'],str) or len(transport['Path'])>8192 or any(ord(c)<32 for c in transport['Path']):
        raise ValueError('Unsupported XHTTP model.')
    version=transport.get('HTTPVersion','2')
    validate_xhttp_extra(transport.get('Extra',{}))
    if version not in ('1.1','2','3') or options['Security']=='Reality' and version!='2':
        raise ValueError('XHTTP HTTP version is incompatible with transport security.')
    expected={'path':transport['Path'],'host':transport['Host'],'mode':transport['Mode']}
    if transport.get('Extra'): expected['extra']=transport['Extra']
    stream=source.get('streamSettings',{}); security=options['Security']
    if security not in ('TLS','Reality') or set(stream)!={'network','security','xhttpSettings','tlsSettings' if security=='TLS' else 'realitySettings'} or stream['network']!='xhttp' or stream['security']!=security.lower() or stream['xhttpSettings']!=expected:
        raise ValueError('XHTTP protocol, transport or security differs.')
    settings=source.get('settings',{})
    if set(settings)!={'clients','decryption'} or settings['decryption']!='none' or sorted(c.get('email','') for c in settings['clients'])!=sorted(item['UserIds']) or any(set(c)!={'id','email'} or not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',c['id']) for c in settings['clients']):
        raise ValueError('XHTTP users or flow differ.')
    if security=='TLS':
        tls=stream['tlsSettings']
        if options['Reality']!={} or not item['CertificateId'] or set(tls)!={'serverName','minVersion','maxVersion','alpn','certificates'} or tls['serverName']!=options['ServerName'] or tls['minVersion']!='1.3' or tls['maxVersion']!='1.3' or tls['alpn']!=[{'1.1':'http/1.1','2':'h2','3':'h3'}[version]] or not isinstance(tls['certificates'],list) or len(tls['certificates'])!=1 or set(tls['certificates'][0])!={'certificate','key'}:
            raise ValueError('XHTTP TLS must retain inline identity and h2.')
    else:
        r=options['Reality']; actual=stream['realitySettings']
        if item['CertificateId'] or set(r)!={'HandshakeServer','HandshakePort','PublicKey','ShortId'} or set(actual)!={'show','target','xver','serverNames','privateKey','shortIds'} or actual['show'] is not False or actual['xver']!=0 or actual['serverNames']!=[options['ServerName']] or actual['target']!=r['HandshakeServer']+':'+str(r['HandshakePort']) or actual['shortIds']!=[r['ShortId']] or not re.fullmatch('[A-Za-z0-9_-]{43}',actual['privateKey']):
            raise ValueError('XHTTP Reality identity differs.')


def normalize(payload):
    if set(payload) != {'Version', 'Model', 'Bindings', 'Configurations', 'Core'} or type(payload['Version']) is not int or payload['Version'] != 1:
        raise ValueError('Unsupported inbound payload.')
    core_spec(payload['Core'])
    model = payload['Model']
    if set(model) != {'Version', 'Inbounds', 'Users', 'Certificates', 'Outbounds'} or model['Version'] != 1 or not all(isinstance(model[g], list) for g in ('Inbounds', 'Users', 'Certificates', 'Outbounds')) or len(model['Inbounds']) > 16:
        raise ValueError('Unsupported inbound model.')
    ids = [identity(i['Id']) for i in model['Inbounds']]
    if len(set(ids)) != len(ids) or set(payload['Configurations']) != set(ids) or len(payload['Bindings']) != len(ids):
        raise ValueError('Inbound bindings are incomplete or duplicated.')
    seen, ports = set(), set()
    for binding in payload['Bindings']:
        if set(binding) != {'Id', 'Enabled', 'Sha256', 'ClientSha256', 'Port', 'Address', 'Udp'} or not re.fullmatch('[a-f0-9]{64}',binding.get('ClientSha256','')):
            raise ValueError('Unsupported inbound binding.')
        identifier = identity(binding['Id'])
        if identifier not in ids or identifier in seen or type(binding['Enabled']) is not bool or type(binding['Udp']) is not bool or type(binding['Port']) is not int or not 1 <= binding['Port'] <= 65535 or binding['Port'] in ports:
            raise ValueError('Invalid or duplicate inbound listener.')
        seen.add(identifier); ports.add(binding['Port'])
        ipaddress.ip_address(binding['Address'])
        data = base64.b64decode(payload['Configurations'][identifier], validate=True)
        if len(data) > 1048576 or digest(data) != binding['Sha256']:
            raise ValueError('Rendered configuration hash does not match.')
        config = json.loads(data); item = next(i for i in model['Inbounds'] if i['Id'] == identifier); reality=item['Protocol'] in ('Reality','VLESS')
        hops = listener_ports(item, binding)
        if ports.intersection(p for p in hops if p != binding['Port']): raise ValueError('Hysteria port range overlaps another inbound.')
        ports.update(hops)
        if set(config) != ({'log','inbounds','outbounds','routing'} if reality else {'log', 'dns', 'inbounds', 'outbounds', 'route'}) or len(config['inbounds']) != 1:
            raise ValueError('Only one independently scoped inbound is supported per service.')
        source = config['inbounds'][0]
        if item['Protocol'] not in ('Reality', 'AnyTLS', 'Shadowsocks2022','Hysteria2','TuicV5','VLESS') or source.get('protocol' if reality else 'type') != {'Reality':'vless','VLESS':'vless','AnyTLS':'anytls','Shadowsocks2022':'shadowsocks','Hysteria2':'hysteria2','TuicV5':'tuic'}[item['Protocol']] or source.get('tag') != identifier or source.get('listen') != binding['Address'] or source.get('port' if reality else 'listen_port') != binding['Port'] or item['Enabled'] != binding['Enabled'] or binding['Udp'] != (item['Protocol'] in ('Shadowsocks2022','Hysteria2','TuicV5') or item['Protocol']=='VLESS' and item['Options']['Transport'].get('HTTPVersion','2')=='3'):
            raise ValueError('Rendered inbound differs from the catalogue.')
        if item['Protocol']=='VLESS': validate_xhttp(model, item, source)
        if reality and ('Reality' not in payload['Core'] or selected_core(payload,identifier)['Engine']!='xray'): raise ValueError('Reality requires its pinned Xray core.')
    return payload


def material(payload):
    registry = {k: payload[k] for k in ('Version', 'Model', 'Bindings', 'Core')}
    result = {REGISTRY: (encoded(registry) + '\n').encode()}
    for binding in payload['Bindings']:
        identifier = binding['Id']
        result[config_path(identifier)] = base64.b64decode(payload['Configurations'][identifier])
        result[unit_path(identifier)] = unit(identifier, selected_core(payload,identifier)).encode()
    return result


class Host:
    def __init__(self, root=Path('/'), run=subprocess.run, download=None):
        self.root, self.run, self.download = root, run, download

    def path(self, absolute):
        logical = str(absolute)
        if not logical.startswith('/') or logical.startswith('//') or '\\' in logical or '..' in logical.split('/'):
            raise ValueError('Inbound path is not an absolute scoped POSIX path.')
        return self.root.joinpath(*PurePosixPath(logical).parts[1:])

    def regular(self, absolute, missing=False):
        path = self.path(absolute)
        for parent in [path, *path.parents]:
            if parent.is_symlink(): raise ValueError('Linked inbound resource path.')
        if path.exists() and not path.is_file() or not missing and not path.exists():
            raise ValueError('Inbound resource is absent or not a regular file.')
        return path

    def command(self, args, check=True):
        result = self.run(args, capture_output=True, text=True, timeout=45)
        if check and result.returncode: raise ValueError('Inbound service operation failed.')
        return result

    def state(self, identifier):
        name = unit_name(identifier)
        return {'Enabled': self.command(['systemctl','is-enabled','--quiet',name],False).returncode == 0,
                'Active': self.command(['systemctl','is-active','--quiet',name],False).returncode == 0}

    def owned_files(self):
        files = []
        directory = self.path(DIRECTORY)
        if directory.exists():
            self.regular(REGISTRY, True)
            for path in directory.iterdir():
                absolute = '/' + path.relative_to(self.root).as_posix()
                if path.name != 'model.json' and not re.fullmatch('[a-f0-9]{32}\\.json',path.name): raise ValueError('Unknown inbound configuration file.')
                self.regular(absolute); files.append(absolute)
        for path in self.path('/etc/systemd/system').glob('may-inbound-*'):
            if not re.fullmatch('may-inbound-[a-f0-9]{32}\\.service',path.name): raise ValueError('Unknown inbound unit or override.')
            absolute = '/' + path.relative_to(self.root).as_posix(); self.regular(absolute); files.append(absolute)
        for directory in ('/run/systemd/system','/usr/lib/systemd/system','/lib/systemd/system'):
            if any(self.path(directory).glob('may-inbound-*')): raise ValueError('Unmanaged inbound unit occupies the namespace.')
        return sorted(files)

    def verify_core(self, core):
        path = core_path(core); metadata = json.loads(self.regular(str(PurePosixPath(path).parent) + '/core.json').read_text())
        if metadata.get('Managed') != 'MayInboundCore.v1' or metadata.get('ArchiveSha256') != core['Sha256'] or metadata.get('Version') != core['Version'] or digest(self.regular(path).read_bytes()) != metadata.get('BinarySha256'):
            raise ValueError('Pinned inbound core differs from its installation record.')

    def read(self):
        files = self.owned_files()
        if REGISTRY not in files:
            if files: raise ValueError('Unmanaged inbound files exist without their catalogue.')
            return {'Hash':'Absent','Registry':None,'Files':{},'Runtime':{}}
        data = json.loads(self.regular(REGISTRY).read_text())
        if set(data) != {'Version','Model','Bindings','Core'} or data['Version'] != 1: raise ValueError('Unsupported saved inbound catalogue.')
        payload = dict(data, Configurations={b['Id']:base64.b64encode(self.regular(config_path(b['Id'])).read_bytes()).decode() for b in data['Bindings']})
        normalize(payload); expected = material(payload)
        if set(files) != set(expected): raise ValueError('Unknown or missing inbound files.')
        for name, content in expected.items():
            if self.regular(name).read_bytes() != content: raise ValueError('Inbound resources changed externally.')
        verified=set()
        for binding in data['Bindings']:
            core=selected_core(payload,binding['Id'])
            if core['Sha256'] not in verified: self.verify_core(core); verified.add(core['Sha256'])
        runtime = {}
        for binding in data['Bindings']:
            identifier = binding['Id']; name = unit_name(identifier)
            if self.command(['systemctl','show',name,'-p','FragmentPath','--value']).stdout.strip() != unit_path(identifier) or self.command(['systemctl','show',name,'-p','DropInPaths','--value']).stdout.strip():
                raise ValueError('Inbound unit identity or overrides differ.')
            runtime[identifier] = self.state(identifier)
        hashes = {p:digest(self.regular(p).read_bytes()) for p in files}
        return {'Hash':digest(encoded(hashes)),'Registry':data,'Files':hashes,'Runtime':runtime}

    def preflight(self, payload, affected):
        normalize(payload); before = self.read(); affected = sorted(identity(i) for i in affected)
        if len(affected) != len(set(affected)): raise ValueError('Duplicate recovery scope.')
        old = {b['Id']:b for b in (before['Registry'] or {}).get('Bindings',[])}; new = {b['Id']:b for b in payload['Bindings']}
        required = {i for i in set(old)|set(new) if old.get(i) != new.get(i) or i in new and before['Runtime'].get(i) != {'Enabled':new[i]['Enabled'],'Active':new[i]['Enabled']}}
        if before['Registry']:
            for i in set(old)&set(new):
                if selected_core(before['Registry'],i)['Sha256']!=selected_core(payload,i)['Sha256']: required.add(i)
        if set(affected) != required: raise ValueError('Affected inbound scope changed after review; read status and review again.')
        local = json.loads(self.command(['ip','-j','address','show']).stdout)
        addresses = {a['local'] for item in local for a in item.get('addr_info',[])}
        for b in payload['Bindings']:
            if not b['Enabled']: continue
            address = ipaddress.ip_address(b['Address'])
            if not address.is_unspecified and str(address) not in addresses: raise ValueError('Inbound address is not assigned to this host.')
            item=next(i for i in payload['Model']['Inbounds'] if i['Id']==b['Id']); protocol=item['Protocol']
            owned_active=b['Id'] in old and old[b['Id']]['Port'] == b['Port'] and old[b['Id']]['Address'] == b['Address'] and before['Runtime'][b['Id']]['Active']
            for transport in ([socket.SOCK_DGRAM] if udp_only(item) else [socket.SOCK_STREAM] + ([socket.SOCK_DGRAM] if b['Udp'] else [])):
                for port in listener_ports(item,b):
                    if owned_active and port==b['Port']: continue
                    with socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, transport) as listener:
                        if transport == socket.SOCK_STREAM: listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                        listener.bind((str(address),port))
        return before

    def write(self, absolute, data, mode=0o600):
        path = self.regular(absolute,True); path.parent.mkdir(parents=True,exist_ok=True)
        temporary = path.with_name(path.name + '.may-new')
        with temporary.open('xb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary,mode); os.replace(temporary,path)

    def journal(self, backup):
        if not re.fullmatch('/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle',str(backup)): raise ValueError('Invalid inbound snapshot path.')
        value = json.loads(self.regular(str(backup)+'/'+JOURNAL).read_text())
        if value.get('Version') != 1: raise ValueError('Unsupported inbound snapshot.')
        for i in value['Affected']: identity(i)
        if len(value['Affected'])!=len(set(value['Affected'])) or set(value['OriginalRuntime'])-set(value['Affected']): raise ValueError('Inbound snapshot service state exceeds its recovery scope.')
        for state in value['OriginalRuntime'].values():
            if set(state)!={'Enabled','Active'} or any(type(flag) is not bool for flag in state.values()): raise ValueError('Invalid inbound snapshot service state.')
        allowed = {REGISTRY}|{p for i in value['Affected'] for p in (config_path(i),unit_path(i))}
        for group in ('Original','Applied'):
            for name in value.get(group,{}):
                if name.removesuffix('.may-new') not in allowed: raise ValueError('Inbound snapshot exceeds its recovery scope.')
        return value

    def save_journal(self, backup, value):
        self.write(str(backup)+'/'+JOURNAL,(encoded(value)+'\n').encode())

    def paths(self, affected):
        allowed = {REGISTRY}|{p for i in affected for p in (config_path(i),unit_path(i))}
        return [p for p in self.read()['Files'] if p in allowed]

    def snapshot(self, backup, expected, payload, affected):
        before = self.preflight(payload,affected)
        if before['Hash'] != expected: raise ValueError('Inbound resources changed before snapshot.')
        paths = self.paths(affected)
        self.save_journal(backup,{'Version':1,'Affected':affected,'Original':{p:before['Files'][p] for p in paths},'OriginalRuntime':{i:before['Runtime'][i] for i in affected if i in before['Runtime']},'OriginalHash':before['Hash'],'BeforeFiles':before['Files']})

    def ensure_core(self, core):
        core_spec(core); destination = self.path(str(PurePosixPath(core_path(core)).parent))
        if destination.exists(): self.verify_core(core); return
        self.regular(str(PurePosixPath(core_path(core)).parent)+'/core.json',True)
        destination.parent.mkdir(parents=True,exist_ok=True)
        os.chmod(destination.parent,0o755)
        stage = Path(tempfile.mkdtemp(prefix='.stage-',dir=destination.parent))
        try:
            if self.download: content = self.download(core)
            else:
                repository='XTLS/Xray-core' if core['Engine']=='xray' else 'SagerNet/sing-box'
                url = 'https://github.com/'+repository+'/releases/download/v' + core['Version'] + '/' + core['Artifact']
                with urllib.request.urlopen(url,timeout=90) as response:
                    if not response.url.startswith('https://'): raise ValueError('Non-HTTPS core redirect refused.')
                    content = response.read(134217729)
            if len(content)>134217728 or digest(content)!=core['Sha256']: raise ValueError('Official inbound core archive checksum mismatch.')
            if core['Engine']=='xray':
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    matches=[m for m in archive.infolist() if not m.is_dir() and m.filename=='xray']
                    if len(matches)!=1 or matches[0].file_size>134217728: raise ValueError('Xray archive executable is ambiguous.')
                    binary=archive.read(matches[0])
            else:
                with tarfile.open(fileobj=io.BytesIO(content),mode='r:gz') as archive:
                    matches=[m for m in archive.getmembers() if m.isfile() and Path(m.name).name=='sing-box']
                    if len(matches)!=1 or matches[0].size>134217728: raise ValueError('Core archive executable is ambiguous.')
                    binary=archive.extractfile(matches[0]).read()
            (stage/core['Engine']).write_bytes(binary); os.chmod(stage/core['Engine'],0o755)
            (stage/'core.json').write_text(encoded({'Managed':'MayInboundCore.v1','Version':core['Version'],'ArchiveSha256':core['Sha256'],'BinarySha256':digest(binary)}))
            os.chmod(stage/'core.json',0o644); os.chmod(stage,0o755)
            os.rename(stage,destination); self.verify_core(core)
        finally:
            if stage.exists(): shutil.rmtree(stage)

    def apply(self, backup, payload, expected, affected):
        before=self.preflight(payload,affected)
        if before['Hash']!=expected: raise ValueError('Inbound resources changed after review.')
        journal=self.journal(backup)
        if journal['BeforeFiles']!=before['Files'] or journal['Affected']!=affected: raise ValueError('Inbound snapshot no longer matches this write.')
        needed={selected_core(payload,i)['Sha256']:selected_core(payload,i) for i in affected if any(b['Id']==i for b in payload['Bindings'])}
        for core in needed.values(): self.ensure_core(core)
        files=material(payload)
        # Check each changed config before stopping any existing service.
        for identifier in affected:
            if config_path(identifier) not in files: continue
            with tempfile.NamedTemporaryFile(mode='wb',prefix='may-inbound-check-',suffix='.json') as candidate:
                os.chmod(candidate.name,0o600); candidate.write(files[config_path(identifier)]); candidate.flush()
                core=selected_core(payload,identifier)
                arguments=['run','-test','-config',candidate.name] if core['Engine']=='xray' else ['check','-c',candidate.name]
                self.command([str(self.path(core_path(core))),*arguments])
        paths={REGISTRY}|{p for i in affected for p in (config_path(i),unit_path(i))}
        journal['Applied']={p:digest(files[p]) if p in files else None for p in paths}
        journal['Applied'].update({p+'.may-new':digest(files[p]) for p in paths if p in files}); self.save_journal(backup,journal)
        for identifier in affected:
            self.command(['systemctl','disable','--now',unit_name(identifier)],False)
            if self.state(identifier)['Active']: raise ValueError('Inbound service did not stop.')
        for path in paths:
            if path in files: self.write(path,files[path],0o644 if path.endswith('.service') else 0o600)
            elif self.regular(path,True).exists(): self.regular(path).unlink()
        self.command(['systemctl','daemon-reload'])
        for binding in payload['Bindings']:
            if binding['Id'] in affected and binding['Enabled']:
                self.command(['systemctl','enable','--now',unit_name(binding['Id'])])
                self.wait_ready(binding)
        return self.read()

    def wait_ready(self, binding):
        model=json.loads(self.regular(REGISTRY).read_text())['Model']
        quic=udp_only(next(i for i in model['Inbounds'] if i['Id']==binding['Id']))
        address=ipaddress.ip_address(binding['Address'])
        host=('127.0.0.1' if address.version==4 else '::1') if address.is_unspecified else str(address)
        for _ in range(60):
            if self.state(binding['Id'])['Active']:
                if quic:
                    pid=self.command(['systemctl','show',unit_name(binding['Id']),'-p','MainPID','--value']).stdout.strip()
                    if re.fullmatch('[1-9][0-9]*',pid):
                        for line in self.command(['ss','-H','-lunp']).stdout.splitlines():
                            columns=line.split()
                            if len(columns)<5 or 'pid='+pid+',' not in line: continue
                            address_text,separator,port=columns[3].rpartition(':')
                            if separator and port==str(binding['Port']) and (address_text.strip('[]')==str(address) or address.is_unspecified and address_text in ('*','0.0.0.0','[::]','::')): return
                    time.sleep(0.1); continue
                try:
                    with socket.create_connection((host,binding['Port']),timeout=0.2): return
                except OSError: pass
            time.sleep(0.1)
        raise ValueError('Inbound did not expose its owned UDP listener after activation.' if quic else 'Inbound did not expose its TCP listener after activation.')

    def rollback_check(self, backup):
        journal=self.journal(backup); paths=set(journal['Original'])|set(journal.get('Applied',{}))
        known=set(journal['BeforeFiles'])|paths
        # Do this before stopping services or restoring the shared catalogue.
        # A new unrelated identity/override must not be hidden by recovery.
        for directory, pattern in ((DIRECTORY,'*'),('/etc/systemd/system','may-inbound-*'),('/run/systemd/system','may-inbound-*'),('/usr/lib/systemd/system','may-inbound-*'),('/lib/systemd/system','may-inbound-*')):
            for entry in self.path(directory).glob(pattern):
                logical='/'+entry.relative_to(self.root).as_posix()
                if logical not in known: raise ValueError('Unknown inbound resource appeared; recovery refused before writes.')
                self.regular(logical)
        for path, expected in journal['BeforeFiles'].items():
            if path not in paths and (not self.regular(path,True).exists() or digest(self.regular(path).read_bytes())!=expected): raise ValueError('An unrelated inbound changed; recovery will not overwrite it.')
        for path in paths:
            current=digest(self.regular(path).read_bytes()) if self.regular(path,True).exists() else None
            if current not in (journal['Original'].get(path),journal.get('Applied',{}).get(path)) and not (current is None and journal.get('Recovering')): raise ValueError('Inbound resource changed externally; recovery refused.')
        with tarfile.open(self.regular(str(backup)+'/protocol-files.tar.gz')) as archive:
            for member in archive.getmembers():
                if member.name.startswith(('etc/may-inbounds/','etc/systemd/system/may-inbound-')) and ('/'+member.name not in journal['Original'] or not member.isfile()): raise ValueError('Archive inbound member exceeds reviewed recovery scope.')
            for path, expected in journal['Original'].items():
                matches=[m for m in archive.getmembers() if m.name==path.lstrip('/')]
                if len(matches)!=1 or not matches[0].isfile() or digest(archive.extractfile(matches[0]).read())!=expected: raise ValueError('Inbound recovery archive differs from its snapshot.')
        return journal,paths

    def rollback_prepare(self, backup):
        journal,paths=self.rollback_check(backup); journal['Recovering']=True; self.save_journal(backup,journal)
        for identifier in journal['Affected']:
            self.command(['systemctl','disable','--now',unit_name(identifier)],False)
            if self.state(identifier)['Active']: raise ValueError('Inbound did not stop for scoped recovery.')
        for path in paths:
            if self.regular(path,True).exists(): self.regular(path).unlink()

    def rollback_complete(self, backup):
        journal=self.journal(backup); self.command(['systemctl','daemon-reload'])
        for identifier,state in journal['OriginalRuntime'].items():
            self.command(['systemctl','enable' if state['Enabled'] else 'disable',unit_name(identifier)])
            if state['Active']: self.command(['systemctl','start',unit_name(identifier)])
        observed=self.read()
        if observed['Hash']!=journal['OriginalHash']: raise ValueError('Scoped inbound recovery did not restore its prior resources.')
        journal['Recovering']=False; self.save_journal(backup,journal)


def main():
    host=Host(); action=sys.argv[1]
    if action in ('read','verify','preflight','snapshot','paths','apply'):
        payload=None; affected=[]
        if os.environ.get('VPS_PARAM_INBOUND_DOCUMENT_FILE'):
            payload=normalize(json.loads(Path(os.environ['VPS_PARAM_INBOUND_DOCUMENT_FILE']).read_text()))
            affected=json.loads(os.environ.get('VPS_PARAM_INBOUND_AFFECTED','[]'))
        if action=='verify':
            if host.read()['Hash']!=os.environ['VPS_PARAM_INBOUND_EXPECTED_HASH']: raise ValueError('Inbound archive hash changed.')
        elif action=='read':
            result=host.read(); print('VPSDEPLOY_INBOUND_STATE_B64='+base64.b64encode(encoded(result).encode()).decode())
        elif action=='preflight': host.preflight(payload,affected)
        elif action=='paths': print('\n'.join(p.lstrip('/') for p in host.paths(affected)))
        elif action=='snapshot': host.snapshot(PurePosixPath(sys.argv[2]),os.environ['VPS_PARAM_INBOUND_EXPECTED_HASH'],payload,affected)
        elif action=='apply': host.apply(PurePosixPath(os.environ['VPS_PARAM_EXPECTED_TRANSACTION']),payload,os.environ['VPS_PARAM_INBOUND_EXPECTED_HASH'],affected)
    elif action=='rollback-check': host.rollback_check(PurePosixPath(sys.argv[2]))
    elif action=='rollback-prepare': host.rollback_prepare(PurePosixPath(sys.argv[2]))
    elif action=='rollback-complete': host.rollback_complete(PurePosixPath(sys.argv[2]))
    else: raise ValueError('Unknown inbound operation.')


if __name__=='__main__':
    main()
