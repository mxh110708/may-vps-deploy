#!/usr/bin/env python3
"""Pure bounded renderer. No network, subprocess, file write or dependency fetch."""
import copy
import hashlib
import io
import json
import sys
from urllib.parse import urlsplit
from ruamel.yaml import YAML

LIMIT = 256 * 1024

def render(document):
    parameters = document['Parameters']
    layout = document['Layout']
    known = set(layout['region_groups']) | {layout['default_exit_group'], layout['direct_group'], 'DIRECT', 'BLOCK'}
    known |= {g['name'] for g in layout['business_groups'] + layout['guard_groups']}
    outputs, dependencies = {}, []
    def reference(fmt, kind, value, local=False):
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError('Invalid dependency')
        if local:
            raise ValueError('Unbundled local dependency; use a complete inline or HTTPS template')
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Remote template dependencies must use HTTPS')
        dependencies.append({'Format': fmt, 'Kind': kind, 'Locator': parsed.hostname, 'Identity': hashlib.sha256(value.encode()).hexdigest(), 'Status': 'RemoteNotFetched'})
    yaml = YAML(typ='safe'); yaml.allow_duplicate_keys = False
    for fmt, text in document['Bases'].items():
        if not isinstance(text, str) or len(text.encode()) > LIMIT:
            raise ValueError('Oversized template')
        base = yaml.load(text) if fmt == 'Clash' else json.loads(text)
        if not isinstance(base, dict):
            raise ValueError('Template must be an object')
        base = copy.deepcopy(base)
        if fmt == 'Clash':
            clash_known = known | {'REJECT', 'REJECT-DROP'}
            if base.get('proxies') or base.get('proxy-providers'):
                raise ValueError('Template cannot contain fixed proxy nodes or subscriptions')
            if base.get('port') or base.get('socks-port') or base.get('redir-port') or base.get('tproxy-port'):
                raise ValueError('Use one explicit mixed listener; extra listeners need a separate profile')
            base.update({'mixed-port': parameters['ClashMixedPort'], 'allow-lan': parameters['AllowLan'], 'bind-address': '*' if parameters['AllowLan'] else '127.0.0.1',
                         'mode': parameters['Mode'], 'log-level': 'warning' if parameters['LogLevel'] == 'warn' else parameters['LogLevel'], 'ipv6': parameters['ClashIpv6']})
            if parameters['TunMtu']:
                base.setdefault('tun', {})['mtu'] = parameters['TunMtu']
            for group in base.get('proxy-groups', []):
                if not isinstance(group, dict) or group.get('name') not in known or any(n not in clash_known for n in group.get('proxies', [])) or group.get('use'):
                    raise ValueError('Unknown proxy group dependency')
            for rule in base.get('rules', []):
                if not isinstance(rule, str):
                    raise ValueError('Invalid rule')
                parts = rule.split(','); target = parts[-2] if parts[-1] in ('no-resolve', 'src') else parts[-1]
                if target not in clash_known:
                    raise ValueError('Unknown rule target')
                if parts[0] == 'RULE-SET' and (len(parts) < 3 or parts[1] not in base.get('rule-providers', {})):
                    raise ValueError('Unknown rule provider dependency')
            for kind, url in base.get('geox-url', {}).items(): reference(fmt, 'GeoData:' + kind, url)
            for name, provider in base.get('rule-providers', {}).items():
                if provider.get('type') == 'http': reference(fmt, 'RuleProvider:' + name, provider.get('url'))
                elif provider.get('type') != 'inline': reference(fmt, 'RuleProvider:' + name, provider.get('path'), local=True)
            stream = io.StringIO(); writer = YAML(); writer.default_flow_style = False; writer.allow_unicode = True; writer.width = 160; writer.dump(base, stream); outputs[fmt] = stream.getvalue()
        elif fmt == 'SingBox':
            outbounds = base.get('outbounds', [])
            if any(not isinstance(o, dict) or o.get('type') not in ('direct', 'block', 'selector', 'urltest') for o in outbounds):
                raise ValueError('Template cannot contain fixed protocol nodes')
            tags = known | {o.get('tag') for o in outbounds} | {s.get('tag') for s in base.get('dns', {}).get('servers', [])}
            rule_tags = {r.get('tag') for r in base.get('route', {}).get('rule_set', [])}
            listeners = base.get('inbounds', [])
            mixed = [i for i in listeners if i.get('type') == 'mixed']
            if len(mixed) != 1 or any(i.get('type') not in ('mixed', 'tun') for i in listeners):
                raise ValueError('Require one mixed listener and optional TUN')
            mixed[0]['listen_port'] = parameters['RouteMixedPort']; mixed[0]['listen'] = '0.0.0.0' if parameters['AllowLan'] else '127.0.0.1'
            base.setdefault('log', {})['level'] = parameters['LogLevel']
            base.setdefault('experimental', {}).setdefault('clash_api', {})['default_mode'] = parameters['Mode']
            if parameters['TunMtu']:
                for inbound in listeners:
                    if inbound['type'] == 'tun': inbound['mtu'] = parameters['TunMtu']
            def refs(node):
                if isinstance(node, dict):
                    for key, value in node.items():
                        if key in ('outbound', 'detour', 'download_detour', 'final', 'default') or key == 'server' and 'action' in node:
                            if isinstance(value, str) and value not in tags: raise ValueError('Unknown outbound dependency')
                        if key == 'rule_set' and isinstance(value, list) and all(isinstance(v, str) for v in value) and any(v not in rule_tags for v in value): raise ValueError('Unknown rule-set dependency')
                        if key == 'outbounds' and isinstance(value, list) and any(isinstance(v, str) and v not in tags for v in value): raise ValueError('Unknown selector dependency')
                        refs(value)
                elif isinstance(node, list):
                    for value in node: refs(value)
            refs(base)
            for rule in base.get('route', {}).get('rule_set', []):
                if rule.get('type') == 'remote': reference(fmt, 'RuleSet:' + str(rule.get('tag')), rule.get('url'))
                elif rule.get('type') != 'inline': reference(fmt, 'RuleSet:' + str(rule.get('tag')), rule.get('path'), local=True)
            outputs[fmt] = json.dumps(base, ensure_ascii=False, indent=2) + '\n'
        else:
            raise ValueError('Unknown client')
    return {'Contents': outputs, 'Hashes': {k: hashlib.sha256(v.encode()).hexdigest() for k,v in outputs.items()}, 'Dependencies': dependencies}

if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024: raise ValueError('Oversized document')
        print(json.dumps(render(json.loads(raw)), ensure_ascii=False))
    except Exception as error:
        # Parser exceptions may quote complete private YAML. Only emit a class.
        print('Template rendering/dependency validation failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
