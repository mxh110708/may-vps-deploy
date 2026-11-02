"""Read paired client nodes to private stdout; never modify either source."""
import argparse
import json
from pathlib import Path
from ruamel.yaml import YAML


def supported_transport(node, clash=False):
    protocol = node.get('type')
    if protocol not in ('vless', 'trojan'):
        return True
    tls = node.get('tls') if not clash else None
    if clash:
        if node.get('reality-opts'):
            return protocol == 'vless'
        if protocol == 'vless' and node.get('tls') is not True:
            return False
        transport = node.get('network')
    else:
        if not isinstance(tls, dict) or tls.get('enabled') is not True:
            return False
        if tls.get('reality', {}).get('enabled'):
            return protocol == 'vless'
        transport = node.get('transport', {}).get('type')
    return transport in (None, '', 'tcp', 'raw', 'ws', 'grpc', 'xhttp') if protocol == 'vless' else transport in (None, '', 'tcp', 'raw', 'ws', 'grpc')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--clash', type=Path)
    parser.add_argument('--sing-box', type=Path)
    args = parser.parse_args()
    if not args.clash and not args.sing_box:
        raise SystemExit('select at least one source')
    clash = (YAML(typ='safe').load(args.clash.read_text(encoding='utf-8')) or {}) if args.clash else {}
    sing = json.loads(args.sing_box.read_text(encoding='utf-8')) if args.sing_box else {}
    proxies = clash.get('proxies') or []
    outbounds = sing.get('outbounds') or []
    names = [str(n.get('name', '')) for n in proxies]
    tags = [str(n.get('tag', '')) for n in outbounds]
    if len(set(names)) != len(names) or len(set(tags)) != len(tags):
        raise SystemExit('duplicate source names')
    by_name = {str(n.get('name')): n for n in proxies}
    nodes = []
    if not args.sing_box:
        for proxy in proxies:
            if proxy.get('type') not in ('vless', 'anytls', 'ss', 'trojan', 'hysteria2', 'tuic'):
                continue
            if not supported_transport(proxy, clash=True):
                continue
            nodes.append(dict(name=str(proxy.get('name', '')), kind='landing' if proxy.get('type') == 'ss' else 'entry',
                              region_group=None, transit_group=proxy.get('dialer-proxy'), clash=proxy, sing_box=None))
    for outbound in outbounds:
        name = str(outbound.get('tag', ''))
        proxy = by_name.get(name)
        if not args.clash:
            if outbound.get('type') not in ('vless', 'anytls', 'shadowsocks', 'trojan', 'hysteria2', 'tuic'):
                continue
            if not supported_transport(outbound):
                continue
            nodes.append(dict(name=name, kind='landing' if outbound.get('type') == 'shadowsocks' else 'entry',
                              region_group=None, transit_group=outbound.get('detour'), clash=None, sing_box=outbound))
            continue
        if not proxy:
            continue
        pair = (proxy.get('type'), outbound.get('type'))
        if pair not in (('vless', 'vless'), ('anytls', 'anytls'), ('ss', 'shadowsocks'), ('trojan', 'trojan'), ('hysteria2', 'hysteria2'), ('tuic', 'tuic')):
            continue
        if not supported_transport(outbound) or not supported_transport(proxy, clash=True):
            continue
        nodes.append(dict(name=name, kind='landing' if pair[0] == 'ss' else 'entry',
                          region_group=None, transit_group=None, clash=proxy, sing_box=outbound))
    # ASCII transport avoids Windows redirected-stdout code-page differences.
    print(json.dumps(nodes, ensure_ascii=True))


if __name__ == '__main__':
    main()
