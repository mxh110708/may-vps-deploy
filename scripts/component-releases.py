"""Read official stable release identities; no package or service mutations."""
import argparse
import base64
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORIES = {'xray': 'XTLS/Xray-core', 'sing_box': 'SagerNet/sing-box', 'komari_agent': 'komari-monitor/komari-agent', 'komari_controller': 'komari-monitor/komari', 'cloudflared': 'cloudflare/cloudflared'}


class ReleaseFailure(RuntimeError):
    pass


def asset_name(component, version):
    return {'xray': 'Xray-linux-64.zip', 'sing_box': 'sing-box-'+version+'-linux-amd64.tar.gz', 'komari_agent': 'komari-agent-linux-amd64', 'komari_controller': 'komari-linux-amd64', 'cloudflared': 'cloudflared-linux-amd64'}[component]


def parse_release(component, release):
    repository = REPOSITORIES[component]
    if release.get('draft') is not False or release.get('prerelease') is not False:
        raise ReleaseFailure('ComponentReleaseNotStable')
    tag = release.get('tag_name', '')
    version = tag[1:] if tag.startswith('v') else tag
    if len(version) > 64 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ReleaseFailure('ComponentReleaseUnsupported')
    expected = asset_name(component, version)
    assets = [item for item in release.get('assets', []) if item.get('name') == expected]
    if len(assets) != 1:
        raise ReleaseFailure('ComponentReleaseAssetMissing')
    asset = assets[0]
    url = 'https://github.com/'+repository+'/releases/download/'+tag+'/'+expected
    digest = asset.get('digest') or ''
    if asset.get('browser_download_url') != url or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest) or not isinstance(asset.get('size'), int) or not 0 < asset['size'] <= 536870912 or not isinstance(asset.get('id'), int) or asset['id'] <= 0 or not isinstance(release.get('id'), int) or release['id'] <= 0:
        raise ReleaseFailure('ComponentReleaseDigestMissing')
    return {'SchemaVersion': 1, 'Component': component, 'Repository': repository, 'Architecture': 'amd64', 'Version': version,
            'Tag': tag, 'AssetName': expected, 'Url': url, 'Sha256': digest[7:], 'Bytes': asset['size'], 'ReleaseId': release['id'],
            'AssetId': asset['id'], 'DigestSource': 'GitHubAssetDigest', 'FetchedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}


def query(component, proxy=None):
    if component not in REPOSITORIES:
        raise ReleaseFailure('ComponentReleaseUnsupported')
    url = 'https://api.github.com/repos/'+REPOSITORIES[component]+'/releases/latest'
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'may-vps-deploy-component-version-check', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        if proxy is not None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy} if proxy else {}))
        response = opener.open(request, timeout=25) if proxy is not None else urllib.request.urlopen(request, timeout=25)
        with response:
            if response.geturl() != url:
                raise ReleaseFailure('ComponentReleaseUnsupported')
            data = response.read(4194305)
            if len(data) > 4194304:
                raise ReleaseFailure('ComponentReleaseUnsupported')
    except urllib.error.HTTPError as error:
        raise ReleaseFailure('ComponentReleaseRateLimited' if error.code in (403, 429) else 'ComponentReleaseHttpFailed') from None
    except (urllib.error.URLError, TimeoutError):
        raise ReleaseFailure('ComponentReleaseNetworkFailed') from None
    return parse_release(component, json.loads(data))


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--component', default=os.environ.get('VPS_PARAM_COMPONENT', ''))
        parser.add_argument('--proxy', default=None)
        args = parser.parse_args()
        if args.proxy:
            parsed = urllib.parse.urlparse(args.proxy)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ReleaseFailure('ComponentReleaseProxyInvalid')
        result = query(args.component, args.proxy)
        print('VPSDEPLOY_COMPONENT_RELEASE_B64='+base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode())
    except Exception as error:
        code = str(error) if isinstance(error, ReleaseFailure) else 'ComponentReleaseUnsupported'
        print('VPSDEPLOY_COMPONENT_RELEASE_FAILURE_B64='+base64.b64encode(code.encode()).decode())
        raise SystemExit(1)
