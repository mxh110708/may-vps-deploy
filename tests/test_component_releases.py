"""Official release identity validation; all HTTP responses are isolated fixtures."""
import copy
import importlib.util
import pathlib
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('component_releases', ROOT/'scripts/component-releases.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def fixture(component, tag='v1.2.3'):
    asset = release.asset_name(component, tag.removeprefix('v'))
    return {'draft': False, 'prerelease': False, 'tag_name': tag, 'id': 123, 'assets': [
        {'name': asset, 'browser_download_url': 'https://github.com/'+release.REPOSITORIES[component]+'/releases/download/'+tag+'/'+asset,
         'digest': 'sha256:'+'a'*64, 'size': 1024, 'id': 456}]}


class ReleaseContracts(unittest.TestCase):
    def test_all_components_pin_exact_official_asset_and_digest(self):
        for component in release.REPOSITORIES:
            for tag in ('v1.2.3', '1.2.3'):
                candidate = release.parse_release(component, fixture(component, tag))
                self.assertEqual(candidate['Version'], '1.2.3')
                self.assertEqual(candidate['Sha256'], 'a'*64)
                self.assertEqual(candidate['DigestSource'], 'GitHubAssetDigest')
                self.assertEqual(candidate['Tag'], tag)

    def test_untrusted_prerelease_draft_and_unknown_versions_refused(self):
        for field, value in [('draft', True), ('prerelease', True), ('prerelease', None), ('tag_name', 'v1.2.3-beta.1'), ('tag_name', 'nightly')]:
            value_fixture = fixture('xray'); value_fixture[field] = value
            with self.assertRaises(release.ReleaseFailure): release.parse_release('xray', value_fixture)

    def test_missing_duplicate_digest_url_size_and_ids_refused(self):
        good = fixture('sing_box')
        for field, value in [('digest', None), ('digest', 'sha256:bad'), ('browser_download_url', 'https://example.com/program'), ('size', 0), ('size', 536870913), ('id', 0)]:
            bad = copy.deepcopy(good); bad['assets'][0][field] = value
            with self.assertRaises(release.ReleaseFailure): release.parse_release('sing_box', bad)
        for assets in ([], good['assets']*2):
            bad = copy.deepcopy(good); bad['assets'] = assets
            with self.assertRaisesRegex(release.ReleaseFailure, 'AssetMissing'): release.parse_release('sing_box', bad)

    def test_unknown_repository_cannot_make_a_network_request(self):
        with mock.patch.object(release.urllib.request, 'urlopen', side_effect=AssertionError('unexpected network')):
            with self.assertRaises(release.ReleaseFailure): release.query('arbitrary/repository')

    def test_http_and_network_errors_are_safe_and_classified(self):
        for error, code in [(urllib.error.HTTPError('https://example.com/secret', 429, 'secret', {}, None), 'ComponentReleaseRateLimited'),
                            (urllib.error.HTTPError('https://example.com/secret', 404, 'secret', {}, None), 'ComponentReleaseHttpFailed'),
                            (urllib.error.URLError('synthetic-secret'), 'ComponentReleaseNetworkFailed')]:
            with mock.patch.object(release.urllib.request, 'urlopen', side_effect=error):
                with self.assertRaisesRegex(release.ReleaseFailure, '^'+code+'$'): release.query('xray')

    def test_oversized_or_redirected_metadata_refused(self):
        url = 'https://api.github.com/repos/XTLS/Xray-core/releases/latest'
        for response_url, data in [(url, b'x'*4194305), ('https://example.com/', b'{}')]:
            response = mock.MagicMock(); response.__enter__.return_value = response
            response.geturl.return_value = response_url; response.read.return_value = data
            with mock.patch.object(release.urllib.request, 'urlopen', return_value=response):
                with self.assertRaises(release.ReleaseFailure): release.query('xray')


if __name__ == '__main__': unittest.main()
