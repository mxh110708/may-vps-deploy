"""Execute the real route probe with deterministic HTTP fixtures and no network."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import unittest
import urllib.error
from unittest.mock import patch

SOURCE = (Path(__file__).resolve().parents[1] / 'assets/remote/tunnel-public-audit.sh').read_text(encoding='utf-8').split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]

class Response:
    status = 200
    def __init__(self, body): self.body = body
    def read(self, limit): return self.body[:limit]
    def __enter__(self): return self
    def __exit__(self, *args): pass

class RouteProbeTests(unittest.TestCase):
    def run_probe(self, public=b'{"data":{"version":"1.5.1"}}', ready=True, controller=True, requests=None):
        class Opener:
            def open(self, request, timeout):
                if requests is not None: requests.append(request)
                url = request.full_url
                if '/ready' in url:
                    if not ready: raise urllib.error.URLError('refused')
                    return Response(b'')
                if '127.0.0.1' in url:
                    if not controller: raise urllib.error.URLError('refused')
                    return Response(b'{"data":{"version":"1.5.1"}}')
                if isinstance(public, Exception): raise public
                return Response(public)
        output = io.StringIO()
        with patch.dict(os.environ, {'VPS_PARAM_PUBLIC_URL': 'https://monitor.example.com', 'VPS_PARAM_CONTROLLER_PORT': '25774', 'VPS_PARAM_METRICS_PORT': '20241'}), patch('urllib.request.build_opener', return_value=Opener()), contextlib.redirect_stdout(output):
            exec(compile(SOURCE, 'tunnel-public-audit.sh', 'exec'), {})
        return json.loads(base64.b64decode(output.getvalue().strip().split('=', 1)[1]))

    def test_real_json_and_matching_version(self):
        self.assertTrue(self.run_probe()['Passed'])

    def test_connected_does_not_mean_published(self):
        value = self.run_probe(urllib.error.HTTPError('fixture', 502, 'unrouted', {}, None))
        self.assertTrue(value['ConnectorReady']); self.assertFalse(value['Passed']); self.assertEqual(value['Code'], 'HttpRejected')
        self.assertEqual(value['HttpStatus'], 502)

    def test_identifies_the_application_without_credentials(self):
        requests = []
        self.assertTrue(self.run_probe(requests=requests)['Passed'])
        self.assertEqual(len(requests), 3)
        for request in requests:
            self.assertEqual(request.get_header('User-agent'), 'May-VPS-Deploy/TunnelAccess')
            self.assertEqual(request.get_header('Accept'), 'application/json')
            self.assertIsNone(request.get_header('Authorization'))
            self.assertIsNone(request.get_header('Cookie'))

    def test_http_rejection_retains_status(self):
        value = self.run_probe(urllib.error.HTTPError('fixture', 403, 'denied', {}, None))
        self.assertEqual(value['Code'], 'HttpRejected'); self.assertEqual(value['HttpStatus'], 403)

    def test_connector_not_ready(self): self.assertEqual(self.run_probe(ready=False)['Code'], 'TunnelNotConnected')
    def test_controller_not_ready(self): self.assertEqual(self.run_probe(controller=False)['Code'], 'ControllerUnavailable')
    def test_dns_failure(self): self.assertEqual(self.run_probe(urllib.error.URLError(socket.gaierror('synthetic')))['Code'], 'DnsFailure')
    def test_tls_failure(self): self.assertEqual(self.run_probe(urllib.error.URLError(ssl.SSLError('synthetic')))['Code'], 'TlsFailure')
    def test_timeout(self): self.assertEqual(self.run_probe(urllib.error.URLError(TimeoutError()))['Code'], 'Timeout')
    def test_wrong_app_spa_and_oversized_responses(self):
        for value in (b'<html>Access login</html>', b'{}', b'[]', b'{"data": null}', b'x' * 65537):
            with self.subTest(value=value[:20]): self.assertEqual(self.run_probe(value)['Code'], 'WrongApplication')
    def test_wrong_version(self): self.assertEqual(self.run_probe(b'{"data":{"version":"1.0.0"}}')['Code'], 'VersionMismatch')
    def test_no_redirect_handler(self):
        namespace = {}
        with patch.dict(os.environ, {'VPS_PARAM_PUBLIC_URL': 'https://monitor.example.com', 'VPS_PARAM_CONTROLLER_PORT': '25774', 'VPS_PARAM_METRICS_PORT': '20241'}), patch('urllib.request.build_opener', side_effect=RuntimeError('stop before IO')):
            with self.assertRaises(RuntimeError): exec(compile(SOURCE, 'probe', 'exec'), namespace)
        self.assertIsNone(namespace['NoRedirect']().redirect_request(None, None, 302, '', {}, 'http://other.example.com'))

if __name__ == '__main__': unittest.main()
