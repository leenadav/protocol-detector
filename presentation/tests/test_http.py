"""Loopback HTTP contract tests; all capture data is synthetic."""
import http.client
import base64
import json
import threading
import unittest

import server
from protocol_adapters.make_sample_pcap import pcap_bytes, sample_frames


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.LocalServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_real_upload_round_trip(self):
        status, headers, body = self.request("POST", "/api/analyze", pcap_bytes(sample_frames()))
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(len(result["sessions"]), 2)
        self.assertFalse(result["meta"]["synthetic"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_decryption_upload_and_missing_keys(self):
        from poc_decryption.demo import fixture
        capture, keys, _, _ = fixture()
        self.assertEqual(self.request('POST', '/api/decrypt', b'{}')[0], 403)
        _, _, response = self.request('GET', '/api/live/interfaces')
        headers = {'X-Live-Token': json.loads(response)['token'],
                   'Content-Type': 'application/json'}
        payload = {'capture': base64.b64encode(capture).decode(), 'keylog': keys}
        status, _, response = self.request('POST', '/api/decrypt', json.dumps(payload), headers)
        self.assertEqual(status, 200)
        self.assertIn('webdav', response.decode())
        self.assertNotIn(keys, response.decode())
        payload['keylog'] = '# no matching keys'
        status, _, response = self.request('POST', '/api/decrypt', json.dumps(payload), headers)
        self.assertNotIn('webdav', response.decode())
        self.assertIn(status, (200, 400))

    def test_rejects_cross_origin_and_rebinding(self):
        for headers in ({"Origin": "https://example.com"}, {"Host": "example.com"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("POST", "/api/demo", headers=headers)[0], 403)

    def test_size_and_invalid_capture_errors(self):
        self.assertEqual(self.request("POST", "/api/analyze", headers={"Content-Length": str(server.MAX_UPLOAD + 1)})[0], 413)
        for payload in (b"", b"not a capture"):
            status, _, body = self.request("POST", "/api/analyze", payload)
            self.assertEqual(status, 400)
            self.assertIn("error", json.loads(body))

    def test_only_public_assets_are_served(self):
        self.assertEqual(self.request("GET", "/SOURCE.json")[0], 404)
        self.assertEqual(self.request("GET", "/../server.py")[0], 404)
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Protocol Observatory", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_live_controls_require_token_and_validate_interface(self):
        self.assertEqual(self.request('POST', '/api/live/start', b'{}')[0], 403)
        status, _, body = self.request('GET', '/api/live/interfaces')
        self.assertEqual(status, 200)
        token = json.loads(body)['token']
        self.assertEqual(self.request('POST', '/api/live/start', b'{"interface":"-i"}',
                                     {'X-Live-Token': token})[0], 400)
        self.assertEqual(self.request('POST', '/api/live/stop', headers={'X-Live-Token': token})[0], 200)


if __name__ == "__main__":
    unittest.main()
