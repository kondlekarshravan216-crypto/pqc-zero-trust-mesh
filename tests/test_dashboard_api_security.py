"""Regression tests for the local dashboard's mutating API safety controls.

Run from the repository root:
    python3 tests/test_dashboard_api_security.py
"""

import threading
import unittest
from http.server import HTTPServer
from urllib import error, request

from dashboard.server import DashboardHandler


class DashboardAPISecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def post(self, path, body=b"{}", headers=None):
        req = request.Request(
            self.base_url + path,
            data=body,
            headers=headers or {},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=3) as response:
                return response.status
        except error.HTTPError as exc:
            return exc.code

    def test_rejects_foreign_origin(self):
        status = self.post(
            "/api/unknown",
            headers={
                "Content-Type": "application/json",
                "Origin": "http://attacker.example",
            },
        )
        self.assertEqual(status, 403)

    def test_rejects_cross_site_fetch_metadata(self):
        status = self.post(
            "/api/unknown",
            headers={
                "Content-Type": "application/json",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        self.assertEqual(status, 403)

    def test_requires_json_content_type(self):
        status = self.post(
            "/api/unknown",
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 415)

    def test_rejects_oversized_request_body(self):
        status = self.post(
            "/api/unknown",
            body=b"x" * 65537,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 413)

    def test_revoke_requires_explicit_serial(self):
        status = self.post(
            "/api/vault/revoke",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)

    def test_opa_evaluator_rejects_missing_identity_destination_action(self):
        status = self.post(
            "/api/evaluate-opa",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
