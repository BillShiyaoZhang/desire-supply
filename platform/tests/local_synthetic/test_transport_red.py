import http.client
import json
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from desire_platform.local_synthetic import LocalSyntheticService
from desire_platform.local_synthetic.http import COOKIE_NAME, LocalSyntheticHTTPServer


class LocalSyntheticHTTPTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.service = LocalSyntheticService(
            str(Path(self.directory.name) / "local.sqlite3")
        )
        self.server = LocalSyntheticHTTPServer(("127.0.0.1", 0), self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address
        self.origin = "http://{}:{}".format(self.host, self.port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.service.close()
        self.directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        final_headers = {"Host": "{}:{}".format(self.host, self.port)}
        final_headers.update(headers or {})
        if encoded is not None:
            final_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=encoded, headers=final_headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        result = response.status, dict(response.getheaders()), payload
        connection.close()
        return result

    def test_real_http_persona_session_bootstrap_action_and_security(self):
        status, headers, personas = self.request("GET", "/v1/local/personas")
        self.assertEqual(status, 200)
        self.assertEqual(len(personas["personas"]), 7)
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, headers, session = self.request(
            "POST",
            "/v1/local/session",
            {"persona_id": "creator-chen"},
            {"Origin": self.origin},
        )
        self.assertEqual(status, 201)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertTrue(cookie.startswith(COOKIE_NAME + "="))

        status, _, bootstrap = self.request(
            "GET", "/v1/local/bootstrap", headers={"Cookie": cookie}
        )
        self.assertEqual(status, 200)
        self.assertEqual(bootstrap["allowed_operations"][0]["operation"], "accept_consent")

        payload = {
            "operation": "accept_consent",
            "expected_revision": bootstrap["revision"],
            "idempotency_key": str(uuid.uuid4()),
            "input": {"decision": "ACCEPT"},
        }
        write_headers = {
            "Cookie": cookie,
            "Origin": self.origin,
            "X-CSRF-Token": bootstrap["csrf"],
        }
        status, _, receipt = self.request(
            "POST", "/v1/local/actions", payload, write_headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(receipt["receipt"]["status"], "COMPLETED")

        status, _, forbidden = self.request(
            "POST",
            "/v1/local/actions",
            {**payload, "idempotency_key": str(uuid.uuid4()), "actor": "case-operator"},
            write_headers,
        )
        self.assertEqual((status, forbidden["code"]), (400, "FORBIDDEN_INPUT_FIELD"))
        status, _, bad_origin = self.request(
            "POST",
            "/v1/local/actions",
            payload,
            {**write_headers, "Origin": "https://attacker.invalid"},
        )
        self.assertEqual((status, bad_origin["code"]), (403, "ORIGIN_NOT_ALLOWED"))

    def test_loopback_bind_is_fail_closed(self):
        with self.assertRaises(ValueError):
            LocalSyntheticHTTPServer(("0.0.0.0", 0), self.service)


if __name__ == "__main__":
    unittest.main()
