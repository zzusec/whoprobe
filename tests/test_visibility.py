import argparse
import http.client
import json
import re
import threading
import unittest
from email.message import Message
from unittest.mock import patch

import probe
import visibility


class VisibilityFieldsTest(unittest.TestCase):
    def test_only_allowlisted_values_and_origin_only_referrer(self):
        headers = Message()
        headers.add_header("Cookie", "private-cookie")
        headers.add_header("Authorization", "private-authorization")
        headers.add_header("If-None-Match", "private-etag")
        headers.add_header("X-Custom-Header", "private-custom")
        headers.add_header("User-Agent", "sample-browser")
        headers.add_header("Referer", "https://from.example:8443/private-path?private=code")
        result = visibility.request_record(headers, method="GET", path="/", query="private=code&empty=", scheme="https")
        self.assertTrue(result["cookiePresent"])
        self.assertTrue(result["authHeadersPresent"])
        self.assertEqual(result["queryFieldCount"], 2)
        shown = {x["name"]: x["value"] for x in result["headers"]}
        self.assertEqual(shown["Referer"], "https://from.example:8443")
        self.assertEqual(shown["User-Agent"], "sample-browser")
        for name in ("Cookie", "Authorization", "If-None-Match", "X-Custom-Header"):
            self.assertIsNone(shown[name])
        self.assertNotIn("private-", str(result))

    def test_endpoint_configuration_and_exact_cors(self):
        parser = argparse.ArgumentParser()
        visibility.add_arguments(parser)
        args = parser.parse_args(["--visibility-origin", "https://main.example",
                                  "--visibility-ipv6-url", "https://ipv6.example/who/api/who/visibility/sample"])
        cfg = visibility.Settings.from_args(args)
        self.assertEqual(cfg.routes["ipv6"], "https://ipv6.example/who/api/who/visibility/sample")
        self.assertEqual(cfg.cors("https://main.example")["Access-Control-Allow-Origin"], "https://main.example")
        self.assertFalse(cfg.cors("https://shadow.main.example"))
        with self.assertRaises(ValueError):
            visibility.Settings.from_args(parser.parse_args(["--visibility-h3-url", "https://user@wrong.example/api/who/visibility/sample"]))
        with self.assertRaises(ValueError):
            visibility.Settings.from_args(parser.parse_args(["--visibility-ipv4-url", "http://unencrypted.example/api/who/visibility/sample"]))


class VisibilityHttpTest(unittest.TestCase):
    def setUp(self):
        self.server = probe.ThreadingHTTPServer(("127.0.0.1", 0), probe.WhoProbeHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.settings = visibility.Settings(origins=frozenset({"https://main.example"}))
        self.view = visibility.View(self.settings)
        self.patch = patch.object(probe, "VISIBILITY_VIEW", self.view)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    @staticmethod
    def embedded(data):
        match = re.search(rb'<script type="application/json" id="whoNavigationReceipt">(.*?)</script>', data)
        if not match:
            raise AssertionError("missing navigation receipt")
        return json.loads(match.group(1))

    def test_actual_navigation_is_embedded_private_and_html_safe(self):
        unusual = "browser </script><svg onload=bad>"
        for path in ("/", "/who/"):
            status, headers, data = self.request("GET", path + "?k=private-query-value", {
                "Cookie": "receipt_probe=private-cookie-value", "Authorization": "Basic private-auth-value",
                "User-Agent": unusual,
            })
            self.assertEqual(status, 200)
            self.assertIn("no-store", headers["Cache-Control"])
            doc = self.embedded(data)
            self.assertEqual(doc["kind"], "navigation")
            self.assertEqual(doc["request"]["path"], path)
            self.assertTrue(doc["request"]["cookiePresent"])
            self.assertTrue(doc["request"]["authHeadersPresent"])
            self.assertEqual(doc["request"]["queryFieldCount"], 1)
            self.assertIn({"name": "User-Agent", "value": unusual}, doc["request"]["headers"])
            self.assertNotIn(b"<svg onload=bad>", data)
            self.assertNotIn(b"private-", data)

    def test_sample_only_returns_challenge_and_observed_network(self):
        challenge = "ab" * 16
        path = "/who/api/who/visibility/sample?challenge=" + challenge
        headers_in = {
            "Origin": "https://main.example", "Cookie": "secret-cookie-value",
            "X-Real-IP": "2001:db8::10", "X-Edge-Peer-IP": "2001:db8::10",
            "X-Edge-Peer-Port": "35642", "X-Edge-Local-IP": "2001:db8::91", "X-Edge-Local-Port": "443",
            "X-HTTP-Version": "HTTP/3.0", "X-TLS-ALPN": "h3", "X-Forwarded-Proto": "https",
        }
        status, headers, data = self.request("GET", path, headers_in)
        payload = json.loads(data)
        self.assertEqual(status, 200)
        self.assertEqual(payload["challenge"], challenge)
        self.assertEqual(payload["peer"]["ip"], "2001:db8::10")
        self.assertEqual(payload["connection"], {"httpVersion": "HTTP/3.0", "alpn": "h3", "source": "trusted-edge"})
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://main.example")
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertNotIn(b"secret-cookie-value", data)
        self.assertNotIn("request", payload)
        headers_in["Origin"] = "https://wrong.example"
        self.assertNotIn("Access-Control-Allow-Origin", self.request("GET", path, headers_in)[1])
        self.assertEqual(self.request("GET", "/api/who/visibility/sample")[0], 400)

        # A UDP request can have the same addresses and ports as a TCP one.
        cache = probe.TTLCache(maxsize=4, ttl_sec=30)
        cache.set(("2001:db8::10", 35642, "2001:db8::91", 443), {"tcp": {"ja4t": "tcp-fixture"}})
        with patch.object(probe, "PACKET_CACHE", cache):
            receipt_path = "/api/who/visibility/request"
            h3 = json.loads(self.request("GET", receipt_path, headers_in)[2])
            self.assertIsNone(h3["wire"]["tcp"])
            h2 = json.loads(self.request("GET", receipt_path, {
                **headers_in, "X-HTTP-Version": "HTTP/2.0", "X-TLS-ALPN": "h2",
            })[2])
            self.assertEqual(h2["wire"]["tcp"]["ja4t"], "tcp-fixture")

    def test_shared_page_does_not_embed_visitor_receipt(self):
        shared = {"id": "example1", "createdAt": 123456789, "report": {"score": 88}}
        with patch.object(probe, "get_share_store") as store:
            store.return_value.get.return_value = shared
            status, _, body = self.request("GET", "/who/r/example1", {"User-Agent": "private-example-agent"})
        self.assertEqual(status, 200)
        self.assertIn(b"__WHOPROBE_SHARED__", body)
        self.assertNotIn(b"whoNavigationReceipt", body)
        self.assertNotIn(b"private-example-agent", body)

    def test_dns_handles_stay_in_same_origin_json(self):
        class Dns:
            def issue(self):
                return {"token": "my-private-handle", "host": "one.measure.example", "expiresIn": 60}

            def lookup(self, token):
                return {"observations": [{"resolverIp": "192.0.2.9", "qtype": "A", "ecsNetwork": None}]} if token == "my-private-handle" else None

        start = "/api/who/visibility/dns/start"
        result = "/api/who/visibility/dns/result"
        headers = {"Content-Type": "application/json"}
        self.assertEqual(self.request("POST", start, headers, "{}")[0], 404)
        self.view.dns = Dns()
        self.assertEqual(self.request("POST", start, {**headers, "Sec-Fetch-Site": "cross-site"}, "{}")[0], 400)
        status, _, payload = self.request("POST", start, headers, "{}")
        self.assertEqual(status, 200)
        token = json.loads(payload)["token"]
        self.assertEqual(self.request("GET", result + "?token=" + token)[0], 404)
        self.assertEqual(self.request("POST", result, headers, '{"token":"unknown"}')[0], 404)
        status, _, payload = self.request("POST", result, headers, json.dumps({"token": token}))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["observations"][0]["resolverIp"], "192.0.2.9")
        self.assertNotIn(token.encode(), payload)

    def test_bgp_only_queries_when_requested(self):
        with patch.object(visibility.egress_intel, "fetch_route_history", return_value={"ok": True, "status": "observed"}) as lookup:
            self.request("GET", "/")
            self.request("HEAD", "/api/who/visibility/bgp?prefix=8.8.8.0%2F24")
            lookup.assert_not_called()
            self.assertEqual(self.request("GET", "/api/who/visibility/bgp?prefix=8.8.8.0%2F24")[0], 200)
            lookup.assert_called_once_with("8.8.8.0/24")


if __name__ == "__main__":
    unittest.main()
