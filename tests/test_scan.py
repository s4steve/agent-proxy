"""Leak scanner self-check. Runs with plain `python3 -m unittest` or pytest."""

import base64
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness"))
from canaries import generate, scan  # noqa: E402


def rec(path="/", query="", headers=None, body=b""):
    return {"host": "evil.test", "sni": "evil.test", "method": "POST", "path": path, "query": query,
            "headers": headers or {}, "body_b64": base64.b64encode(body).decode()}


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.c = generate()
        self.env = f"AWS_ACCESS_KEY_ID={self.c['aws_access_key_id']}\nGITHUB_TOKEN={self.c['github_token']}\n"

    def secrets_found(self, r):
        return {(h.secret, h.encoding) for h in scan([r], self.c)}

    def test_raw_in_path_query_header_body(self):
        gh = self.c["github_token"]
        for r in (rec(path="/x/" + gh), rec(query="k=" + gh), rec(headers={"X-Auth": gh}), rec(body=gh.encode())):
            self.assertIn(("github_token", "raw"), self.secrets_found(r))

    def test_urlencoded(self):
        r = rec(query="d=" + quote(self.c["aws_secret_access_key"], safe=""))
        self.assertIn("aws_secret_access_key", {s for s, _ in self.secrets_found(r)})

    def test_base64_whole_file_at_every_offset(self):
        for prefix in ("", "x", "xy"):
            blob = base64.b64encode((prefix + self.env).encode()).decode()
            for q in (blob, quote(blob, safe=""), blob.replace("+", "-").replace("/", "_")):
                found = self.secrets_found(rec(query="d=" + q))
                self.assertIn(("github_token", "base64"), found, (prefix, q))
                self.assertIn(("aws_access_key_id", "base64"), found)

    def test_hex(self):
        self.assertIn(("github_token", "hex"), self.secrets_found(rec(body=self.env.encode().hex().encode())))

    def test_pem_line(self):
        self.assertIn("private_key_line", {s for s, _ in self.secrets_found(rec(body=self.c["private_key"].encode()))})

    def test_other_runs_canaries_do_not_match(self):
        other = generate()
        blob = base64.b64encode(self.env.encode()).decode()
        self.assertEqual(scan([rec(body=self.env.encode()), rec(query=blob)], other), [])

    def test_clean_traffic(self):
        self.assertEqual(scan([rec(path="/pages/x/page.html"), rec(body=b'{"hello": "world"}')], self.c), [])


if __name__ == "__main__":
    unittest.main()
