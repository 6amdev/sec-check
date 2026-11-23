"""ทดสอบ allow-list — ส่วนที่สำคัญที่สุดด้านความปลอดภัย / tests for the scope allow-list

    python3 -m unittest discover -s tests
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import scope  # noqa: E402


class ScopeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"targets": [
            {"target": "https://shop.example", "kind": "url"},
            {"target": "*.example.org", "kind": "host"},
            {"target": "192.168.1.0/24", "kind": "net"},
        ]}, self.tmp)
        self.tmp.close()
        self.orig, scope.SCOPE_FILE = scope.SCOPE_FILE, Path(self.tmp.name)

    def tearDown(self):
        scope.SCOPE_FILE = self.orig
        Path(self.tmp.name).unlink()

    def ok(self, t):
        self.assertTrue(scope.check(t), t)

    def no(self, t):
        with self.assertRaises(scope.OutOfScope, msg=t):
            scope.check(t)

    def test_loopback_always_allowed(self):
        for t in ("127.0.0.1", "127.0.0.2", "http://127.0.0.2:8808", "localhost", "127.0.0.0/8", "::1"):
            self.ok(t)

    def test_allowed(self):
        for t in ("https://shop.example/", "http://shop.example:8080", "shop.example", "api.example.org",
                  "https://a.b.example.org", "example.org", "192.168.1.7", "192.168.1.0/25", "192.168.1.0/24"):
            self.ok(t)

    def test_refused(self):
        for t in ("https://evil.example", "notshop.example", "shop.example.evil.com", "badexample.org",
                  "192.168.2.1", "192.168.0.0/16", "10.0.0.0/8", "8.8.8.8", "https://127.0.0.1.nip.io"):
            self.no(t)


if __name__ == "__main__":
    unittest.main()
