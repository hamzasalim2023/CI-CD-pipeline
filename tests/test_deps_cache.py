import os
import tempfile
import unittest

from mytool.deps.cache import OSVCache


class TestOSVCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = OSVCache(cache_dir=self.tmp.name, ttl_hours=24.0)

    def tearDown(self):
        self.cache.close()
        self.tmp.cleanup()

    def test_roundtrip(self):
        self.assertIsNone(self.cache.get("PyPI", "flask", "1.1.4"))
        self.cache.put("PyPI", "flask", "1.1.4", [{"id": "GHSA-x"}])
        self.assertEqual(self.cache.get("PyPI", "flask", "1.1.4"), [{"id": "GHSA-x"}])

    def test_empty_result_is_cached(self):
        self.cache.put("PyPI", "pkg", "1.0.0", [])
        self.assertEqual(self.cache.get("PyPI", "pkg", "1.0.0"), [])

    def test_ttl_expiry(self):
        self.cache.close()
        self.cache = OSVCache(cache_dir=self.tmp.name, ttl_hours=0.0)
        self.cache.put("PyPI", "pkg", "1.0.0", [{"id": "GHSA-x"}])
        self.assertIsNone(self.cache.get("PyPI", "pkg", "1.0.0"))

    def test_vuln_record_cache(self):
        self.assertIsNone(self.cache.get_vuln("GHSA-abc"))
        self.cache.put_vuln("GHSA-abc", {"id": "GHSA-abc", "summary": "hi"})
        self.assertEqual(self.cache.get_vuln("GHSA-abc")["summary"], "hi")

    def test_clear(self):
        self.cache.put("PyPI", "pkg", "1.0.0", [])
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)


if __name__ == "__main__":
    unittest.main()