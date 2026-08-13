import tempfile
import unittest

from mytool.deps.cache import OSVCache
from mytool.deps.parsers import Package
from mytool.deps.scanner import DependencyScanner, dedupe_vulns, primary_id

FULL_GHSA = {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "summary": "Demo advisory",
    "details": "long details ...",
    "aliases": ["CVE-2020-1234"],
    "modified": "2022-01-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "database_specific": {"severity": "HIGH"},
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "demo"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}],
    }],
}

FULL_PYSEC = {
    "id": "PYSEC-2020-100",
    "summary": "Same CVE via PyPI db",
    "aliases": ["CVE-2020-1234"],
    "modified": "2022-01-01T00:00:00Z",
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "demo"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}],
    }],
}


class FakeResponse:
    def __init__(self, payload, status=200):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code != 200:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _next(self):
        if not self.responses:
            return FakeResponse({})
        item = self.responses.pop(0)
        return item(self) if callable(item) else item

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return self._next()

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        return self._next()


def make_scanner(session=None, offline=False):
    tmp = tempfile.TemporaryDirectory()
    cache = OSVCache(cache_dir=tmp.name, ttl_hours=24)
    scanner = DependencyScanner(cache=cache, offline=offline, session=session)
    scanner._tmp = tmp
    return scanner


PKG = Package("PyPI", "demo", "1.0.0", file="requirements.txt", line=3)


class TestScannerOnline(unittest.TestCase):
    def test_simple_query_produces_finding(self):
        session = FakeSession([FakeResponse({"vulns": [FULL_GHSA]})])
        scanner = make_scanner(session=session)
        try:
            findings = scanner.findings_for([PKG])
        finally:
            scanner.cache.close()
            scanner._tmp.cleanup()
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.scan_type, "dependency")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.rule_id, "CVE-2020-1234")
        self.assertEqual(f.extra["package"], "demo")
        self.assertEqual(f.extra["installed"], "1.0.0")
        self.assertEqual(f.extra["fixed"], "2.1.0")

    def test_abbreviated_entries_resolved(self):
        def first_post(sess):
            assert sess.calls[-1][2].get("params") is None
            return FakeResponse(
                {"vulns": [{"id": "GHSA-xxxx-xxxx-xxxx", "modified": "x"}],
                 "next_page_token": "tok"}
            )

        def second_post(sess):
            assert sess.calls[-1][2].get("params") == {"page_token": "tok"}
            return FakeResponse({"vulns": []})

        session = FakeSession([
            first_post, second_post,
            FakeResponse(FULL_GHSA),  # the GET /v1/vulns/{id}
        ])
        scanner = make_scanner(session=session)
        try:
            findings = scanner.findings_for([PKG])
        finally:
            scanner.cache.close()
            scanner._tmp.cleanup()
        gets = [c for c in session.calls if c[0] == "get"]
        self.assertTrue(gets, "expected a GET /v1/vulns call")
        self.assertTrue(gets[0][1].endswith("GHSA-xxxx-xxxx-xxxx"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_no_vulns(self):
        session = FakeSession([FakeResponse({"vulns": []})])
        scanner = make_scanner(session=session)
        try:
            self.assertEqual(scanner.findings_for([PKG]), [])
        finally:
            scanner.cache.close()
            scanner._tmp.cleanup()


class TestScannerOffline(unittest.TestCase):
    def test_cache_hit_avoids_network(self):
        session = FakeSession([])
        scanner = make_scanner(session=session, offline=True)
        try:
            scanner.cache.put("PyPI", "demo", "1.0.0", [FULL_GHSA])
            findings = scanner.findings_for([PKG])
        finally:
            scanner.cache.close()
            scanner._tmp.cleanup()
        self.assertEqual(session.calls, [])
        self.assertEqual(len(findings), 1)


class TestDedupe(unittest.TestCase):
    def test_keeps_ghsa_over_pysec(self):
        kept = dedupe_vulns([FULL_PYSEC, FULL_GHSA])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["id"], "GHSA-xxxx-xxxx-xxxx")

    def test_distinct_vulns_kept(self):
        other = dict(FULL_GHSA)
        other["id"] = "GHSA-yyyy"
        other["aliases"] = ["CVE-2020-9999"]
        kept = dedupe_vulns([FULL_GHSA, other])
        self.assertEqual(len(kept), 2)


class TestPrimaryId(unittest.TestCase):
    def test_prefers_cve(self):
        self.assertEqual(primary_id(FULL_GHSA), "CVE-2020-1234")

    def test_falls_back_to_advisory_id(self):
        v = dict(FULL_GHSA)
        v["aliases"] = []
        self.assertEqual(primary_id(v), "GHSA-xxxx-xxxx-xxxx")


if __name__ == "__main__":
    unittest.main()