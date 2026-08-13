import unittest
from pathlib import Path

from mytool.deps.parsers import (
    discover_manifests,
    parse_go_mod,
    parse_manifest_text,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
)

FIXTURES = Path(__file__).parent / "fixtures" / "deps"


class TestRequirements(unittest.TestCase):
    def test_pinned_versions_extracted(self):
        text = (FIXTURES / "requirements.txt").read_text(encoding="utf-8")
        deps = parse_requirements(text)
        by_name = {d.name: d.version for d in deps}
        self.assertEqual(by_name["flask"], "1.1.4")
        self.assertEqual(by_name["requests"], "2.19.1")
        self.assertEqual(by_name["urllib3"], "1.24.1")
        self.assertEqual(by_name["django"], "2.2.0")

    def test_range_specs_not_queried(self):
        text = (FIXTURES / "requirements.txt").read_text(encoding="utf-8")
        deps = parse_requirements(text)
        self.assertNotIn("pyyaml", {d.name for d in deps})

    def test_comments_ignored(self):
        deps = parse_requirements("# comment\nrequests==1.0.0\n")
        self.assertEqual([d.name for d in deps], ["requests"])


class TestPackageJson(unittest.TestCase):
    def test_extracts_deps_and_devdeps(self):
        text = (FIXTURES / "package.json").read_text(encoding="utf-8")
        deps = parse_package_json(text)
        by_name = {d.name: d.version for d in deps}
        self.assertEqual(by_name["express"], "4.17.1")
        self.assertEqual(by_name["lodash"], "4.17.20")
        self.assertEqual(by_name["minimist"], "1.2.5")
        self.assertEqual(by_name["left-pad"], "1.3.0")  # ^1.3.0 -> 1.3.0
        self.assertEqual(by_name["jquery"], "3.4.1")


class TestGoMod(unittest.TestCase):
    def test_module_versions(self):
        text = (FIXTURES / "go.mod").read_text(encoding="utf-8")
        deps = parse_go_mod(text)
        by_name = {d.name: d.version for d in deps}
        self.assertEqual(by_name["golang.org/x/text"], "0.3.2")
        self.assertEqual(by_name["github.com/gin-gonic/gin"], "1.7.0")


class TestDiscovery(unittest.TestCase):
    def test_finds_manifests(self):
        found = discover_manifests(str(FIXTURES))
        names = {Path(f).name for f in found}
        self.assertIn("requirements.txt", names)
        self.assertIn("package.json", names)
        self.assertIn("go.mod", names)


class TestParseDispatch(unittest.TestCase):
    def test_unknown_file_returns_empty(self):
        self.assertEqual(parse_manifest_text("irrelevant", "foo.yml"), [])


if __name__ == "__main__":
    unittest.main()