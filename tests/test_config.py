import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from mytool.commands.sast import run_scan_code
from mytool.config import (
    Config,
    apply_allowlist,
    filter_paths,
    find_config,
    load_config,
    process_findings,
)
from mytool.models import Finding


def _finding(rule="sast-os-system", scan="code", file="app.py", line=3, context="os.system('ls')"):
    return Finding(
        scan_type=scan, rule_id=rule, severity="high",
        file=file, line=line, message="x", context=context,
    )


CONFIG_TOML = """\
fail-on = "critical"
cache-dir = ".ci-scanner-cache"
ttl-hours = 48.0
offline = true

include = ["src"]
exclude = ["tests/fixtures"]

[[allow]]
scan = "secret"
file = "tests/**"
line = 5
value = "example"
"""


class TestLoadConfig(unittest.TestCase):
    def test_explicit_file_parses_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mytool.toml"
            path.write_text(CONFIG_TOML, encoding="utf-8")
            cfg = load_config(explicit=str(path))
        self.assertEqual(cfg.fail_on, "critical")
        self.assertEqual(cfg.cache_dir, ".ci-scanner-cache")
        self.assertEqual(cfg.ttl_hours, 48.0)
        self.assertTrue(cfg.offline)
        self.assertFalse(cfg.refresh)
        self.assertEqual(cfg.include, ["src"])
        self.assertEqual(cfg.exclude, ["tests/fixtures"])
        self.assertEqual(cfg.allowlist, [
            {"scan": "secret", "file": "tests/**", "line": 5, "value": "example"},
        ])
        self.assertTrue(cfg.source)

    def test_no_file_returns_defaults(self):
        cfg = load_config(start=str(Path(tempfile.gettempdir())))
        self.assertEqual(cfg, Config())
        self.assertEqual(cfg.source, "")

    def test_find_config_walks_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp) / "proj"
            deep = proj / "src" / "pkg" / "nested"
            deep.mkdir(parents=True)
            (proj / "mytool.toml").write_text("", encoding="utf-8")
            found = find_config(start=str(deep))
        self.assertEqual(found, str(proj / "mytool.toml"))


class TestAllowlist(unittest.TestCase):
    def test_rule_match_suppresses(self):
        cfg = Config(allowlist=[{"rule": "sast-os-system"}])
        kept = apply_allowlist([_finding()], cfg)
        self.assertEqual(kept, [])

    def test_non_matching_rule_kept(self):
        cfg = Config(allowlist=[{"rule": "sast-shell-true"}])
        kept = apply_allowlist([_finding()], cfg)
        self.assertEqual(len(kept), 1)

    def test_file_glob_match(self):
        cfg = Config(allowlist=[{"file": "tests/**"}])
        kept = apply_allowlist([_finding(file="tests/case.py")], cfg)
        self.assertEqual(kept, [])

    def test_value_substring_match(self):
        cfg = Config(allowlist=[{"value": "AKIAIOS"}])
        f = _finding(rule="secret-aws-access-key-id",
                     scan="secret", context="AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(apply_allowlist([f], cfg), [])

    def test_scan_type_match(self):
        cfg = Config(allowlist=[{"scan": "secret"}])
        code = _finding()
        secret = _finding(rule="secret-github-token", scan="secret")
        kept = apply_allowlist([code, secret], cfg)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].rule_id, "sast-os-system")


class TestPathFilter(unittest.TestCase):
    def test_exclude_drops_matching_prefix(self):
        cfg = Config(exclude=["tests"])
        kept = filter_paths(
            [_finding(file="tests/fixtures/x.py"), _finding(file="app.py")], cfg
        )
        self.assertEqual([f.file for f in kept], ["app.py"])

    def test_include_keeps_only_matching(self):
        cfg = Config(include=["src"])
        kept = filter_paths(
            [_finding(file="src/app.py"), _finding(file="docs/x.py")], cfg
        )
        self.assertEqual([f.file for f in kept], ["src/app.py"])

    def test_process_findings_applies_both(self):
        cfg = Config(
            exclude=["tests"],
            allowlist=[{"rule": "sast-os-system"}],
        )
        findings = [
            _finding(file="tests/x.py"),
            _finding(file="app.py"),
            _finding(file="app.py", rule="sast-shell-true"),
        ]
        kept = process_findings(findings, cfg)
        self.assertEqual([f.rule_id for f in kept], ["sast-shell-true"])


class TestConfigIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "app.py").write_text("import os\nos.system('ls')\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, config=None, fail_on=None):
        args = SimpleNamespace(
            path=str(self.dir), diff=None, json=False, output=None,
            fail_on=fail_on, config=config,
        )
        return run_scan_code(args)

    def test_config_allowlist_suppresses_finding(self):
        (self.dir / "mytool.toml").write_text(
            '[[allow]]\nrule = "sast-os-system"\n', encoding="utf-8"
        )
        self.assertEqual(self._run(config=str(self.dir / "mytool.toml")), 0)

    def test_config_fail_on_raises_threshold(self):
        (self.dir / "mytool.toml").write_text(
            'fail-on = "critical"\n', encoding="utf-8"
        )
        # os.system is "high", so "critical" threshold does not fail.
        self.assertEqual(self._run(config=str(self.dir / "mytool.toml")), 0)

    def test_cli_fail_on_overrides_config(self):
        (self.dir / "mytool.toml").write_text(
            'fail-on = "critical"\n', encoding="utf-8"
        )
        self.assertEqual(
            self._run(config=str(self.dir / "mytool.toml"), fail_on="high"), 1
        )

    def test_no_config_default_high_fails(self):
        self.assertEqual(self._run(), 1)


if __name__ == "__main__":
    unittest.main()