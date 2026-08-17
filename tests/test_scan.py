import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from mytool.commands.scan import run_scan
from mytool.models import Finding

FAKE_DEP = Finding(
    scan_type="dependency",
    rule_id="CVE-2020-1234",
    severity="critical",
    file="requirements.txt",
    line=3,
    context="demo@1.0.0",
    message="Demo advisory",
)


def _args(**overrides):
    base = dict(
        path=".", diff=None, json=False, output=None, fail_on="high",
        no_secrets=False, no_deps=False, no_code=False,
        cache_dir=None, ttl_hours=24.0, offline=False, refresh=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestScanCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, text):
        (self.dir / name).write_text(text)

    def _run(self, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_scan(args)
        return code, buf.getvalue()

    def test_can_be_called_standalone(self):
        self.assertTrue(callable(run_scan))

    def test_aggregates_all_scan_types(self):
        self._write("app.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nos.system("ls")\n')
        self._write("requirements.txt", "demo==1.0.0\n")
        cache_dir = str(Path(self.tmp.name) / "cache")
        with mock.patch(
            "mytool.commands.scan.DependencyScanner"
        ) as scanner_cls:
            scanner_cls.return_value.findings_for.return_value = [FAKE_DEP]
            code, out = self._run(_args(path=str(self.dir), cache_dir=cache_dir, fail_on="low"))
        self.assertEqual(code, 1)
        self.assertIn("3 finding(s)", out)
        self.assertIn("1 secret", out)
        self.assertIn("1 dependency", out)
        self.assertIn("1 code", out)

    def test_skip_flags_find_nothing(self):
        self._write("app.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nos.system("ls")\n')
        code, out = self._run(
            _args(path=str(self.dir), no_secrets=True, no_deps=True, no_code=True)
        )
        self.assertEqual(code, 0)
        self.assertIn("No issues found", out)

    def test_missing_path_does_not_crash(self):
        code, _ = self._run(_args(path=str(self.dir / "nope")))
        self.assertEqual(code, 0)

    def test_deps_error_returns_2(self):
        self._write("requirements.txt", "demo==1.0.0\n")
        with mock.patch(
            "mytool.commands.scan.DependencyScanner"
        ) as scanner_cls:
            from mytool.deps.scanner import OSVError

            scanner_cls.return_value.findings_for.side_effect = OSVError("boom")
            code, out = self._run(
                _args(path=str(self.dir), cache_dir=str(Path(self.tmp.name) / "c"))
            )
        self.assertEqual(code, 2)
        self.assertIn("boom", out)


class TestScanCommandDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.repo)
        git = ["git", "-C", str(self.repo)]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(git + ["config", "user.email", "test@example.com"], check=True)
        subprocess.run(git + ["config", "user.name", "Test"], check=True)
        (self.repo / "app.py").write_text("import os\nos.system('echo ok')\n")
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(git + ["commit", "-qm", "initial"], check=True)

    def tearDown(self):
        os.chdir(self._cwd)
        self.tmp.cleanup()

    def test_diff_mode_catches_new_secret_in_commit(self):
        (self.repo / "app.py").write_text(
            "import os\nos.system('echo ok')\n"
            "TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ'\n"
        )
        subprocess.run(["git", "-C", str(self.repo), "add", "app.py"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "second"], check=True
        )
        args = _args(
            path=".", diff=["HEAD~1", "HEAD"],
            no_deps=True, fail_on="high",
        )
        code, out = self._run(args)
        self.assertEqual(code, 1)
        self.assertIn("secret-github", out)

    def _run(self, args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_scan(args)
        return code, buf.getvalue()


if __name__ == "__main__":
    unittest.main()