import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from mytool.commands.sast import run_scan_code
from mytool.sast.checker import scan_path, scan_text

FIXTURES = Path(__file__).parent / "fixtures" / "code"
INSECURE = str(FIXTURES / "insecure.py")
CLEAN = str(FIXTURES / "clean.py")


class TestSastScan(unittest.TestCase):
    def _scan(self, path):
        return scan_path(path)

    def test_insecure_file_finds_all_rules(self):
        findings = self._scan(INSECURE)
        rule_ids = {f.rule_id for f in findings}
        expected = {
            "sast-os-system",
            "sast-shell-true",
            "sast-insecure-deserialization",
            "sast-verify-false",
            "sast-ssl-check-hostname",
            "sast-sql-injection",
        }
        self.assertTrue(
            expected.issubset(rule_ids),
            msg=f"missing {expected - rule_ids}; got {rule_ids}",
        )

    def test_findings_have_correct_shape(self):
        findings = self._scan(INSECURE)
        os_sys = [f for f in findings if f.rule_id == "sast-os-system"]
        self.assertEqual(len(os_sys), 1)
        self.assertEqual(os_sys[0].scan_type, "code")
        self.assertEqual(os_sys[0].severity, "high")
        self.assertEqual(os_sys[0].file, "insecure.py")
        self.assertEqual(os_sys[0].line, 10)
        self.assertEqual(os_sys[0].extra["cwe"], "CWE-78")

    def test_eval_and_exec_detected(self):
        findings = scan_text(
            'value = eval("1+1")\nexec("import os")\n', "danger.py"
        )
        evals = {f.line for f in findings if f.rule_id == "sast-eval-exec"}
        self.assertEqual(evals, {1, 2})

    def test_shell_true_via_keyword(self):
        findings = scan_text(
            'subprocess.run("ls", shell=True)\n', "danger.py"
        )
        self.assertEqual(
            [f.rule_id for f in findings], ["sast-shell-true"]
        )

    def test_clean_file_no_findings(self):
        findings = self._scan(CLEAN)
        self.assertEqual(findings, [])

    def test_scan_whole_dir_includes_only_py(self):
        findings = self._scan(str(FIXTURES))
        files = {f.file for f in findings}
        self.assertIn("insecure.py", files)
        self.assertNotIn("clean.py", files)

    def test_syntax_error_file_is_skipped(self):
        with open(str(FIXTURES.parent / "_broken_tmp.py"), "w") as fh:
            fh.write("def broken(:\n")
        try:
            self.assertEqual(scan_path(str(FIXTURES.parent / "_broken_tmp.py")), [])
        finally:
            (FIXTURES.parent / "_broken_tmp.py").unlink(missing_ok=True)


class TestScanCodeCommandDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.repo)
        git = ["git", "-C", str(self.repo)]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(
            git + ["config", "user.email", "test@example.com"], check=True
        )
        subprocess.run(git + ["config", "user.name", "Test"], check=True)
        (self.repo / "app.py").write_text("import os\nos.system('echo ok')\n")
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(git + ["commit", "-qm", "initial"], check=True)

    def tearDown(self):
        os.chdir(self._cwd)
        self.tmp.cleanup()

    def test_diff_mode_finds_os_system_in_changed_file(self):
        (self.repo / "app.py").write_text(
            "import os\nos.system('echo ok')\n"
            "os.system('rm -rf /tmp/x')\n"
        )
        subprocess.run(["git", "-C", str(self.repo), "add", "app.py"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "second"], check=True
        )
        args = SimpleNamespace(
            path=".", diff=["HEAD~1", "HEAD"], json=False, output=None,
            fail_on="high",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_scan_code(args)
        self.assertEqual(code, 1)
        self.assertIn("sast-os-system", buf.getvalue())


if __name__ == "__main__":
    unittest.main()