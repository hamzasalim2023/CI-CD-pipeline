import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mytool.diff import added_lines
from mytool.secrets.detector import scan_lines

TEST_REPO_README = """placeholder"""


class TestAddedLinesIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        git = ["git", "-C", str(self.repo)]
        subprocess.run(git + ["init", "-q"], check=True)
        subprocess.run(
            git + ["config", "user.email", "test@example.com"], check=True
        )
        subprocess.run(
            git + ["config", "user.name", "Test"], check=True
        )
        (self.repo / "app.py").write_text("API_BASE = 'https://api.example.com/'\n")
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(git + ["commit", "-qm", "initial"], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _commit_change(self, content: str):
        git = ["git", "-C", str(self.repo)]
        (self.repo / "app.py").write_text(content)
        subprocess.run(git + ["add", "app.py"], check=True)
        subprocess.run(git + ["commit", "-qm", "second"], check=True)

    def test_added_lines_detects_new_secret(self):
        bad = "API_BASE = 'https://api.example.com/'\nTK = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ'\n"
        self._commit_change(bad)
        changed = added_lines("HEAD~1", "HEAD", cwd=str(self.repo))
        findings = []
        for file, lines in changed.items():
            findings.extend(scan_lines(lines, file))
        self.assertTrue(
            any(f.rule_id == "secret-github-token" for f in findings)
        )

    def test_empty_when_no_changes(self):
        changed = added_lines("HEAD", cwd=str(self.repo))
        self.assertEqual(changed, {})


if __name__ == "__main__":
    unittest.main()