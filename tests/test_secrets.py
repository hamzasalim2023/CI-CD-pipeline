import unittest
from pathlib import Path

from mytool.secrets.detector import scan_path

FIXTURES = Path(__file__).parent / "fixtures" / "secrets"


class TestSecretsScan(unittest.TestCase):
    def test_bad_file_detects_known_rule_ids(self):
        findings = scan_path(str(FIXTURES / "bad_secrets.py"))
        rule_ids = {f.rule_id for f in findings}
        expected = {
            "secret-aws-access-key-id",
            "secret-aws-secret-access-key",
            "secret-github-token",
            "secret-slack-webhook",
            "secret-google-api-key",
            "secret-stripe-live-key",
            "secret-jwt-token",
            "secret-generic-api-key",
            "secret-private-key",
        }
        self.assertTrue(
            expected.issubset(rule_ids),
            msg=f"missing {expected - rule_ids}; got {rule_ids}",
        )

    def test_bad_file_line_numbers(self):
        findings = scan_path(str(FIXTURES / "bad_secrets.py"))
        aws = [f for f in findings if f.rule_id == "secret-aws-access-key-id"]
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0].line, 5)
        self.assertEqual(aws[0].file, "bad_secrets.py")
        self.assertEqual(aws[0].severity, "critical")

    def test_bad_file_no_duplicate_line_for_specific_rule(self):
        findings = scan_path(str(FIXTURES / "bad_secrets.py"))
        stripe = [f for f in findings if f.rule_id == "secret-stripe-live-key"]
        self.assertEqual(len(stripe), 1)

    def test_clean_file_no_findings(self):
        findings = scan_path(str(FIXTURES / "clean_code.py"))
        self.assertEqual(findings, [])

    def test_scan_whole_dir_captures_both(self):
        findings = scan_path(str(FIXTURES))
        files = {f.file for f in findings}
        self.assertIn("bad_secrets.py", files)
        self.assertNotIn("clean_code.py", files)


if __name__ == "__main__":
    unittest.main()