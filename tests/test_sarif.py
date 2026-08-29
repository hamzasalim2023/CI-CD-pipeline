import json
import unittest

from mytool.models import Finding
from mytool.sarif import build_sarif, finding_to_sarif_result


def _finding(scan_type="code", rule="sast-eval-exec", severity="high",
             file="app.py", line=15, message="msg", extra=None, cwe="CWE-95"):
    return Finding(scan_type, rule, severity, file, line, message,
                   context="print(x)", extra=extra or {"cwe": cwe})


class TestSarifStructure(unittest.TestCase):
    def test_document_shape(self):
        doc = build_sarif([_finding()])
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["$schema"].startswith("https://"))
        self.assertEqual(len(doc["runs"]), 1)
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "mytool")
        self.assertEqual(driver["version"], "0.1.0")

    def test_empty_findings_still_valid(self):
        doc = build_sarif([])
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertEqual(run["results"], [])


class TestSarifResults(unittest.TestCase):
    def test_result_maps_core_fields(self):
        f = _finding(line=42)
        res = finding_to_sarif_result(f)
        self.assertEqual(res["ruleId"], "sast-eval-exec")
        self.assertEqual(res["level"], "error")  # high -> error
        self.assertEqual(res["message"]["text"], "msg")
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "app.py")
        self.assertEqual(loc["region"]["startLine"], 42)

    def test_level_mapping(self):
        cases = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        for severity, expected in cases.items():
            res = finding_to_sarif_result(_finding(severity=severity))
            self.assertEqual(res["level"], expected)

    def test_security_severity_property(self):
        self.assertEqual(finding_to_sarif_result(_finding(severity="critical"))
                         ["properties"]["security-severity"], "9.5")
        self.assertEqual(finding_to_sarif_result(_finding(severity="low"))
                         ["properties"]["security-severity"], "3.0")

    def test_code_finding_has_cwe_tag_and_column(self):
        f = _finding(extra={"cwe": "CWE-95", "col": 3})
        res = finding_to_sarif_result(f)
        self.assertIn("CWE-95", res["properties"]["tags"])
        self.assertEqual(res["locations"][0]["physicalLocation"]["region"]
                         ["startColumn"], 3)

    def test_dependency_finding_carries_package_metadata(self):
        f = Finding("dependency", "GHSA-xxxx", "high", "requirements.txt", 1,
                    "vuln", context="flask",
                    extra={"package": "flask", "ecosystem": "PyPI",
                           "installed": "0.12.2", "fixed": "0.12.3",
                           "cvss_score": 7.5, "cwe": ""})
        res = finding_to_sarif_result(f)
        dep = res["properties"]["dependency"]
        self.assertEqual(dep["package"], "flask")
        self.assertEqual(dep["ecosystem"], "PyPI")
        self.assertEqual(dep["installed"], "0.12.2")
        self.assertEqual(dep["fixed"], "0.12.3")


class TestSarifRules(unittest.TestCase):
    def test_rules_deduplicated_by_id(self):
        doc = build_sarif([_finding(line=1), _finding(line=2),
                           _finding(rule="sast-shell-true", file="x.py", line=3)])
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(len(rules), 2)
        self.assertIn("sast-eval-exec", ids)
        self.assertIn("sast-shell-true", ids)

    def test_rule_has_short_description_and_severity(self):
        rule = build_sarif([_finding()])["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["shortDescription"]["text"], "msg")
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")

    def test_rule_is_json_serializable(self):
        doc = build_sarif([_finding()])
        # Building the document must produce JSON-serializable data.
        json.dumps(doc)


if __name__ == "__main__":
    unittest.main()
