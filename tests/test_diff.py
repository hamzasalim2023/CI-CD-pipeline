import unittest

from mytool.diff import parse_unified_diff

SYNTHETIC_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,5 @@
 def main():
+    print("hello")
     foo()
     bar()
+    api_key = "AKIAIOSFODNN7EXAMPLE"
@@ -10,2 +11,3 @@ def other():
     x = 1
+    y = 2
+    secret = "sk_live_51J4XbEKxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyy"
"""


class TestDiffParsing(unittest.TestCase):
    def test_parses_added_lines_with_line_numbers(self):
        changed = parse_unified_diff(SYNTHETIC_DIFF)
        self.assertIn("app.py", changed)
        additions = changed["app.py"]
        self.assertEqual(
            additions,
            [
                (2, '    print("hello")'),
                (5, '    api_key = "AKIAIOSFODNN7EXAMPLE"'),
                (12, "    y = 2"),
                (13, '    secret = "sk_live_51J4XbEKxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyy"'),
            ],
        )

    def test_deleted_lines_excluded(self):
        diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,2 @@
-old line
 context
+new line
"""
        changed = parse_unified_diff(diff)
        self.assertEqual(changed, {"app.py": [(2, "new line")]})


if __name__ == "__main__":
    unittest.main()