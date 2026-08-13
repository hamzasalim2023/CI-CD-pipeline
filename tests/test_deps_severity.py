import unittest

from mytool.deps.severity import cvss_base_score, roundup, score_severity


class TestCvssBaseScore(unittest.TestCase):
    def test_known_high_vector(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
        self.assertAlmostEqual(
            cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8, places=1
        )

    def test_known_medium_vector(self):
        # AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L -> 5.0
        self.assertAlmostEqual(
            cvss_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"), 5.0, places=1
        )

    def test_invalid_vector_returns_none(self):
        self.assertIsNone(cvss_base_score("garbage"))

    def test_empty_vector(self):
        self.assertIsNone(cvss_base_score(""))


class TestRoundup(unittest.TestCase):
    def test_half_up(self):
        self.assertAlmostEqual(roundup(5.75), 5.8, places=1)
        self.assertAlmostEqual(roundup(5.3), 5.3, places=1)


class TestScoreSeverity(unittest.TestCase):
    def test_numeric_mapping(self):
        self.assertEqual(score_severity(9.8), "critical")
        self.assertEqual(score_severity(7.5), "high")
        self.assertEqual(score_severity(5.0), "medium")
        self.assertEqual(score_severity(1.0), "low")

    def test_word_fallback(self):
        self.assertEqual(score_severity(None, "CRITICAL"), "critical")
        self.assertEqual(score_severity(None, "MODERATE"), "medium")
        self.assertEqual(score_severity(None, ""), "medium")

    def test_numeric_wins_over_word(self):
        self.assertEqual(score_severity(9.8, "MODERATE"), "critical")


if __name__ == "__main__":
    unittest.main()