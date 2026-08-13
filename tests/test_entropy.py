import unittest

from mytool.secrets.entropy import charclass_ratio, shannon_entropy


class TestShannonEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_repeated_single_char(self):
        self.assertEqual(shannon_entropy("aaaaaaaaaaaaaaaaaaaa"), 0.0)

    def test_two_chars_even_split(self):
        self.assertAlmostEqual(shannon_entropy("aaaaabbbbb"), 1.0, places=3)

    def test_high_entropy_random(self):
        self.assertGreater(shannon_entropy("xQ8$#fY2!zLmNp9@vT1"), 3.0)

    def test_lower_entropy_word(self):
        self.assertLess(shannon_entropy("configuration"), shannon_entropy("xq8fY2zLmNp9vT1rw"))


class TestCharClassRatio(unittest.TestCase):
    def test_mixed(self):
        lower, upper, digits, symbols = charclass_ratio("Ab1!")
        self.assertEqual((lower, upper, digits, symbols), (0.25, 0.25, 0.25, 0.25))

    def test_lowercase_only(self):
        lower, _, _, _ = charclass_ratio("hello")
        self.assertEqual(lower, 1.0)


if __name__ == "__main__":
    unittest.main()