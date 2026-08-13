"""Shannon entropy calculation, used to spot high-entropy strings that
look like randomly generated tokens/keys.

Entropy is a measure of the amount of uncertainty in a string. Random
secrets (API keys, tokens) tend to have high entropy (~4+ bits/char for
alphanumerics), while words, emails and commit hashes are lower.
"""

from math import log2


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    freq: dict = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    return -sum((count / length) * log2(count / length) for count in freq.values())


def charclass_ratio(data: str) -> tuple:
    """Return (lower, upper, digits, symbols) ratios in [0,1] each."""
    if not data:
        return (0.0, 0.0, 0.0, 0.0)
    n = len(data)
    lower = sum(1 for c in data if c.islower())
    upper = sum(1 for c in data if c.isupper())
    digits = sum(1 for c in data if c.isdigit())
    symbols = n - lower - upper - digits
    return (lower / n, upper / n, digits / n, symbols / n)
