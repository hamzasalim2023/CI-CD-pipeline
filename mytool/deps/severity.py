"""Minimal CVSS v3.1 base score computation.

OSV carries vulnerability severity as a CVSS 3.x *vector* string (e.g.
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") rather than a ready-made
number, so we derive the base score ourselves using the published CVSS
spec and map it onto our low/medium/high/critical rating scale.

This is used by the dependency module to show meaningful severities in
CI output without relying on a third-party CVSS library.
"""

import math

_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "SPECIAL_C": 0.68, "SPECIAL_U": 0.62,
           "L_C": 0.68, "L_U": 0.62, "H_C": 0.5, "H_U": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}


def _parse_vector(vector: str) -> dict:
    """Split 'CVSS:3.1/AV:N/AC:L/...' into a metric dict."""
    result = {}
    for part in vector.split("/"):
        try:
            key, value = part.split(":")
        except ValueError:
            continue
        result[key] = value.strip()
    return result


def roundup(value: float) -> float:
    """Round a float up to one decimal place (NIST reference algorithm)."""
    value = float(value)
    if math.ceil(value) == value:
        return value
    integer_part = int(value * 10)
    remainder = round(value * 10 - integer_part, 2)
    if remainder == 0.5:
        remainder = 1
    if remainder >= 0.5:
        return 0.1 * (integer_part + 1)
    return 0.1 * integer_part


def cvss_base_score(vector: str) -> float | None:
    """Return the CVSS v3 base score for a vector string, or None."""
    v = _parse_vector(vector)
    try:
        av = _METRICS["AV"][v["AV"]]
        ac = _METRICS["AC"][v["AC"]]
        pr_key = v["PR"]
        if pr_key == "N":
            pr = 0.85
        else:
            pr = _METRICS["PR"].get(f"{pr_key}_{v['S']}",
                                    _METRICS["PR"].get(f"SPECIAL_{v['S']}"))
        ui = _METRICS["UI"][v["UI"]]
        c, i, a = _METRICS["C"][v["C"]], _METRICS["I"][v["I"]], _METRICS["A"][v["A"]]
        if pr is None:
            return None
    except (KeyError, IndexError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if v.get("S") == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if v.get("S") == "C":
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return roundup(base)


def score_severity(score: float | None, fallback: str = "medium") -> str:
    if score is None:
        word = (fallback or "").lower()
        mapping = {
            "critical": "critical", "high": "high", "moderate": "medium",
            "medium": "medium", "low": "low",
        }
        return mapping.get(word, "medium")
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"