"""Shared data models for scan findings."""

from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def severity_score(severity: str) -> int:
    return SEVERITY_ORDER.get((severity or "info").lower(), 0)


def threshold_for(fail_on: str) -> int:
    """Resolve a `--fail-on` value (comma-separated severities) into the
    minimum severity score that should fail the build.

    e.g. "high" -> 3, "medium,critical" -> 2 (uses the lowest/lenient bound).
    Unknown severities are ignored; if none resolve, defaults to the most
    permissive threshold (0) so nothing fails unexpectedly.
    """
    items = [severity_score(s) for s in str(fail_on or "").split(",") if s.strip()]
    if not items:
        return 0
    return min(items)


def sort_severity(severity: str) -> int:
    return -severity_score(severity)


@dataclass
class Finding:
    """A single issue discovered by one of the scanner modules."""

    scan_type: str
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    context: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["severity_score"] = severity_score(self.severity)
        return data


def findings_by_severity(findings: list) -> list:
    return sorted(findings, key=lambda f: sort_severity(f.severity))