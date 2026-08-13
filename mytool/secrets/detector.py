"""High-level secrets detection.

Supports two modes:
  * whole-path scanning (scan_path) - walks a directory tree, ignoring
    vendored/binary/large files
  * diff scanning (scan_git_diff) - only inspects the *added* lines of a
    commit or PR, so pre-existing secrets in the codebase don't block CI.
"""

import os
import re
from pathlib import Path

from mytool.models import Finding
from mytool.secrets.entropy import charclass_ratio, shannon_entropy
from mytool.secrets.rules import COMPILED, SecretRule, is_ignored_value

# Directories that are vendored/generated and never worth scanning.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    "target", ".venv", "venv", "__pycache__", ".terraform", ".gradle",
    ".next", "coverage", ".pytest_cache", "site-packages", ".mypy_cache",
    ".tox", ".eggs",
}

MAX_FILE_BYTES = 1_000_000
BINARY_SUSPECT = re.compile(rb"[\x00-\x08\x0e-\x1f]")


def is_binary(data: bytes) -> bool:
    if not data:
        return True
    probe = data[:4096]
    if BINARY_SUSPECT.search(probe):
        return True
    try:
        probe.decode("utf-8")
        return False
    except UnicodeDecodeError:
        # fall back to a heuristic: ratio of replacement characters
        decoded = probe.decode("utf-8", errors="replace")
        ratio = decoded.count("\ufffd") / max(1, len(decoded))
        return ratio > 0.05


def match_line(line: str, line_no: int, file: str) -> list:
    """Run every rule against a single line. Returns findings."""
    candidates = []
    seen = set()
    for rule, compiled in COMPILED:
        for match in compiled.finditer(line):
            value = match.group(rule.group) if rule.group else match.group(0)
            if not value:
                continue
            if rule.min_len and len(value) < rule.min_len:
                continue
            if rule.entropy is not None and shannon_entropy(value) < rule.entropy:
                continue
            if is_ignored_value(value):
                continue
            key = (rule.rule_id, value)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((rule, value))

    # Drop catch-all findings (generic assignment / high-entropy) when the
    # same value was already caught by a more specific rule on this line
    # (this includes values contained inside a larger specific match, e.g.
    # JWT payload segments).
    specific = [
        v for r, v in candidates
        if r.rule_id not in {"secret-generic-api-key", "secret-high-entropy-string"}
    ]
    generic = {
        v for r, v in candidates if r.rule_id == "secret-generic-api-key"
    }

    def covered_by_specific(value: str) -> bool:
        return any(value in sv or sv in value for sv in specific)

    findings = []
    for rule, value in candidates:
        if rule.rule_id == "secret-generic-api-key" and covered_by_specific(value):
            continue
        if rule.rule_id == "secret-high-entropy-string":
            if covered_by_specific(value) or value in generic:
                continue
            if _looks_like_known_format(value):
                continue
            lower, upper, digits, symbols = charclass_ratio(value)
            if not _looks_random_enough(lower, upper, digits, symbols):
                continue
        findings.append(
            Finding(
                scan_type="secret",
                rule_id=rule.rule_id,
                severity=rule.severity,
                file=file,
                line=line_no,
                message=rule.description,
                context=value,
                extra={"match_type": rule.rule_id},
            )
        )
    return findings


def _looks_like_known_format(value: str) -> bool:
    """Filter high-entropy false positives: UUIDs, git hex, numbers."""
    v = value
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
        return True
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", v
    ):
        return True
    if v.isdigit():
        return True
    if len(set(v)) <= 4:
        return True
    return False


def _looks_random_enough(lower, upper, digits, symbols) -> bool:
    """Require a mix of character classes so words like 'configuration'
    (lowercase-only, low entropy) don't get flagged."""
    if lower > 0.9:
        return False          # all-lowercase words/domains
    has_upper_or_symbol = upper > 0.05 or symbols > 0.05
    return has_upper_or_symbol or digits > 0.2


def _iter_files(root: str):
    """Yield text file paths under root, skipping ignored dirs and binaries."""
    root_path = Path(root).resolve()
    stack = [root_path]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                if entry.name in SKIP_DIRS:
                    continue
                stack.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False):
                try:
                    if entry.stat().st_size > MAX_FILE_BYTES:
                        continue
                    with open(entry.path, "rb") as fh:
                        head = fh.read(4096)
                    if not head or is_binary(head):
                        continue
                except OSError:
                    continue
                yield str(Path(entry.path))


def _read_text(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if is_binary(data):
            return None
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def scan_path(root: str, allowlist=None) -> list:
    """Scan every text file under root (or a single file) for secrets."""
    findings = []
    allowlist = allowlist or []
    root_abs = os.path.abspath(root)
    if os.path.isfile(root_abs):
        return scan_file(root_abs, allowlist=allowlist)
    for file in _iter_files(root):
        text = _read_text(file)
        if text is None:
            continue
        rel = os.path.relpath(file, os.path.abspath(root))
        for line_no, line in enumerate(text.splitlines(), start=1):
            matched = match_line(line, line_no, rel)
            for finding in matched:
                if not _allowed(rel, line_no, finding.rule_id, finding.context, allowlist):
                    findings.append(finding)
    return findings


def scan_file(path: str, allowlist=None) -> list:
    """Scan a single file for secrets, returning line numbers relative to it."""
    findings = []
    allowlist = allowlist or []
    text = _read_text(path)
    if text is None:
        return findings
    for line_no, line in enumerate(text.splitlines(), start=1):
        matched = match_line(line, line_no, os.path.basename(path))
        for finding in matched:
            if not _allowed(os.path.basename(path), line_no, finding.rule_id,
                            finding.context, allowlist):
                findings.append(finding)
    return findings


def scan_lines(lines: list, file: str) -> list:
    """Scan an explicit list of (line_no, text) tuples (from a diff)."""
    findings = []
    for line_no, text in lines:
        findings.extend(match_line(text, line_no, file))
    return findings


def _allowed(file: str, line_no: int, rule_id: str, value: str, allowlist) -> bool:
    import fnmatch

    for entry in allowlist:
        if entry.get("rule") and entry["rule"] != rule_id:
            continue
        if entry.get("file") and not fnmatch.fnmatch(file, entry["file"]):
            continue
        if entry.get("line") and entry["line"] != line_no:
            continue
        if entry.get("value") and entry["value"].lower() not in value.lower():
            continue
        # All specified filters on this entry matched -> allowlisted.
        return True
    return False