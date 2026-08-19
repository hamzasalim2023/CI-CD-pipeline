"""Configuration + allowlist support via a `mytool.toml` file.

Enables teams to codify scan behaviour instead of repeating CLI flags:
default severity threshold, OSV cache settings, path include/exclude
filters, and per-finding allowlists (suppress specific rules/files/lines).
"""

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # Python >= 3.11
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

CONFIG_NAME = "mytool.toml"


@dataclass
class Config:
    fail_on: str = "high"
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    allowlist: list = field(default_factory=list)
    cache_dir: str | None = None
    ttl_hours: float = 24.0
    offline: bool = False
    refresh: bool = False
    source: str = ""


def find_config(start: str | None = None) -> str | None:
    """Walk up from `start` to the filesystem root looking for mytool.toml."""
    start = start or os.getcwd()
    path = Path(start)
    if path.is_file():
        path = path.parent
    for parent in (path.resolve(), *path.resolve().parents):
        candidate = parent / CONFIG_NAME
        if candidate.is_file():
            return str(candidate)
    return None


def load_config(explicit: str | None = None, start: str | None = None) -> Config:
    """Load config from an explicit file, or auto-discover one near `start`."""
    if explicit:
        path = Path(explicit)
    else:
        found = find_config(start)
        path = Path(found) if found else None
    if not path or not path.is_file():
        return Config()
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    allowlist = []
    for entry in data.get("allow", []) or []:
        if isinstance(entry, dict):
            allowlist.append({k: v for k, v in entry.items() if v is not None})
    return Config(
        fail_on=str(data.get("fail-on", "high")),
        include=[str(x) for x in (data.get("include") or [])],
        exclude=[str(x) for x in (data.get("exclude") or [])],
        allowlist=allowlist,
        cache_dir=data.get("cache-dir"),
        ttl_hours=float(data.get("ttl-hours", 24.0)),
        offline=bool(data.get("offline", False)),
        refresh=bool(data.get("refresh", False)),
        source=str(path),
    )


def _path_match(file: str, pattern: str) -> bool:
    pattern = str(pattern).replace("\\", "/")
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatch(file, pattern)
    # Plain directory/file prefix without glob characters.
    return file == pattern or file.startswith(pattern.rstrip("/") + "/")


def filter_paths(findings: list, config: Config) -> list:
    """Drop findings whose file doesn't match include/exclude patterns."""
    if not config.include and not config.exclude:
        return findings
    out = []
    for f in findings:
        if any(_path_match(f.file, p) for p in config.exclude):
            continue
        if config.include and not any(_path_match(f.file, p) for p in config.include):
            continue
        out.append(f)
    return out


def apply_allowlist(findings: list, config: Config) -> list:
    """Remove findings matched by any [[allow]] entry."""
    if not config.allowlist:
        return findings
    return [f for f in findings if not _allowed(f, config.allowlist)]


def _allowed(finding, allowlist: list) -> bool:
    for entry in allowlist:
        if entry.get("scan") and entry["scan"] != finding.scan_type:
            continue
        if entry.get("rule") and entry["rule"] != finding.rule_id:
            continue
        if entry.get("file") and not fnmatch.fnmatch(finding.file, entry["file"]):
            continue
        if entry.get("line") and entry["line"] != finding.line:
            continue
        if entry.get("value"):
            hay = f"{finding.context or ''} {finding.message or ''}".lower()
            if str(entry["value"]).lower() not in hay:
                continue
        return True
    return False


def process_findings(findings: list, config: Config) -> list:
    """Apply path filters then allowlists to a raw finding list."""
    return apply_allowlist(filter_paths(findings, config), config)