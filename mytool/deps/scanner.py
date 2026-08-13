"""Dependency vulnerability scanning against the OSV API (osv.dev).

OSV aggregates advisories across many ecosystems (PyPI, npm, Go, etc.) so
one integration covers all of our manifest types. Responses are cached in
SQLite by the OSVCache to avoid hammering the API across repeated CI runs.
"""

import re
import time

import requests

from mytool.deps.cache import OSVCache
from mytool.deps.severity import cvss_base_score, score_severity
from mytool.models import Finding, severity_score

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns"
DEFAULT_TIMEOUT = 30.0


class OSVError(RuntimeError):
    pass


class DependencyScanner:
    def __init__(
        self,
        cache: OSVCache | None = None,
        offline: bool = False,
        refresh: bool = False,
        session: requests.Session | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.cache = cache or OSVCache()
        self.offline = offline
        self.refresh = refresh
        self.session = session or requests.Session()
        self.timeout = timeout

    # -- OSV API ---------------------------------------------------------
    def fetch_vulns(self, packages: list) -> dict:
        """Return {package_key: [vuln_dict, ...]} using cache + API."""
        results: dict = {}
        pending = []
        for pkg in packages:
            key = pkg.query_key()
            cached = None if self.refresh else self.cache.get(*key)
            if cached is not None:
                results[key] = cached
            else:
                pending.append(pkg)
        if pending and not self.offline:
            for pkg in pending:
                key = pkg.query_key()
                vulns = self._query_single_full(pkg)
                results[key] = dedupe_vulns(vulns)
                self.cache.put(*key, results[key])
                time.sleep(0.05)
        if pending and self.offline:
            results.update((p.query_key(), []) for p in pending)
        else:
            for key, vulns in results.items():
                results[key] = dedupe_vulns(vulns)
        return results

    def _query_single_full(self, pkg) -> list:
        """Query one package/version, following pagination and resolving
        abbreviated `{id, modified}` entries to full advisory records."""
        body = {
            "package": {"ecosystem": pkg.ecosystem, "name": pkg.name},
            "version": pkg.version,
        }
        entries: list = []
        page_token = None
        try:
            while True:
                params = {"page_token": page_token} if page_token else None
                resp = self.session.post(
                    OSV_QUERY, json=body, params=params, timeout=self.timeout
                )
                if resp.status_code == 404:
                    break  # package/version not found at all
                if resp.status_code != 200:
                    raise OSVError(
                        f"OSV API returned HTTP {resp.status_code}: {resp.text[:200]}"
                    )
                data = resp.json()
                entries.extend(data.get("vulns") or [])
                page_token = data.get("next_page_token")
                if not page_token:
                    break
        except requests.RequestException as exc:
            raise OSVError(f"OSV API unreachable: {exc}") from exc

        return self._resolve_abbreviated(entries)

    def _resolve_abbreviated(self, entries: list) -> list:
        """Fetch full records for any entry with only {id, modified}."""
        full = []
        need_ids: list[str] = []
        by_id = {}
        for entry in entries:
            if "summary" in entry:
                full.append(entry)
            else:
                by_id[entry["id"]] = entry
                need_ids.append(entry["id"])
        if need_ids:
            try:
                for vuln_id in need_ids:
                    cached = self.cache.get_vuln(vuln_id)
                    if cached is not None:
                        full.append(cached)
                        continue
                    resp = self.session.get(
                        f"{OSV_VULN}/{vuln_id}", timeout=self.timeout
                    )
                    resp.raise_for_status()
                    record = resp.json()
                    self.cache.put_vuln(vuln_id, record)
                    full.append(record)
                    time.sleep(0.05)
            except requests.RequestException as exc:
                raise OSVError(f"OSV API unreachable: {exc}") from exc
        return full

    # -- analysis ---------------------------------------------------------
    def findings_for(self, packages: list) -> list:
        vulns_by_key = self.fetch_vulns(packages)
        findings = []
        for pkg in packages:
            for vuln in vulns_by_key.get(pkg.query_key(), []):
                findings.append(
                    vuln_to_finding(vuln, pkg)
                )
        return findings


def vuln_severity(vuln: dict) -> tuple:
    """Return (severity_word, cvss_score_or_None) for an OSV vuln dict.

    The GitHub Advisory DB severity (NONE/LOW/MODERATE/HIGH/CRITICAL) is the
    most authoritative signal and is preferred. Otherwise fall back to a
    computed CVSS v3 base score when a vector is present.
    """
    v3_scores = []
    for sev in vuln.get("severity", []) or []:
        if sev.get("type", "").upper().startswith("CVSS_V3"):
            score = cvss_base_score(sev.get("score") or "")
            if score is not None:
                v3_scores.append(score)
    db_severity = (vuln.get("database_specific") or {}).get("severity", "")

    best_score = max(v3_scores) if v3_scores else None
    if db_severity:
        word = score_severity(None, db_severity)
        return word, best_score
    return score_severity(best_score, "medium"), best_score


def dedupe_vulns(vulns: list) -> list:
    """Collapse multiple advisories that describe the same CVE.

    The OSV database frequently carries the same CVE as both a GHSA and a
    PYSEC/NVD record. Reporting both is noisy; we keep the single most
    informative record per CVE (GHSA preferred, then higher severity).
    """
    def keys(v: dict):
        k = {(v.get("id") or "").lower()}
        for alias in v.get("aliases", []) or []:
            k.add(str(alias).lower())
        return k

    def preference(v: dict) -> tuple:
        sev, _ = vuln_severity(v)
        is_ghsa = (v.get("id") or "").startswith("GHSA")
        return (0 if is_ghsa else 1, severity_score(sev), v.get("modified") or "")

    chosen: list = []
    index: dict = {}
    for v in vulns:
        kset = keys(v)
        pos = next((index[k] for k in kset if k in index), None)
        if pos is None:
            pos = len(chosen)
            chosen.append(v)
            for k in kset:
                index[k] = pos
            continue
        current = chosen[pos]
        if preference(v) < preference(current):
            chosen[pos] = v
            for k in kset:
                index[k] = pos
    return chosen


def primary_id(vuln: dict) -> str:
    """Prefer the CVE alias when present, else the advisory id."""
    for alias in vuln.get("aliases", []) or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return vuln.get("id") or "UNKNOWN"


def fixed_version(vuln: dict, installed: str) -> str | None:
    """Pick the smallest fix that applies to the installed version.

    Only ECOSYSTEM ranges that contain the installed version are considered
    (introduced <= installed < fixed), so branch-incompatible fixes from
    other release lines are not suggested.
    """
    installed_k = installed_key(installed)
    candidates = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            fixed = None
            introduced = None
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed = ev["fixed"]
                if "introduced" in ev:
                    introduced = ev["introduced"]
            if introduced and installed_k < installed_key(introduced):
                continue
            if fixed and installed_k >= installed_key(fixed):
                continue  # installed version is already past this fix
            if fixed:
                candidates.append(fixed)
    if not candidates:
        return None
    return min(candidates, key=installed_key)


def installed_key(version: str):
    """Sortable key for a version string (numeric segments then suffixes)."""
    version = str(version).lstrip("v").strip()
    parts = re.split(r"[.\-+]", version)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p))
    return key


def vuln_to_finding(vuln: dict, pkg) -> Finding:
    """Map an OSV vuln dict + Package onto a unified Finding."""
    severity, score = vuln_severity(vuln)
    fixed = fixed_version(vuln, pkg.version)
    vuln_id = primary_id(vuln)
    summary = vuln.get("summary") or vuln.get("details") or ""
    if len(summary) > 160:
        summary = summary[:160] + "..."
    message = f"{vuln_id}: {summary}".strip()
    return Finding(
        scan_type="dependency",
        rule_id=vuln_id,
        severity=severity,
        file=pkg.file,
        line=pkg.line,
        message=message,
        context=pkg.name,
        extra={
            "package": pkg.name,
            "ecosystem": pkg.ecosystem,
            "installed": pkg.version,
            "fixed": fixed,
            "cvss_score": round(score, 1) if score is not None else None,
            "aliases": vuln.get("aliases", []),
        },
    )