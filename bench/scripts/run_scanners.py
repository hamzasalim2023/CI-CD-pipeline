"""Run each configured scanner against the shared fixture corpus and emit a
normalized findings report per (tool, scan_type) pair, plus timing data.

Usage:
    python bench/scripts/run_scanners.py [--tools mytool,gitleaks,...] [-o out.json]

The script auto-detects which external tools are installed and skips any that
are missing (listing them under "unavailable"). A tool can still be skipped if
its output parser is not implemented (also listed under "unavailable").

Normalized finding shape (deliberately minimal so all tools map onto it):
    {"tool", "scan_type", "file", "line", "rule", "severity"}

Output JSON: {"scans": [{"tool","scan_type","findings":[...],"runs":[sec,...]}],
              "unavailable": [...]}
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "bench" / "fixtures"
RESULTS = ROOT / "bench" / "results"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def norm(file, line, rule, severity=None):
    return {
        "file": str(file).replace("\\", "/"),
        "line": int(line) if isinstance(line, (int, float)) and line > 0 else 0,
        "rule": str(rule),
        "severity": (severity or "").lower(),
    }


def avail(tool):
    return shutil.which(tool) is not None


def run(cmd, cwd, timeout=900):
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout)
        rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return None, None, None, 0.0
    except subprocess.TimeoutExpired as exc:
        rc, stdout, stderr = 124, (exc.stdout or ""), (exc.stderr or "")
    dt = time.perf_counter() - t0
    return rc, stdout, stderr, dt


def load_mytool_json(tmp_path):
    data = json.loads(tmp_path.read_text(encoding="utf-8"))
    out = []
    for f in data.get("findings", []):
        item = norm(f.get("file"), f.get("line"),
                    f.get("rule_id") or f.get("rule"), f.get("severity"))
        item["context"] = (f.get("context") or
                           (f.get("extra") or {}).get("package") or "")
        out.append(item)
    return out


def report(tool, scan_type, findings, runs):
    return {"tool": tool, "scan_type": scan_type,
            "findings": findings, "runs": runs}


# ---------------------------------------------------------------------------
# mytool
# ---------------------------------------------------------------------------

def scan_mytool(scan_type, reps=1):
    tmp = RESULTS / f"mytool_{scan_type}.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    if scan_type == "secrets":
        cmd = [sys.executable, "-m", "mytool", "scan-secrets",
               str(FIXTURES / "secrets"), "--json"]
    elif scan_type == "deps":
        cmd = [sys.executable, "-m", "mytool", "scan-deps",
               str(FIXTURES / "deps"), "--json"]
    else:
        cmd = [sys.executable, "-m", "mytool", "scan-code",
               str(FIXTURES / "code"), "--json"]
    runs = []
    rc = None
    stdout = None
    for _ in range(reps):
        rc, out, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
        stdout = out
    tmp.write_text(stdout, encoding="utf-8")
    try:
        findings = load_mytool_json(tmp)
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] mytool {scan_type}: bad output: {exc}", file=sys.stderr)
        findings = []
    return report("mytool", scan_type, findings, runs)


# ---------------------------------------------------------------------------
# secrets tools
# ---------------------------------------------------------------------------

def scan_gitleaks(reps=1):
    """gitleaks generate|detect --format json --no-banner <path>"""
    # gitleaks needs a git repo; init a throwaway repo over the fixture copy.
    repo = RESULTS / "gitleaks_repo"
    if repo.exists():
        shutil.rmtree(repo, ignore_errors=True)
    shutil.copytree(FIXTURES / "secrets", repo)
    subprocess.run(["git", "init", "-q"], cwd=str(repo), check=False,
                   capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=str(repo), check=False,
                   capture_output=True)
    subprocess.run(["git", "-c", "user.email=b@b", "-c", "user.name=b",
                    "commit", "-qm", "init"], cwd=str(repo), check=False,
                   capture_output=True)
    cmd = ["gitleaks", "detect", "--source", str(repo), "--report-format", "json",
           "--report-path", str(RESULTS / "gitleaks.json"), "--no-banner"]
    runs = []
    rc = None
    for _ in range(reps):
        rc, _, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
    findings = []
    try:
        data = json.loads((RESULTS / "gitleaks.json").read_text(encoding="utf-8"))
        for f in data.get("Findings", data if isinstance(data, list) else []):
            findings.append(norm(f.get("File"), f.get("StartLine"),
                                 f.get("RuleID"), f.get("Severity")))
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] gitleaks parse: {exc}", file=sys.stderr)
    return report("gitleaks", "secrets", findings, runs)


def scan_trufflehog(reps=1):
    """trufflehog filesystem --json <path>"""
    cmd = ["trufflehog", "filesystem", str(FIXTURES / "secrets"), "--json"]
    runs = []
    rc = None
    stdout = None
    for _ in range(reps):
        rc, stdout, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
    findings = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        loc = rec.get("SourceMetadata", {}).get("Data", {}).get("Filesystem",
                                                                {}) or {}
        findings.append(norm(loc.get("file"), loc.get("line"),
                             rec.get("DetectorName") or rec.get("DecoderType"),
                             "critical" if rec.get("Verified") is True else None))
    return report("trufflehog", "secrets", findings, runs)


# ---------------------------------------------------------------------------
# deps tools
# ---------------------------------------------------------------------------

def scan_osv_scanner(reps=1):
    """osv-scanner -r --format json <dir>"""
    cmd = ["osv-scanner", "-r", "--format", "json", str(FIXTURES / "deps")]
    runs = []
    rc = None
    stdout = None
    for _ in range(reps):
        rc, stdout, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
    findings = []
    try:
        data = json.loads(stdout)
        for res in data.get("results", []):
            for v in res.get("vulnerabilities", []):
                ids = v.get("id", "")
                pkg = ((v.get("vulnerability", {}).get("affected", [{}])[0]
                        .get("package", {}).get("name", "")))
                loc = v.get("locations", [{}])
                fname = loc[0].get("path", "") if loc else ""
                item = norm(fname, loc[0].get("start", {}).get("line")
                            if loc else None, ids, "high")
                item["context"] = pkg
                findings.append(item)
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] osv-scanner parse: {exc}", file=sys.stderr)
    return report("osv-scanner", "deps", findings, runs)


def scan_trivy(reps=1):
    cmd = ["trivy", "fs", "--format", "json", "--scanners", "vuln",
           str(FIXTURES / "deps")]
    runs = []
    rc = None
    stdout = None
    for _ in range(reps):
        rc, stdout, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
    findings = []
    try:
        data = json.loads(stdout)
        for res in data.get("Results", []):
            target = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                item = norm(target, None, v.get("VulnerabilityID"), v.get("Severity"))
                item["context"] = v.get("PkgName") or ""
                findings.append(item)
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] trivy parse: {exc}", file=sys.stderr)
    return report("trivy", "deps", findings, runs)


# ---------------------------------------------------------------------------
# code tools
# ---------------------------------------------------------------------------

def scan_bandit(reps=1):
    tmp = RESULTS / "bandit.json"
    cmd = ["bandit", "-r", str(FIXTURES / "code"), "-f", "json", "-o",
           str(tmp)]
    runs = []
    rc = None
    for _ in range(reps):
        rc, _, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
    findings = []
    try:
        data = json.loads(tmp.read_text(encoding="utf-8"))
        for res in data.get("results", []):
            findings.append(norm(res.get("filename"), res.get("line_number"),
                                 res.get("test_id"), res.get("issue_severity")))
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] bandit parse: {exc}", file=sys.stderr)
    return report("bandit", "code", findings, runs)


def scan_semgrep(reps=1):
    cmd = ["semgrep", "--json", "--config", "p/security-audit",
           str(FIXTURES / "code")]
    runs = []
    rc = None
    stdout = None
    for _ in range(reps):
        rc, stdout, _, dt = run(cmd, ROOT)
        if rc is None:
            return None
        runs.append(dt)
    findings = []
    try:
        data = json.loads(stdout)
        for res in data.get("results", []):
            findings.append(norm(res.get("path"), res.get("start", {}).get("line"),
                                 res.get("check_id"),
                                 res.get("extra", {}).get("severity")))
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] semgrep parse: {exc}", file=sys.stderr)
    return report("semgrep", "code", findings, runs)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools",
                    default="mytool,gitleaks,trufflehog,osv-scanner,trivy,bandit,semgrep")
    ap.add_argument("--reps", type=int, default=1, help="Repeat each scan this many times")
    ap.add_argument("-o", "--out", default=str(RESULTS / "scans.json"))
    args = ap.parse_args()

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    scans, unavailable = [], []

    drivers = {
        "mytool": lambda: [s for st in ("secrets", "deps", "code")
                           if (s := scan_mytool(st, args.reps)) is not None],
        "gitleaks": lambda: scan_gitleaks(args.reps),
        "trufflehog": lambda: scan_trufflehog(args.reps),
        "osv-scanner": lambda: scan_osv_scanner(args.reps),
        "trivy": lambda: scan_trivy(args.reps),
        "bandit": lambda: scan_bandit(args.reps),
        "semgrep": lambda: scan_semgrep(args.reps),
    }

    for tool in tools:
        if tool not in drivers:
            unavailable.append(f"{tool} (unknown tool)")
            continue
        if tool != "mytool" and not avail(tool):
            unavailable.append(f"{tool} (not installed)")
            continue
        result = drivers[tool]()
        if result is None:
            unavailable.append(f"{tool} (failed to run)")
        elif isinstance(result, list):
            scans.extend(result)
        else:
            scans.append(result)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(
        {"scans": scans, "unavailable": unavailable, "note":
            "Tools under 'unavailable' were not installed or not runnable."},
        indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {out_path}")
    print(f"Unavailable: {unavailable or 'none'}")
    for s in scans:
        runs = s["runs"] or [0.0]
        print(f"  {s['tool']:12} {s['scan_type']:8} "
              f"{len(s['findings']):4} findings  "
              f"{min(runs)*1000:7.0f} ms (min of {len(runs)})")


if __name__ == "__main__":
    main()
