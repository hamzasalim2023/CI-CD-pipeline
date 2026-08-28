"""Verify which pinned packages in the dep fixture manifests have OSV
advisories, write the advisory reference (bench/goldens/deps-advisories.json),
and cross-check against the ground-truth baseline (bench/goldens/deps.json).

Run:  python bench/scripts/verify_deps.py
"""
import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "bench" / "fixtures" / "deps"
GOLDEN = ROOT / "bench" / "goldens" / "deps.json"
ADVISORY_REF = ROOT / "bench" / "goldens" / "deps-advisories.json"

PACKAGES = [
    # (ecosystem, name, version, source file)
    ("PyPI", "flask", "0.12.2", "requirements.txt"),
    ("PyPI", "django", "2.0.7", "requirements.txt"),
    ("PyPI", "urllib3", "1.24.1", "requirements.txt"),
    ("PyPI", "redis", "2.10.5", "requirements.txt"),
    ("PyPI", "Pillow", "6.2.0", "requirements.txt"),
    ("PyPI", "boto3", "1.9.254", "requirements.txt"),
    ("PyPI", "certifi", "2017.4.17", "requirements.txt"),
    ("npm", "lodash", "4.17.19", "package.json"),
    ("npm", "minimist", "0.0.8", "package.json"),
    ("npm", "yargs-parser", "13.0.0", "package.json"),
    ("npm", "tar", "4.4.8", "package.json"),
    ("npm", "axios", "0.18.1", "package.json"),
    ("npm", "mixin-deep", "1.3.1", "package.json"),
    ("npm", "serialize-javascript", "2.1.1", "package.json"),
    ("npm", "dot-prop", "4.2.0", "package.json"),
    ("npm", "debug", "2.6.8", "package.json"),
    ("npm", "ms", "2.1.1", "package.json"),
    ("Go", "golang.org/x/text", "v0.3.0", "go.mod"),
    ("Go", "gopkg.in/yaml.v2", "v2.2.2", "go.mod"),
    ("Go", "github.com/gin-gonic/gin", "v1.6.3", "go.mod"),
    ("Go", "github.com/gorilla/websocket", "v1.4.0", "go.mod"),
    ("Go", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible", "go.mod"),
    ("Go", "github.com/hashicorp/go-retryablehttp", "v0.5.4", "go.mod"),
    ("Go", "github.com/nats-io/nats-server/v2", "v2.1.8", "go.mod"),
    ("Go", "github.com/ulikunitz/xz", "v0.5.6", "go.mod"),
]

OSV_QUERY = "https://api.osv.dev/v1/query"


def query(osv_ecosystem, name, version):
    payload = {
        "package": {"ecosystem": osv_ecosystem, "name": name},
        "version": version,
    }
    resp = requests.post(OSV_QUERY, json=payload, timeout=30)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    return [v["id"] for v in resp.json().get("vulns") or []]


def main():
    ref = {"fixtures": {}}
    for ecosystem, name, version, source in PACKAGES:
        try:
            vulns = query(ecosystem, name, version)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] error {ecosystem}:{name}@{version}: {exc}", file=sys.stderr)
            vulns = []
        status = "VULNERABLE" if vulns else "clean"
        print(f"{status:10} {ecosystem:6} {name}@{version} ({len(vulns)} advisories)")
        entry = {"name": name, "version": version, "ecosystem": ecosystem,
                 "file": source, "advisories": vulns}
        ref["fixtures"].setdefault(source, []).append(entry)

    ADVISORY_REF.parent.mkdir(parents=True, exist_ok=True)
    ADVISORY_REF.write_text(json.dumps(ref, indent=2) + "\n")
    print(f"\nWrote advisory reference {ADVISORY_REF}")

    if GOLDEN.exists():
        gt = json.loads(GOLDEN.read_text(encoding="utf-8"))
        gt_vuln = {p["name"].lower() for p in gt["findings"]["packages"]}
        gt_clean = {p["name"].lower() for p in gt.get("clean", {}).get("packages", [])}
        osv_vuln = {e["name"].lower() for e in ref["fixtures"].values()
                    for e in e if e["advisories"]}
        osv_clean = {e["name"].lower() for e in ref["fixtures"].values()
                     for e in e if not e["advisories"]}
        problems = []
        if gt_vuln - osv_vuln:
            problems.append(f"in ground truth but OSV says CLEAN: "
                            f"{sorted(gt_vuln - osv_vuln)}")
        if gt_clean - osv_clean:
            problems.append(f"in ground truth 'clean' but OSV says VULNERABLE: "
                            f"{sorted(gt_clean - osv_clean)}")
        if problems:
            print("\n[!] Ground truth does NOT match live OSV data:")
            for p in problems:
                print("    -", p)
            sys.exit(1)
        print("\nGround truth (bench/goldens/deps.json) matches live OSV data OK.")


if __name__ == "__main__":
    main()
