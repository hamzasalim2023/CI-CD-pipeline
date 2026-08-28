"""Score the normalized scan results (bench/results/scans.json) against the
ground-truth golden baselines and print a comparison table:
precision / recall / F1 per tool, plus wall-clock runtime.

Usage:
    python bench/scripts/evaluate.py [--scans path] [--json]

Matching rules:
  * secrets & code : a finding is a true positive if its LINE is in the
    golden findings set for that scan_type. Any finding not on a ground-truth
    line (including decoy lines) is a false positive.
  * deps           : a finding is a true positive if the package name matches
    a golden vulnerable package. Findings on 'clean' packages are FPs.

Multiple findings on the same line/package are collapsed to one before scoring,
so tools with verbose rule sets are not penalised for double-reporting.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDENS = ROOT / "bench" / "goldens"
DEFAULT_SCANS = ROOT / "bench" / "results" / "scans.json"


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def golden_for(scan_type):
    return load_json(GOLDENS / f"{scan_type}.json")


def key_for(scan_type, finding):
    if scan_type == "deps":
        pkg = finding.get("context") or finding.get("rule")
        return str(pkg or "").split(":")[0].strip().lower()
    return finding.get("line")


def score(scan_type, findings, golden):
    if scan_type == "deps":
        tp_set = set(p["name"].lower() for p in golden["findings"]["packages"])
        clean_set = set(p["name"].lower()
                        for p in golden.get("clean", {}).get("packages", []))
    else:
        tp_set = set(golden["findings"]["lines"])
        clean_set = set(golden.get("decoys", {}).get("lines", []))

    # Collapse duplicate keys per tool.
    keys = set()
    for f in findings:
        k = key_for(scan_type, f)
        if k is None:
            continue
        if isinstance(k, int) and k <= 0:
            continue
        if scan_type == "deps" and k == "":
            continue
        keys.add(k)

    tp = len(keys & tp_set)
    fp = len(keys - tp_set)  # includes decoys and other-stray findings
    fn = len(tp_set - keys)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scans", default=str(DEFAULT_SCANS))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    data = load_json(args.scans)
    scans = data.get("scans", [])
    unavailable = data.get("unavailable", [])

    rows = []
    for s in scans:
        tool, st, findings, runs = s["tool"], s["scan_type"], s["findings"], s["runs"]
        golden = golden_for(st)
        metrics = score(st, findings, golden)
        best = min(runs) if runs else 0.0
        rows.append({"tool": tool, "scan_type": st, **metrics,
                     "best_ms": best * 1000, "n_findings": len(findings)})

    if args.json:
        print(json.dumps({"rows": rows, "unavailable": unavailable}, indent=2))
        return

    # Plain-text table
    header = f"{'tool':14} {'type':8} {'TP':>3} {'FP':>3} {'FN':>3} " \
             f"{'precision':>9} {'recall':>6} {'F1':>5} {'time(ms)':>9}"
    print(header)
    print("-" * len(header))
    for r in sorted(rows, key=lambda x: (x["scan_type"], -x["f1"])):
        print(f"{r['tool']:14} {r['scan_type']:8} {r['tp']:3} {r['fp']:3} "
              f"{r['fn']:3} {r['precision']:9.2%} {r['recall']:6.2%} "
              f"{r['f1']:5.3f} {r['best_ms']:9.0f}")
    if unavailable:
        print(f"\nUnavailable / not run: {', '.join(unavailable)}")


if __name__ == "__main__":
    main()
