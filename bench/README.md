# Benchmark harness

A reproducible way to compare **mytool** against other vulnerability scanners on
three axes:

1. **Detection accuracy** — precision / recall / F1 against curated ground truth.
2. **Performance** — wall-clock time per scan (best of N repeats).
3. **Coverage** — which scan types each tool actually detects.

Everything is scripted; run two commands and read the table.

## Layout

```
bench/
  fixtures/
    secrets/app_config.py   # planted real-format fake secrets + decoys
    code/app.py             # insecure python patterns + safe decoys
    deps/                   # manifests pinned to known-vulnerable versions
      requirements.txt
      package.json
      go.mod
  goldens/
    secrets.json            # line-level ground truth for secrets
    code.json               # line-level ground truth for code
    deps.json               # package-level ground truth for dependencies
    deps-advisories.json    # advisory reference generated from live OSV API
  scripts/
    run_scanners.py         # run each scanner, normalize output, time it
    evaluate.py             # score results vs goldens -> comparison table
    verify_deps.py          # regenerate deps-advisories + sanity-check goldens
  results/                  # generated: per-tool JSON + combined scans.json
```

## Requirements

* Python 3.10+ with `mytool` installed (see repo README) and `requests`.
* The optional competitor binaries you want to compare, on `PATH`:

| scan type | mytool | competitors (optional) |
|-----------|--------|------------------------|
| secrets   | `scan-secrets` | `gitleaks`, `trufflehog` |
| deps      | `scan-deps`    | `osv-scanner`, `trivy`   |
| code      | `scan-code`    | `bandit`, `semgrep`      |

Any competitor that is not installed is detected and skipped (listed as
"unavailable"); the remaining tools are still scored.

## Quick start

```bash
# 1. Run every available scanner against the fixtures (3 reps for stable timing).
python bench/scripts/run_scanners.py --reps 3

# 2. Score detection accuracy and print the comparison table.
python bench/scripts/evaluate.py
```

Example output:

```
tool           type      TP  FP  FN precision recall    F1  time(ms)
--------------------------------------------------------------------
mytool         code      10   0   0   100.00% 100.00% 1.000       823
mytool         deps      22   0   0   100.00% 100.00% 1.000       822
mytool         secrets   24   0   0   100.00% 100.00% 1.000       800
gitleaks       secrets   ...                                        ...
```

`time(ms)` is the *minimum* measured over the runs (best warm-cache time).
For dependency scans, run `--reps 3` once first to populate the OSV cache, then
re-run so the "warm cache" figure reflects a CI-type repeat scan rather than the
one-off cold-cache API pull.

## Interpreting the metrics

* **TP**: finding on a ground-truth line (secrets/code) or a vulnerable package (deps).
* **FP**: finding on a decoy / non-ground-truth line, or a "clean" package.
* **FN**: a ground-truth line / vulnerable package the tool missed.
* **Precision** = TP/(TP+FP) — how much of what a tool reports is real.
* **Recall**    = TP/(TP+FN) — how much of the real issues the tool catches.
* **F1**        = harmonic mean of precision and recall.

Deliberately, multiple findings on the same line/package are collapsed to one
before scoring, so a tool that reports both a specific rule *and* a generic
"high entropy" hit for the same secret is not penalised for double-reporting.

## Which competitors are compared against what

* `gitleaks`, `trufflehog` -> `secrets` fixtures.
* `osv-scanner`, `trivy`  -> `deps` fixtures (same OSV database as mytool).
* `bandit`, `semgrep`     -> `code` fixtures.

## Making the results credible (tips)

* Fix all tool versions in a `requirements`/`go install @version` / container
  image and record them alongside the run.
* Pre-warm caches (OSV for deps; gitleaks/trufflehog have none) and use
  `--reps 5` so timing is not noise-dominated.
* For an apples-to-apples *detection* claim, prefer the golden corpus here; for
  *scale*, add a large real monorepo and run the same tools over it (the
  evaluator's recall needs a golden, so scale tests measure runtime, not F1).
* Re-run `python bench/scripts/verify_deps.py` when you bump fixture versions —
  it confirms the dependency golden still matches the live OSV API and fails if
  a package's advisories change.

## Extending

* Add a new scan type: create `bench/fixtures/<type>/`, a `goldens/<type>.json`
  with `findings.lines` (+ optional `decoys.lines`), and a `scan_<tool>()`
  driver in `run_scanners.py` plus its entry in the `drivers` dict.
* Add a competitor: implement its normalizer (parse its JSON output into the
  normalized finding shape) and register it in `drivers`.

## Fabricated-fixture caveat

The secrets and code fixtures are hand-crafted to match well-known rule sets
(e.g. Gitleaks/TruffleHog secret prefixes, Bandit/Semgrep code patterns). They
exercise the common, documented detections. For a fully realistic picture,
supplement with a golden-labelled subset of a real product repository — the
harness scores any labelled corpus you point it at.
