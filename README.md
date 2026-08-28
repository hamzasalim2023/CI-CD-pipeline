# CI/CD pipeline security scanner

A stateless CLI that runs in CI (as a GitHub Action, GitLab CI job, or
standalone) and scans a repository for three classes of issues:

| Scan | What it finds |
|------|---------------|
| **Secrets** (`scan-secrets`) | Hardcoded credentials: AWS keys, GitHub/GitLab tokens, Slack webhooks, JWTs, high-entropy strings |
| **Dependencies** (`scan-deps`) | Dependency manifests checked against the OSV vulnerability database (PyPI, npm, Go, Pipfile, Poetry) |
| **Code** (`scan-code`) | Insecure Python patterns via AST analysis: `eval`/`exec`, SQL injection, `shell=True`, `verify=False`, `pickle.load`, TLS verification disabled |

Each scan either fails the build (non-zero exit) or posts a machine-readable
JSON report, depending on the documented exit codes.

## Install

Requires Python 3.10+.

```bash
pip install .
# or, for development / running the test suite:
pip install -e ".[dev]"
```

## Quick start

```bash
# Run all three scanners on the current directory.
mytool scan .                # human-readable table, exit 1 on high/critical findings
mytool scan . --json         # JSON to stdout
mytool scan . -o report.json # JSON to a file (stdout keeps the summary)

# Run one scanner at a time.
mytool scan-secrets src/
mytool scan-deps .           # checks every supported manifest under '.'
mytool scan-code app.py      # AST analysis of a single file works too
```

### Scan only what a commit/PR introduces

Pass a git ref to `--diff` and only the lines (secrets) or files (code)
changed since that ref are analyzed, so pre-existing issues in the codebase
never block a build:

```bash
mytool scan --diff origin/main          # working tree vs. a branch
mytool scan --diff HEAD~1 HEAD          # a commit range
mytool scan-code --diff HEAD~1          # single-file command, same syntax
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the threshold (or nothing to scan) |
| `1` | At least one finding at or above the threshold — fail the build |
| `2` | Error (bad path, git unavailable, OSV API failure) |

Severities, in descending order: `critical`, `high`, `medium`, `low`, `info`.
The default threshold is `high`; override per run with `--fail-on medium`.

## Configuration (`mytool.toml`)

Behaviour can be codified in a `mytool.toml` file. It is auto-discovered by
walking upward from the scanned path (or pointed to explicitly with
`--config <path>`). Command-line flags always override the config file.

```toml
fail-on = "medium"          # default severity threshold
cache-dir = ".ci-scanner-cache"   # OSV cache location
ttl-hours = 24.0
offline = false             # never query the OSV API (use cache only)
refresh = false             # ignore the cache and re-query the API

# Restrict which paths are scanned (file prefixes or fnmatch globs).
include = ["src"]
exclude = ["tests/fixtures", "generated/**"]

# Suppress specific findings. Any combination of filters may be used;
# all supplied filters must match for an entry to apply.
[[allow]]
scan = "secret"             # secret | dependency | code
rule = "secret-generic-api-key"
file = "tests/**"
line = 42
value = "example"           # case-insensitive match against finding context
```

## GitHub Action

The repository ships a composite action that installs mytool, scans a diff
(or the whole tree), and uploads the JSON report:

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0                      # needed for --diff
  - uses: <your-org>/<repo>@v1
    with:
      diff: origin/main                   # scan only changes vs. the base
      fail-on: high
      # no-deps: "true"                  # skip the OSV API scan
      # path: src                        # default: repository root
```

Or call the CLI directly in your own workflow:

```yaml
- run: pip install .
- run: mytool scan . --diff origin/main --fail-on high -o mytool-report.json
- if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: mytool-report
    path: mytool-report.json
```

## GitLab CI

```yaml
security-scan:
  image: python:3.11
  stage: test
  script:
    - pip install .
    - mytool scan . --fail-on high -o mytool-report.json
  artifacts:
    when: always
    expire_in: 1 week
    paths:
      - mytool-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## Development

```bash
pip install -e .
python -m pytest
```

The test suite uses fixtures under `tests/fixtures/`. Note that the fixtures
contain intentionally vulnerable code and fake credentials for the scanners to
find.

## Benchmarking against other scanners

A reproducible harness lives in `bench/` for comparing mytool with other
vulnerability scanners on detection accuracy (precision / recall / F1) and
performance (wall-clock time). It runs mytool plus any competitor binaries you
install (`gitleaks`, `trufflehog`, `osv-scanner`, `trivy`, `bandit`, `semgrep`)
over a curated vulnerable fixture corpus and scores them against ground-truth
golden baselines.

```bash
python bench/scripts/run_scanners.py --reps 3   # run all available scanners
python bench/scripts/evaluate.py                # print the comparison table
python bench/scripts/verify_deps.py             # sanity-check the dependency golden
```

See [`bench/README.md`](bench/README.md) for the full details. Generated scan
output under `bench/results/` is git-ignored; the fixtures and goldens are
committed.
