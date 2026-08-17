"""Milestone 4: `mytool scan` - run all three scanners and aggregate findings."""

import os

from mytool.commands import deps as deps_cmd
from mytool.commands.common import exit_for_findings, filter_changed, write_output
from mytool.deps.cache import OSVCache
from mytool.deps.parsers import MANIFEST_KINDS, parse_manifest_text
from mytool.deps.scanner import OSVError, DependencyScanner
from mytool.diff import GitError, added_lines
from mytool.sast.checker import scan_path as sast_scan_path
from mytool.sast.checker import scan_text as sast_scan_text
from mytool.secrets.detector import scan_path as secret_scan_path
from mytool.secrets.detector import scan_lines as secret_scan_lines


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "scan",
        help="Run every scanner (secrets, dependencies, code) and aggregate.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory or file to scan (default: current directory).",
    )
    parser.add_argument(
        "--diff",
        nargs="*",
        metavar="REF",
        help=(
            "Scan only what a diff introduces. One argument scans that ref vs "
            "the working tree / HEAD (e.g. `--diff origin/main`); two arguments "
            "scan a range (e.g. `--diff HEAD~1 HEAD`)."
        ),
    )
    parser.add_argument("-j", "--json", action="store_true", help="JSON output.")
    parser.add_argument("-o", "--output", help="Write JSON report to this file.")
    parser.add_argument(
        "--fail-on",
        default="high",
        help="Comma-separated severities that fail the build (default: high).",
    )
    parser.add_argument(
        "--no-secrets", action="store_true", help="Skip the secrets scan."
    )
    parser.add_argument(
        "--no-deps", action="store_true", help="Skip the dependency scan."
    )
    parser.add_argument(
        "--no-code", action="store_true", help="Skip the SAST code scan."
    )
    parser.add_argument(
        "--cache-dir", help="Directory for the SQLite OSV query cache."
    )
    parser.add_argument(
        "--ttl-hours",
        type=float,
        default=24.0,
        help="How long to keep OSV responses cached (default: 24h).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use only cached OSV responses; never call the API.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore the cache and re-query the OSV API.",
    )
    parser.set_defaults(func=run_scan)


def _changed_files(args):
    """Return the diff's changed-file dict, or None when not in diff mode."""
    if not args.diff:
        return None
    base = args.diff[0]
    ref = args.diff[1] if len(args.diff) > 1 else None
    try:
        return added_lines(base, ref)
    except GitError as exc:
        print(f"error: {exc}")
        return "ERROR"


def _secrets_findings(args, changed) -> list:
    if changed is not None:
        changed = filter_changed(changed, args.path)
        findings = []
        for file, lines in sorted(changed.items()):
            findings.extend(secret_scan_lines(lines, file))
        return findings
    if not os.path.exists(args.path):
        return []
    return secret_scan_path(args.path)


def _code_findings(args, changed) -> list:
    if changed is not None:
        changed = filter_changed(changed, args.path)
        findings = []
        for file in changed:
            if not file.endswith(".py") or not os.path.isfile(file):
                continue
            try:
                with open(file, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            findings.extend(sast_scan_text(text, file))
        return findings
    if not os.path.exists(args.path):
        return []
    return sast_scan_path(args.path)


def _deps_findings(args, changed) -> list:
    cache = OSVCache(args.cache_dir, ttl_hours=args.ttl_hours)
    scanner = DependencyScanner(
        cache=cache, offline=args.offline, refresh=args.refresh,
    )
    try:
        if changed is not None:
            changed = filter_changed(changed, args.path)
            files = [
                f for f in changed
                if os.path.basename(f) in MANIFEST_KINDS and os.path.isfile(f)
            ]
            packages = _load_manifests(files)
        else:
            packages = deps_cmd.load_packages(args.path)
        findings = scanner.findings_for(packages)
    except OSVError as exc:
        cache.close()
        print(f"error: {exc}")
        return None
    cache.close()
    return findings


def _load_manifests(files: list) -> list:
    packages = []
    for filespec in files:
        try:
            with open(filespec, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        packages.extend(parse_manifest_text(text, filespec))
    return packages


def run_scan(args) -> int:
    changed = _changed_files(args)
    if changed == "ERROR":
        return 2

    findings = []
    if not args.no_secrets:
        findings.extend(_secrets_findings(args, changed))
    if not args.no_deps:
        deps = _deps_findings(args, changed)
        if deps is None:
            return 2
        findings.extend(deps)
    if not args.no_code:
        findings.extend(_code_findings(args, changed))

    ordered = write_output(
        findings, as_json=args.json, out_file=args.output,
    )
    if not args.json and findings:
        by_type = {}
        for f in ordered:
            by_type[f.scan_type] = by_type.get(f.scan_type, 0) + 1
        summary = ", ".join(f"{n} {kind}" for kind, n in sorted(by_type.items()))
        print(
            f"\n[dim]{len(ordered)} finding(s): {summary} - severity above "
            f"threshold would fail the build.[/dim]"
        )
    return exit_for_findings(findings, args.fail_on)