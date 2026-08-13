"""Milestone 2: `mytool scan-deps` - vulnerable dependency detection via OSV."""

import os

from mytool.commands.common import exit_for_findings, write_output
from mytool.deps.cache import OSVCache
from mytool.deps.parsers import (
    discover_manifests,
    parse_manifest_text,
)
from mytool.deps.scanner import OSVError, DependencyScanner


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "scan-deps",
        help="Check dependencies against the OSV vulnerability database.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Manifest file, or directory to auto-discover manifests in.",
    )
    parser.add_argument("-j", "--json", action="store_true", help="JSON output.")
    parser.add_argument("-o", "--output", help="Write JSON report to this file.")
    parser.add_argument(
        "--fail-on",
        default="high",
        help="Comma-separated severities that fail the build (default: high).",
    )
    parser.add_argument(
        "--cache-dir", help="Directory for the SQLite query cache."
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
        help="Use only cached responses; never call the OSV API.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore the cache and re-query the OSV API.",
    )
    parser.set_defaults(func=run_scan_deps)


def load_packages(path: str) -> list:
    """Parse a single manifest file or discover + parse all under a dir."""
    packages = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = discover_manifests(path)
    else:
        files = []
    for filespec in files:
        try:
            with open(filespec, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        packages.extend(parse_manifest_text(text, filespec))
    return packages


def run_scan_deps(args) -> int:
    packages = load_packages(args.path)
    if args.json and not args.output:
        pass
    cache = OSVCache(args.cache_dir, ttl_hours=args.ttl_hours)
    scanner = DependencyScanner(
        cache=cache, offline=args.offline, refresh=args.refresh,
    )
    try:
        findings = scanner.findings_for(packages)
    except OSVError as exc:
        print(f"error: {exc}")
        return 2
    finally:
        cache.close()

    ordered = write_output(
        findings, as_json=args.json, out_file=args.output,
    )
    if not args.json and findings:
        packages_with_issues = len({f.extra.get("package") for f in findings})
        print(
            f"\n[dim]{len(findings)} vulnerable version(s) across "
            f"{packages_with_issues} package(s) - severity above threshold "
            f"would fail the build.[/dim]"
        )
    elif not args.json:
        print(f"[dim]Checked {len(packages)} package(s) against the OSV database.[/dim]")
    return exit_for_findings(findings, args.fail_on)