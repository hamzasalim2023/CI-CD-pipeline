"""Milestone 1: `mytool scan-secrets` - hardcoded secrets detection."""

import os

from mytool.commands.common import exit_for_findings, filter_changed, write_output
from mytool.config import load_config, process_findings
from mytool.diff import GitError, added_lines
from mytool.secrets.detector import scan_lines, scan_path


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "scan-secrets",
        help="Detect hardcoded secrets, API keys, tokens and credentials.",
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
            "Scan only the lines added in a diff. With one argument it scans "
            "that ref vs the working tree / HEAD (e.g. `--diff origin/main`). "
            "With two arguments it scans a range (e.g. `--diff HEAD~1 HEAD`)."
        ),
    )
    parser.add_argument("-j", "--json", action="store_true", help="JSON output.")
    parser.add_argument(
        "--sarif", action="store_true", help="SARIF 2.1.0 report output."
    )
    parser.add_argument("-o", "--output", help="Write report to this file.")
    parser.add_argument(
        "--fail-on",
        default="high",
        help="Comma-separated severities that fail the build (default: high).",
    )
    parser.add_argument(
        "--config",
        help="Path to a mytool.toml config file (default: discovered upward "
             "from the scan path).",
    )
    parser.set_defaults(func=run_scan_secrets, fail_on=None)


def run_scan_secrets(args) -> int:
    cfg = load_config(getattr(args, "config", None), start=args.path)
    fail_on = getattr(args, "fail_on", None) or cfg.fail_on
    sarif = getattr(args, "sarif", False)
    findings = []
    if args.diff:
        base = args.diff[0]
        ref = args.diff[1] if len(args.diff) > 1 else None
        try:
            changed = added_lines(base, ref)
        except GitError as exc:
            print(f"error: {exc}")
            return 2
        changed = filter_changed(changed, args.path)
        for file, lines in sorted(changed.items()):
            findings.extend(scan_lines(lines, file))
    else:
        path = args.path
        if not os.path.exists(path):
            print(f"error: path does not exist: {path}")
            return 2
        findings = scan_path(path)

    findings = process_findings(findings, cfg)
    if cfg.source:
        print(f"[dim]Using config: {cfg.source}[/dim]")
    ordered = write_output(
        findings, as_json=args.json, out_file=args.output, sarif=sarif,
    )
    if not args.json and not sarif and findings:
        print(
            f"\n[dim]{len(findings)} secret(s) detected - severity above "
            f"threshold would fail the build.[/dim]"
        )
    return exit_for_findings(findings, fail_on)