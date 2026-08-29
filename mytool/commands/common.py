"""Shared output helpers for CLI commands (human table + JSON)."""

import json
import os
import sys

from rich.console import Console
from rich.table import Table

console = Console()


def filter_changed(changed: dict, path: str) -> dict:
    """Restrict a diff's changed-file dict to a given path prefix."""
    if path in (".", os.curdir):
        return changed
    prefix = os.path.normpath(path).replace("\\", "/")
    return {f: lines for f, lines in changed.items() if f == prefix or f.startswith(prefix + "/")}


def print_findings_table(findings) -> None:
    if not findings:
        console.print("[green]No issues found.[/green]")
        return
    table = Table(title=f"Findings ({len(findings)})", show_lines=False)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Type")
    table.add_column("Rule")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Detail")

    color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "blue"}
    for f in findings:
        table.add_row(
            f"[{color.get(f.severity, 'white')}]{f.severity.upper()}[/]",
            f.scan_type,
            f.rule_id,
            f.file,
            str(f.line),
            f.message,
        )
    console.print(table)


def print_json(data) -> None:
    print(json.dumps(data, indent=2, default=str))


def write_output(findings, as_json: bool, out_file: str | None, sarif: bool = False) -> list:
    """Render findings to stdout (and/or a file) in the requested format and
    return the finding list.

    Format priority: SARIF (--sarif) > JSON (--json) > human table.
    When `out_file` is given, the machine-readable report is written there for
    CI parsing; stdout shows the human summary unless a stdout format flag was
    explicitly requested. When no `out_file` is given, the chosen format is
    printed to stdout.
    """
    ordered = sorted(
        findings, key=lambda f: (-models_severity(f), f.file, f.line)
    )

    if sarif:
        from mytool.sarif import build_sarif

        report = build_sarif(ordered)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
        if as_json or not out_file:
            print_json(report)
        if not as_json and out_file:
            print_findings_table(ordered)
        return ordered

    if as_json or out_file:
        payload = {
            "scanner": "mytool",
            "findings": [f.as_dict() for f in ordered],
            "count": len(ordered),
        }
        if out_file:
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        if as_json:
            print_json(payload)
    if not as_json:
        print_findings_table(ordered)
    return ordered


def models_severity(finding) -> int:
    from mytool.models import severity_score

    return severity_score(finding.severity)


def exit_for_findings(findings, fail_on: str) -> int:
    """CI-facing exit codes:
    0 -> no findings at/above the threshold
    1 -> findings at/above the threshold (fail the build)
    """
    from mytool.models import severity_score, threshold_for

    threshold = threshold_for(fail_on)
    worst = max(severity_score(f.severity) for f in findings) if findings else 0
    return 1 if worst >= threshold else 0
