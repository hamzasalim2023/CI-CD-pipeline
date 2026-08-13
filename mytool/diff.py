"""Parsing `git diff` output to extract added (newly introduced) lines.

Used so CI can scan only what a commit/PR introduces instead of the whole
repository (which would immediately fail on any pre-existing secret).
"""

import subprocess
import re

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    pass


def run_git(args: list, cwd: str | None = None) -> str:
    cmd = ["git"] + args
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=cwd,
        )
    except FileNotFoundError:
        raise GitError("git executable not found on PATH")
    if proc.returncode != 0:
        raise GitError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return proc.stdout


def parse_unified_diff(diff_text: str) -> dict:
    """Parse unified diff text into {file_path: [(line_no, text), ...]} for
    added lines only.

    Files use the path from the `+++ b/...` line (stripped of the `b/`
    prefix). Line numbers come from the `@@ -a,b +c,d @@` hunk headers.
    """
    changed: dict = {}
    current_file = None
    current_line = 0

    for raw in diff_text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("diff --git"):
            continue
        if line.startswith("--- "):
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path == "/dev/null":
                current_file = None
                continue
            if path.startswith("b/"):
                path = path[2:]
            elif path.startswith("a/"):
                path = path[2:]
            current_file = path
            changed.setdefault(current_file, [])
            continue
        if line.startswith("\\ No newline"):
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            if current_file is None:
                continue
            current_line = int(hunk.group(1))
            continue
        if current_file is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed[current_file].append((current_line, line[1:]))
            current_line += 1
        elif line.startswith("-"):
            continue
        elif line.startswith(" "):
            current_line += 1
    return {path: lines for path, lines in changed.items() if lines}


def added_lines(base: str, ref: str | None = None, cwd: str | None = None) -> dict:
    """Return added lines between base and ref (or the working tree).

    * added_lines("HEAD~1", "HEAD")     -> a single commit
    * added_lines("HEAD~3", "HEAD")     -> a range
    * added_lines("origin/main")        -> working tree vs that ref (PR-style)
    """
    args = ["diff", base] + ([ref] if ref else [])
    diff_text = run_git(args, cwd=cwd)
    return parse_unified_diff(diff_text)
