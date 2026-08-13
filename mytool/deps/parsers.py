"""Parsers for common dependency manifests -> Package records.

Supported: requirements.txt, package.json (+package-lock.json), go.mod.
"""

import json
import os
import re
from dataclasses import dataclass, field


@dataclass
class Package:
    ecosystem: str            # OSV ecosystem name (PyPI, npm, Go, ...)
    name: str
    version: str
    file: str = ""
    line: int = 0
    spec: str = field(default="", repr=False)

    def query_key(self) -> tuple:
        return (self.ecosystem, self.name, self.version)


MANIFEST_KINDS = {
    "requirements.txt": "requirements",
    "requirements-dev.txt": "requirements",
    "package.json": "package-json",
    "package-lock.json": "package-lock",
    "npm-shrinkwrap.json": "package-lock",
    "go.mod": "go-mod",
    "Pipfile.lock": "pipfile",
    "poetry.lock": "poetry",
}


def _canonical_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _canonical_npm(name: str) -> str:
    return name.strip()


def _npm_base_version(spec: str) -> str | None:
    m = re.search(r"\d+\.\d+(?:\.\d+)?", spec)
    return m.group(0) if m else None


def parse_requirements(text: str, file: str = "") -> list:
    deps: list = []
    entry_re = re.compile(
        r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|~=|>=|<=|>|<|!=)\s*"
        r"([^\s;]+)"
    )
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", ".", "http", "git", "hg", "svn")):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        m = entry_re.match(line)
        if not m:
            continue
        name, op, version = m.groups()
        name = _canonical_pypi(name)
        version = version.split("#")[0].strip()
        if op == "==" and version:
            deps.append(Package("PyPI", name, version, file=file, line=lineno, spec=line))
    return deps


def parse_package_json(text: str, file: str = "") -> list:
    deps: list = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return deps
    for section in ("dependencies", "devDependencies"):
        table = data.get(section) or {}
        for name, spec in table.items():
            if not isinstance(spec, str):
                continue
            version = _npm_base_version(spec)
            if version:
                deps.append(Package(
                    "npm", _canonical_npm(name), version, file=file,
                    line=data.get("line") or 0, spec=spec,
                ))
    return deps


def parse_package_lock(text: str, file: str = "") -> list:
    deps: list = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return deps
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path.startswith("node_modules/"):
                continue
            name = path[len("node_modules/"):].split("/node_modules/")[-1]
            version = info.get("version")
            if isinstance(version, str) and version:
                deps.append(Package("npm", name, version, file=file))
    else:
        deps_lx = data.get("dependencies")
        if isinstance(deps_lx, dict):
            _walk_npm_tree(deps_lx, deps, file, prefix="")
    return deps


def _walk_npm_tree(node, into, file, prefix):
    for name, info in node.items():
        full = f"{prefix}/{name}" if prefix else name
        version = info.get("version")
        if isinstance(version, str) and version:
            into.append(Package("npm", full, version, file=file))
        sub = info.get("dependencies")
        if isinstance(sub, dict):
            _walk_npm_tree(sub, into, file, full)


def parse_go_mod(text: str, file: str = "") -> list:
    deps: list = []
    module_re = re.compile(r"^([A-Za-z0-9_./\-]+)\s+(v\d+\.\d+\.\d+(?:-[^\s]+)?)")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//")[0].strip()
        if not line or line in ("require (", ")", "require", "replace", "retract"):
            continue
        if line.startswith((
            "module ", "go ", "toolchain ", "exclude", "replace",
        )):
            continue
        m = module_re.match(line)
        if m:
            name, version = m.groups()
            deps.append(Package(
                "Go", name, version.lstrip("v"), file=file, line=lineno, spec=line,
            ))
    return deps


def parse_manifest_text(text: str, filename: str) -> list:
    kind = MANIFEST_KINDS.get(os.path.basename(filename))
    if kind in ("requirements",):
        return parse_requirements(text, filename)
    if kind == "package-json":
        return parse_package_json(text, filename)
    if kind == "package-lock":
        return parse_package_lock(text, filename)
    if kind == "go-mod":
        return parse_go_mod(text, filename)
    if kind == "pipfile":
        return parse_pipfile_lock(text, filename)
    if kind == "poetry":
        return parse_poetry_lock(text, filename)
    return []


def parse_pipfile_lock(text: str, file: str = "") -> list:
    deps: list = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return deps
    for section in ("default", "develop"):
        table = data.get(section) or {}
        for name, info in table.items():
            version = info.get("version", "").lstrip("=")
            if version:
                deps.append(Package("PyPI", _canonical_pypi(name), "".join(c for c in version if c.isdigit() or c == ".")))
    return deps


_TOML_RE = re.compile(r"name\s*=\s*\"([^\"]+)\"\s*\nversion\s*=\s*\"([^\"]+)\"")
def parse_poetry_lock(text: str, file: str = "") -> list:
    deps: list = []
    for m in _TOML_RE.finditer(text):
        name, version = m.groups()
        deps.append(Package("PyPI", _canonical_pypi(name), version, file=file))
    return deps


def discover_manifests(root: str) -> list:
    """Find all supported manifest files under root, sorted."""
    from mytool.secrets.detector import SKIP_DIRS  # reuse skip list

    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in MANIFEST_KINDS:
                found.append(os.path.join(dirpath, name))
    return sorted(found)