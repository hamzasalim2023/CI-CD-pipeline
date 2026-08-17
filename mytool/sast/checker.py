"""AST-based static analysis checks for Python codebases.

Implements hand-written checks on top of the stdlib `ast` module - the
same technique Semgrep/Bandit use under the hood - so we detect real
call/assignment patterns instead of regex matches (fewer false positives).
"""

import ast
import os

from mytool.models import Finding
from mytool.sast.rules import rule_metadata
from mytool.secrets.detector import SKIP_DIRS

DANGEROUS_EVAL = {"eval", "exec"}
SQL_METHODS = {"execute", "executemany", "executescript"}
SUBPROCESS_FUNCS = {"Popen", "call", "run", "check_call", "check_output",
                    "getoutput", "getstatusoutput"}
ALWAYS_SHELL = {"getoutput", "getstatusoutput"}
REQUEST_METHODS = {"get", "post", "put", "delete", "patch", "head",
                   "request", "options"}
PICKLE_MODULES = {"pickle", "cPickle", "dill"}
SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM",
                "JOIN", "CREATE", "DROP", "ALTER", "TRUNCATE", "MERGE")

_MAX_CONTEXT = 200


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, source: str, filename: str):
        self.source = source
        self.filename = filename
        self.findings: list[Finding] = []
        self.modules: dict = {}
        self.members: dict = {}

    # -- helpers ---------------------------------------------------------
    def _resolve(self, func) -> tuple:
        """Return (module_or_None, callable_name) for a Call's func."""
        if isinstance(func, ast.Attribute):
            base = func.value
            if isinstance(base, ast.Name):
                module = self.modules.get(base.id, base.id)
                return module, func.attr
            return None, func.attr
        if isinstance(func, ast.Name):
            if func.id in self.members:
                return self.members[func.id], func.id
            return self.modules.get(func.id, func.id), func.id
        return None, None

    def _kw_value(self, keywords, name):
        for kw in keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _is_falsy_constant(self, node) -> bool:
        if isinstance(node, ast.Constant):
            if node.value is False or node.value == 0:
                return True
            if isinstance(node.value, str) and node.value.lower() in ("false", "no", "off", "0"):
                return True
        return False

    def _add(self, rule_id, node, message=None, severity=None):
        meta = rule_metadata(rule_id)
        self.findings.append(Finding(
            scan_type="code",
            rule_id=rule_id,
            severity=severity or meta["severity"],
            file=self.filename,
            line=node.lineno,
            message=message or meta["description"],
            context=self._context(node),
            extra={"cwe": meta.get("cwe", ""), "col": node.col_offset + 1},
        ))

    def _context(self, node) -> str:
        try:
            seg = ast.get_source_segment(self.source, node)
        except (TypeError, ValueError):
            return ""
        if seg is None:
            return ""
        seg = " ".join(seg.split())
        return seg[:_MAX_CONTEXT] + ("..." if len(seg) > _MAX_CONTEXT else "")

    # -- entry points ----------------------------------------------------
    def visit_Import(self, node):
        for alias in node.names:
            if alias.asname:
                self.modules[alias.asname] = alias.name
            else:
                self.modules[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            name = alias.asname or alias.name
            if alias.asname:
                self.modules[alias.asname] = f"{mod}.{alias.name}"
            if mod == "subprocess" or mod.endswith(".subprocess"):
                self.members[name] = "subprocess"
            elif mod == "os":
                self.members[name] = "os"
            elif mod in ("pickle", "cPickle", "dill"):
                self.members[name] = "pickle"
            elif mod == "requests":
                self.members[name] = "requests"
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self._check_ssl_assignment(target, node.value)
            elif isinstance(target, ast.Name):
                # track `sess = requests.Session()` for verify detection
                if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
                    module, _ = self._resolve(node.value.func)
                    if module == "requests":
                        self.members[target.id] = "requests"
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Attribute):
            self._check_ssl_assignment(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node):
        module, name = self._resolve(node.func)
        self._check_eval(node, module, name)
        self._check_subprocess(node, module, name)
        self._check_sql(node, module, name)
        self._check_tls(node, module, name)
        self._check_ssl_ctx(node, module, name)
        self._check_pickle(node, module, name)
        self.generic_visit(node)

    # -- individual rules -------------------------------------------------
    def _check_eval(self, node, module, name):
        if isinstance(node.func, ast.Name) and name in DANGEROUS_EVAL:
            self._add("sast-eval-exec", node)

    def _check_subprocess(self, node, module, name):
        if name in ALWAYS_SHELL and module == "subprocess":
            self._add("sast-shell-true", node,
                      "subprocess.{0} always invokes the system shell".format(name))
            return
        if name in SUBPROCESS_FUNCS and module == "subprocess":
            shell = self._kw_value(node.keywords, "shell")
            if shell is not None and self._is_falsy_constant(shell):
                # shell=False explicitly - safe
                return
            if shell is not None:
                self._add("sast-shell-true", node)
        if module == "os" and name in ("system", "popen", "popen2"):
            self._add("sast-os-system", node)

    def _check_sql(self, node, module, name):
        if not (isinstance(node.func, ast.Attribute) and name in SQL_METHODS):
            return
        target = self._kw_value(node.keywords, "sql")
        first = node.args[0] if node.args else target
        if first is None:
            return
        if isinstance(first, ast.BinOp) and isinstance(first.op, (ast.Add, ast.Mod)):
            self._add("sast-sql-injection", node)
        elif isinstance(first, ast.JoinedStr):
            static = "".join(
                part.value.upper() for part in first.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            if any(kw in static for kw in SQL_KEYWORDS):
                self._add("sast-sql-injection", node,
                          "SQL built with an f-string - ensure values cannot inject SQL")

    def _check_tls(self, node, module, name):
        verify = self._kw_value(node.keywords, "verify")
        if verify is not None and self._is_falsy_constant(verify):
            ok_module = module in ("requests", "httpx", "urllib3")
            ok_name = isinstance(node.func, ast.Attribute) and name in REQUEST_METHODS
            if ok_module or ok_name:
                self._add("sast-verify-false", node)

    def _check_ssl_ctx(self, node, module, name):
        if module == "ssl" and name in ("SSLContext", "create_default_context", "_https_verify_certificates"):
            verify_mode = self._kw_value(node.keywords, "verify_mode")
            if verify_mode is not None and self._is_falsy_constant(verify_mode):
                self._add("sast-ssl-check-hostname", node)
            enable = self._kw_value(node.keywords, "enable")
            if enable is not None and self._is_falsy_constant(enable):
                self._add("sast-ssl-check-hostname", node)
        if isinstance(node.func, ast.Attribute):
            base, attr = node.func.value, node.func.attr
            if attr == "verify_mode" and isinstance(base, ast.Attribute) and base.attr == "CERT_NONE":
                self._add("sast-ssl-check-hostname", node)

    def _check_ssl_assignment(self, target, value):
        if target.attr == "check_hostname" and self._is_falsy_constant(value):
            self._add("sast-ssl-check-hostname", target)
        if target.attr == "verify_mode":
            if isinstance(value, ast.Attribute) and value.attr == "CERT_NONE":
                self._add("sast-ssl-check-hostname", target)

    def _check_pickle(self, node, module, name):
        if module in PICKLE_MODULES and name in ("load", "loads"):
            self._add("sast-insecure-deserialization", node)


def scan_text(text: str, filename: str) -> list:
    try:
        tree = ast.parse(text, filename=filename)
    except (SyntaxError, ValueError):
        return []
    visitor = _CallVisitor(text, filename)
    visitor.visit(tree)
    return visitor.findings


def scan_file(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, os.path.basename(path))


def iter_python_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_path(root: str) -> list:
    if os.path.isfile(root):
        return scan_file(root)
    findings = []
    for file in iter_python_files(root):
        findings.extend(scan_file(file))
    return findings