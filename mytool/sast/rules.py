"""SAST rule catalog.

A focused, hand-written rule set that mirrors common findings from tools
like Bandit and Semgrep's security rules. Each rule maps to concrete AST
patterns implemented in checker.py.
"""

RULES = {
    "sast-eval-exec": {
        "description": "eval()/exec()/compile() allows arbitrary code execution",
        "severity": "high",
        "cwe": "CWE-95",
    },
    "sast-sql-injection": {
        "description": "SQL statement built via string interpolation (injection risk)",
        "severity": "critical",
        "cwe": "CWE-89",
    },
    "sast-shell-true": {
        "description": "subprocess launched with shell=True (shell injection risk)",
        "severity": "high",
        "cwe": "CWE-78",
    },
    "sast-os-system": {
        "description": "os.system passes a command string to the shell",
        "severity": "high",
        "cwe": "CWE-78",
    },
    "sast-verify-false": {
        "description": "TLS certificate verification disabled (verify=False)",
        "severity": "medium",
        "cwe": "CWE-295",
    },
    "sast-ssl-check-hostname": {
        "description": "SSL hostname verification disabled",
        "severity": "medium",
        "cwe": "CWE-295",
    },
    "sast-insecure-deserialization": {
        "description": "Unsafe deserialization of untrusted data",
        "severity": "high",
        "cwe": "CWE-502",
    },
}


def rule_metadata(rule_id: str) -> dict:
    return RULES.get(rule_id, {"description": rule_id, "severity": "medium", "cwe": ""})