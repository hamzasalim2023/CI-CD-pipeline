"""SARIF 2.1.0 report generation.

Maps mytool `Finding` objects onto the Static Analysis Results Interchange
Format so results can be surfaced natively in GitHub code scanning / GitLab
SAST, instead of only as our custom JSON payload.

Structure produced (minimal but valid SARIF 2.1.0):

    runs[0].tool.driver     -> name/version/rules (ruleId, shortDescription,
                               helpUri, properties.tags, security-severity)
    runs[0].results[i]      -> one entry per finding with ruleId, level,
                               message, and a physical location (uri + region)
"""

import json

from mytool.models import Finding, sort_severity

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# mytool severity -> SARIF run result level.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# mytool severity -> GitHub code-scanning security-severity (0.0 - 10.0).
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}

_SCAN_TYPE_TAG = {
    "secret": "secrets",
    "dependency": "dependencies",
    "code": "security",
}

_HELP_URI = {
    "secret": "https://github.com/hamzasalim2023/CI-CD-pipeline",
    "dependency": "https://osv.dev",
    "code": "https://owasp.org/www-community/",
}


def _rule_id(finding: Finding) -> str:
    return finding.rule_id or "unknown-rule"


def _rule_tags(finding: Finding) -> list:
    tags = []
    scan = _SCAN_TYPE_TAG.get(finding.scan_type)
    if scan:
        tags.append(scan)
    cwe = (finding.extra or {}).get("cwe")
    if cwe and str(cwe).startswith("CWE-"):
        tags.append(str(cwe))
    return tags


def _level(finding: Finding) -> str:
    return _LEVEL.get(finding.severity.lower().strip(), "note")


def _security_severity(finding: Finding) -> str:
    return _SECURITY_SEVERITY.get(finding.severity.lower().strip(), "1.0")


def _region_column(finding: Finding) -> int | None:
    col = (finding.extra or {}).get("col")
    if isinstance(col, int) and col > 0:
        return col
    return None


def _location(finding: Finding) -> dict:
    loc = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
        }
    }
    region = {"startLine": finding.line}
    col = _region_column(finding)
    if col:
        region["startColumn"] = col
    loc["physicalLocation"]["region"] = region
    return loc


def _help_uri(finding: Finding) -> str:
    cwe = (finding.extra or {}).get("cwe")
    if cwe and str(cwe).startswith("CWE-"):
        return f"https://cwe.mitre.org/data/definitions/{str(cwe).split('-')[1]}.html"
    return _HELP_URI.get(finding.scan_type, _HELP_URI["secret"])


def _rule(finding: Finding) -> dict:
    tags = _rule_tags(finding)
    rule = {
        "id": _rule_id(finding),
        "shortDescription": {"text": finding.message or finding.rule_id},
    }
    if finding.severity:
        rule["defaultConfiguration"] = {"level": _level(finding)}
    props = {}
    if tags:
        props["tags"] = tags
    props["security-severity"] = _security_severity(finding)
    rule["properties"] = props
    uri = _help_uri(finding)
    if uri:
        rule["helpUri"] = uri
    return rule


def finding_to_sarif_result(finding: Finding) -> dict:
    result = {
        "ruleId": _rule_id(finding),
        "level": _level(finding),
        "message": {"text": finding.message or finding.rule_id},
        "locations": [_location(finding)],
    }
    tags = _rule_tags(finding)
    props = {"security-severity": _security_severity(finding)}
    if tags:
        props["tags"] = tags
    # Expose dependency-specific extra metadata for downstream tooling.
    extra = finding.extra or {}
    if finding.scan_type == "dependency" and extra:
        dep = {}
        for k in ("package", "ecosystem", "installed", "fixed", "cvss_score"):
            if extra.get(k) is not None:
                dep[k] = extra[k]
        if dep:
            props["dependency"] = dep
    result["properties"] = props
    return result


def build_sarif(findings: list, driver_name: str = "mytool",
                driver_version: str = "0.1.0",
                information_uri: str = "https://github.com/hamzasalim2023/CI-CD-pipeline") -> dict:
    """Build a complete SARIF 2.1.0 document from a list of Findings."""
    ordered = sorted(findings, key=lambda f: (sort_severity(f.severity), f.file, f.line))
    rules = []
    seen_rules = set()
    results = []
    for f in ordered:
        rid = _rule_id(f)
        if rid not in seen_rules:
            seen_rules.add(rid)
            rules.append(_rule(f))
        results.append(finding_to_sarif_result(f))

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": driver_name,
                        "version": driver_version,
                        "informationUri": information_uri,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def dumps_sarif(findings: list, **kwargs) -> str:
    return json.dumps(build_sarif(findings, **kwargs), indent=2)

