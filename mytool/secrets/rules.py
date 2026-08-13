"""Secret detection rules.

The patterns below were informed by reading public rulesets such as
Gitleaks and TruffleHog. They were re-written from scratch to reflect an
understanding of *what* makes each secret detectable (fixed prefixes,
fixed lengths, base64 character sets, surrounding keywords) rather than
copied verbatim.

Each rule either matches a well-known secret format (regex only) or a
keyword assignment whose value must additionally clear an entropy bar
(`entropy` threshold) to reduce false positives.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    description: str
    pattern: str
    severity: str
    entropy: float | None = None  # minimum entropy for the matched value
    min_len: int = 0              # minimum length of matched value
    group: int = 0                # regex group holding the secret value


def _id(name: str) -> str:
    return f"secret-{name}"


RULES = [
    SecretRule(
        _id("aws-access-key-id"),
        "AWS Access Key ID",
        r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b",
        "critical",
    ),
    SecretRule(
        _id("aws-secret-access-key"),
        "AWS Secret Access Key",
        r"(?i)\baws.{0,30}(?:secret|secret_access_key|secret_key|access_key).{0,10}"
        r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "critical",
        entropy=4.0,
        group=1,
        min_len=40,
    ),
    SecretRule(
        _id("github-token"),
        "GitHub personal access token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
        "critical",
    ),
    SecretRule(
        _id("gitlab-token"),
        "GitLab personal access token",
        r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        "critical",
    ),
    SecretRule(
        _id("slack-webhook"),
        "Slack incoming webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{20,}",
        "critical",
    ),
    SecretRule(
        _id("stripe-live-key"),
        "Stripe live secret key",
        r"(?i)\bsk_live_[0-9a-zA-Z]{24,}\b",
        "critical",
    ),
    SecretRule(
        _id("stripe-restricted-key"),
        "Stripe restricted key",
        r"(?i)\brk_live_[0-9a-zA-Z]{20,}\b",
        "high",
    ),
    SecretRule(
        _id("stripe-test-key"),
        "Stripe test secret key",
        r"(?i)\bsk_test_[0-9a-zA-Z]{24,}\b",
        "medium",
    ),
    SecretRule(
        _id("google-api-key"),
        "Google API key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "high",
    ),
    SecretRule(
        _id("private-key"),
        "Private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "critical",
    ),
    SecretRule(
        _id("jwt-token"),
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b",
        "high",
        entropy=3.5,
    ),
    SecretRule(
        _id("twilio-api-key"),
        "Twilio API key",
        r"\bSK[0-9a-fA-F]{32}\b",
        "high",
    ),
    SecretRule(
        _id("sendgrid-api-key"),
        "SendGrid API key",
        r"\bSG\.[0-9A-Za-z\-_]{16,32}\.[0-9A-Za-z\-_]{16,80}\b",
        "critical",
    ),
    SecretRule(
        _id("openai-api-key"),
        "OpenAI API key",
        r"\bsk-[0-9A-Za-z]{20,}\b",
        "critical",
    ),
    SecretRule(
        _id("npm-token"),
        "npm access token",
        r"\bnpm_[0-9A-Za-z]{36}\b",
        "critical",
    ),
    SecretRule(
        _id("pypi-token"),
        "PyPI API token",
        r"\bpypi-[A-Za-z0-9\-_]{20,}\b",
        "high",
    ),
    SecretRule(
        _id("shopify-access-token"),
        "Shopify access token",
        r"\bshpat_[0-9a-f]{32}\b",
        "high",
    ),
    SecretRule(
        _id("discord-webhook"),
        "Discord webhook URL",
        r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9\-_]{60,68}",
        "high",
    ),
    SecretRule(
        _id("telegram-bot-token"),
        "Telegram bot token",
        r"\b[0-9]{8,10}:[A-Za-z0-9\-_]{35}\b",
        "medium",
    ),
    SecretRule(
        _id("huggingface-token"),
        "Hugging Face token",
        r"\bhf_[A-Za-z0-9]{34,}\b",
        "medium",
    ),
    SecretRule(
        _id("azure-storage-key"),
        "Azure Storage account key",
        r"(?i)\b[A-Za-z0-9+/=]{88}\b",
        "high",
        entropy=4.3,
        min_len=88,
    ),
    # Generic keyword-assignment rules: value must clear the entropy bar.
    SecretRule(
        _id("generic-api-key"),
        "Generic API key / token / password assignment",
        r"(?i)\b(?:api[_-]?key|apikey|secret|token|passwd|password|pass|auth|credential|"
        r"client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key)"
        r"(['\"]?)\s*[:=]\s*['\"]([A-Za-z0-9_\-./+!@#$%^&*?=]{10,})['\"]",
        "high",
        entropy=3.9,
        group=2,
        min_len=10,
    ),
    SecretRule(
        _id("high-entropy-string"),
        "Possible high-entropy secret (review)",
        r"([A-Za-z0-9\-_+/=]{20,})",
        "medium",
        entropy=4.3,
        group=1,
        min_len=20,
    ),
]

# Values that commonly appear in placeholders/docs and must not be flagged
# by entropy-based rules.
IGNORED_VALUES = {
    "your_token_here",
    "your_api_key_here",
    "your_password_here",
    "changeme",
    "example",
    "token_placeholder",
    "REPLACE_ME",
    "your_secret_key",
    "example_secret",
    "dummy_secret",
    "not-a-real-secret",
}


def is_ignored_value(value: str) -> bool:
    v = value.lower()
    if v in {i.lower() for i in IGNORED_VALUES}:
        return True
    # Repeated single characters (aaaaaaaaaaaaaa, xxxxxxxxxxxx) are not secrets.
    if value and len(set(value)) == 1:
        return True
    return False


RULE_BY_ID = {r.rule_id: r for r in RULES}
COMPILED = [(r, re.compile(r.pattern)) for r in RULES]
