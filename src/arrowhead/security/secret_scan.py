"""Secrets and PII scanning that never returns the raw value.

Each finding reports a type, a line number, and a redacted placeholder of
the form [REDACTED:TYPE:tag], where the tag is a short, non-reversible hash
of the matched value. The same secret produces the same tag, which lets a
caller correlate occurrences without ever seeing the secret. Patterns are
fixed and linear (no user-supplied regex), so scanning has no ReDoS
surface.
"""

import hashlib
import re
from dataclasses import dataclass

# Ordered so more specific patterns are reported before the generic ones.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(
            r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"
        ),
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password)"
            r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{12,})"
        ),
    ),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


@dataclass(frozen=True)
class Finding:
    type: str
    line: int
    redacted: str


def _redact(value: str, kind: str) -> str:
    tag = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED:{kind.upper()}:{tag}]"


def scan_text(text: str, *, max_findings: int) -> list[Finding]:
    """Return redacted findings for secrets and PII in the text."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                findings.append(
                    Finding(type=kind, line=lineno, redacted=_redact(value, kind))
                )
                if len(findings) >= max_findings:
                    return findings
    return findings
