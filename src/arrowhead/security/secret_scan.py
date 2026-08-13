"""Secrets and PII scanning that never returns the raw value.

Each finding reports a type, a line number, and a redacted placeholder of
the form [REDACTED:TYPE:tag]. The tag is a keyed hash of the matched value
under a random per-process salt: within one run the same value redacts to the
same tag, so a caller can correlate occurrences, but the tag cannot be
brute-forced back to a low-entropy value such as an SSN or email, because the
salt is secret and is never persisted or returned. Patterns are fixed and
linear (no user-supplied regex), so scanning has no ReDoS surface.
"""

import hashlib
import re
import secrets
from dataclasses import dataclass

# A random per-process salt. It keeps the redaction tag stable within a run
# (the intended correlation signal) while making the tag non-reversible: an
# 8-hex-character SHA-256 of an SSN or email is trivially brute-forced, but
# not without this salt.
_SALT = secrets.token_bytes(16)

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
    tag = hashlib.sha256(_SALT + value.encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED:{kind.upper()}:{tag}]"


def scan_text(text: str, *, max_findings: int) -> list[Finding]:
    """Return redacted findings for secrets and PII in the text.

    Patterns run most-specific first; a match that overlaps one already
    recorded on the same line is skipped, so a single secret that matches two
    patterns (a JWT that is also a credential assignment) is reported once and
    does not consume two of the finding slots.
    """
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        claimed: list[tuple[int, int]] = []
        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                span = match.span(1) if match.groups() else match.span(0)
                if any(span[0] < end and start < span[1] for start, end in claimed):
                    continue
                claimed.append(span)
                value = match.group(1) if match.groups() else match.group(0)
                findings.append(
                    Finding(type=kind, line=lineno, redacted=_redact(value, kind))
                )
                if len(findings) >= max_findings:
                    return findings
    return findings


def redact_text(text: str, *, max_findings: int) -> tuple[str, int]:
    """Replace every secret and PII match in the text with its placeholder.

    Runs the same pattern set as scan_text and substitutes each matched
    value with its redaction tag in place, so output that must leave the
    server (a subprocess's stdout) carries no raw secret. Returns the
    redacted text and how many values were replaced. Substitution is
    right-to-left within a line so earlier spans keep their offsets.
    """
    replaced = 0
    out_lines: list[str] = []
    for line in text.splitlines():
        spans: list[tuple[int, int, str]] = []
        claimed: list[tuple[int, int]] = []
        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                span = match.span(1) if match.groups() else match.span(0)
                if any(
                    span[0] < end and start < span[1] for start, end in claimed
                ):
                    continue
                claimed.append(span)
                value = match.group(1) if match.groups() else match.group(0)
                spans.append((span[0], span[1], _redact(value, kind)))
        for start, end, placeholder in sorted(spans, reverse=True):
            line = line[:start] + placeholder + line[end:]
            replaced += 1
            if replaced >= max_findings:
                break
        out_lines.append(line)
        if replaced >= max_findings:
            out_lines.extend(text.splitlines()[len(out_lines):])
            break
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out_lines) + trailing, replaced
