"""Per-resource authorization policy.

An OAuth scope grants a capability (may this caller write documents at
all?); it does not grant access to a specific document (may this caller
write *this* document?). The MCP security guidance names treating the
token scope as sufficient an anti-pattern, so every document tool consults
an authorizer with the concrete resource before acting.

The default in-process policy is default-deny ABAC driven by a small grant
list. The Authorizer protocol is the seam where an external policy engine
(OPA, Cedar) can be substituted later without touching the tools.
"""

import json
from dataclasses import dataclass
from typing import Protocol

from arrowhead.config import Settings

# Actions correspond to the document verbs, decoupled from tool names.
ACTION_SEARCH = "search"
ACTION_READ = "read"
ACTION_SCAN = "scan"
ACTION_WRITE = "write"

# A grant prefix may contain this token, expanded to the requesting
# subject before matching, so one rule can scope every caller to its own
# namespace (e.g. prefix "${subject}/").
SUBJECT_TOKEN = "${subject}"


# Resource kinds. A point resource is one concrete document; a prefix
# resource is a range query (search, scan) over documents under a path; a
# URL resource is an external address, controlled by the SSRF guard rather
# than by path scoping.
KIND_DOCUMENT = "document"
KIND_PREFIX = "prefix"
KIND_URL = "url"


@dataclass(frozen=True)
class Resource:
    """The target of an action: a document, a path prefix, or a URL."""

    kind: str
    identifier: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class Grant:
    subject: str  # exact subject or "*"
    actions: frozenset[str]  # action names or {"*"}
    prefix: str  # document path prefix; may contain SUBJECT_TOKEN

    def matches(self, subject: str, action: str, resource: Resource) -> bool:
        if self.subject != "*" and self.subject != subject:
            return False
        if "*" not in self.actions and action not in self.actions:
            return False
        if resource.kind == KIND_URL:
            # URLs are not path-scoped; a subject and action match is enough.
            # The SSRF guard is the resource control there.
            return True
        expanded = self.prefix.replace(SUBJECT_TOKEN, subject)
        if resource.kind == KIND_PREFIX:
            # A range query (search, scan) is allowed if the requested area
            # overlaps a granted area (either contains or is contained by
            # it). The per-document filter then restricts which documents are
            # actually touched, so an overlap can never leak one the caller
            # may not access.
            return resource.identifier.startswith(
                expanded
            ) or expanded.startswith(resource.identifier)
        # A point resource (one document) must sit under a granted prefix.
        return resource.identifier.startswith(expanded)


class Authorizer(Protocol):
    def authorize(
        self, subject: str, action: str, resource: Resource
    ) -> Decision: ...


class AllowAllAuthorizer:
    """Used when auth is disabled (local development); permits everything."""

    def authorize(
        self, subject: str, action: str, resource: Resource
    ) -> Decision:
        return Decision(allowed=True, reason="authorization disabled")


class JailPolicy:
    """Default-deny policy: allow only what a grant explicitly permits."""

    def __init__(self, grants: list[Grant]) -> None:
        self._grants = grants

    def authorize(
        self, subject: str, action: str, resource: Resource
    ) -> Decision:
        for grant in self._grants:
            if grant.matches(subject, action, resource):
                return Decision(allowed=True, reason="grant matched")
        return Decision(allowed=False, reason="no grant matched")


# The default policy when auth is enabled but no policy is configured:
# every authenticated caller may search, read, and scan the whole corpus,
# but may write only within its own "<subject>/" namespace. This is a safe,
# illustrative ABAC default (cross-subject writes are denied) and is fully
# overridable via configuration.
_DEFAULT_GRANTS = [
    Grant(
        subject="*",
        actions=frozenset({ACTION_SEARCH, ACTION_READ, ACTION_SCAN}),
        prefix="",
    ),
    Grant(subject="*", actions=frozenset({ACTION_WRITE}), prefix=f"{SUBJECT_TOKEN}/"),
]


class PolicyError(Exception):
    """The configured policy could not be parsed."""


def parse_policy(raw: str) -> JailPolicy:
    """Parse a JSON policy document into a JailPolicy.

    Shape: {"grants": [{"subject": "*", "actions": ["read"], "prefix": ""}]}.
    """
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise PolicyError("policy is not valid JSON") from exc
    if not isinstance(document, dict) or not isinstance(
        document.get("grants"), list
    ):
        raise PolicyError("policy must be an object with a 'grants' list")
    grants = []
    for entry in document["grants"]:
        if not isinstance(entry, dict):
            raise PolicyError("each grant must be an object")
        try:
            actions = frozenset(entry["actions"])
            grants.append(
                Grant(
                    subject=str(entry["subject"]),
                    actions=actions,
                    prefix=str(entry.get("prefix", "")),
                )
            )
        except (KeyError, TypeError) as exc:
            raise PolicyError("grant missing subject or actions") from exc
    return JailPolicy(grants)


def build_authorizer(settings: Settings) -> Authorizer:
    """Build the authorizer from settings.

    Auth disabled -> allow all (mirrors scope enforcement being skipped for
    local development). Otherwise a JailPolicy, from the configured policy or
    the safe per-subject-namespace default.
    """
    if not settings.auth_enabled:
        return AllowAllAuthorizer()
    if settings.authz_policy.strip():
        return parse_policy(settings.authz_policy)
    return JailPolicy(list(_DEFAULT_GRANTS))
