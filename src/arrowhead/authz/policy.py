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

# Actions correspond to the resource verbs, decoupled from tool names.
ACTION_SEARCH = "search"
ACTION_READ = "read"
ACTION_SCAN = "scan"
ACTION_WRITE = "write"
# Reading a database table is its own verb, so a policy can grant table access
# independently of document access even though both are reads.
ACTION_QUERY = "query"
# Fetching an external URL is its own verb, distinct from reading a document,
# so a policy can deny outbound fetch to a caller without also denying its
# document reads. A wildcard action still covers it.
ACTION_FETCH = "fetch"
# Writing document chunks into a vector store is its own verb, so a policy can
# grant retrieval ingestion independently of document writes. It is absent from
# the default grants, so ingestion is denied until a deployment allows it.
ACTION_INGEST = "ingest"

# A grant prefix may contain this token, expanded to the requesting
# subject before matching, so one rule can scope every caller to its own
# namespace (e.g. prefix "${subject}/").
SUBJECT_TOKEN = "${subject}"  # noqa: S105  # a path template token, not a secret


# Resource kinds. A point resource is one concrete document; a prefix
# resource is a range query (search, scan) over documents under a path; a
# URL resource is an external address, controlled by the SSRF guard rather
# than by path scoping.
KIND_DOCUMENT = "document"
KIND_PREFIX = "prefix"
KIND_URL = "url"
# A file read from the read_file jail, identified by its jail-relative path.
# Like a document it is a point resource: it must sit under a granted prefix.
KIND_FILE = "file"
# A database table, identified as "schema.table" (or "database.schema.table").
# Like a document it is a point resource: it must sit under a granted prefix.
KIND_TABLE = "table"
# A read query that references no table (SELECT with only functions or
# literals). It is authorized against this kind rather than a real table, and
# the default policy does not grant it, so a tableless query (which can hide a
# table read or a side effect inside a function) requires an explicit grant.
KIND_TABLELESS = "tableless"
# Repository resources live in their own kinds so a grant over corpus
# documents never implicitly covers source code, and vice versa. A repo
# file is a point resource under the repo jail; a repo prefix is a range
# query (search, symbol map, dependency graph) over files beneath a path.
KIND_REPO_FILE = "repo_file"
KIND_REPO_PREFIX = "repo_prefix"


@dataclass(frozen=True)
class Resource:
    """The target of an action: a document, a path prefix, or a URL."""

    kind: str
    identifier: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _covered_by_prefix(prefix: str, identifier: str) -> bool:
    """True when a point resource sits under a granted prefix.

    Matching is component-aware: the identifier must equal the prefix or
    continue past it at a path or schema separator, so a grant on "notes" does
    not reach "notes-private" and a grant on "orders" does not reach
    "orders_pii". An empty prefix covers everything.
    """
    if prefix == "":
        return True
    if identifier == prefix:
        return True
    if not identifier.startswith(prefix):
        return False
    if prefix.endswith(("/", ".")):
        return True
    return identifier[len(prefix)] in "/."


@dataclass(frozen=True)
class Grant:
    subject: str  # exact subject or "*"
    actions: frozenset[str]  # action names or {"*"}
    prefix: str  # document path prefix; may contain SUBJECT_TOKEN
    kinds: frozenset[str] = frozenset()  # resource kinds, empty means any kind

    def matches(self, subject: str, action: str, resource: Resource) -> bool:
        if self.subject != "*" and self.subject != subject:
            return False
        if "*" not in self.actions and action not in self.actions:
            return False
        if self.kinds and resource.kind not in self.kinds:
            return False
        if resource.kind == KIND_URL:
            # A URL is not path-scoped; the SSRF guard is its resource control.
            # Governance is by the fetch action, so a read-only grant does not
            # imply outbound fetch.
            return True
        if SUBJECT_TOKEN in self.prefix and ("/" in subject or ".." in subject):
            # A subject carrying a path separator could otherwise reshape the
            # namespace it is scoped to; refuse to expand such a subject.
            return False
        expanded = self.prefix.replace(SUBJECT_TOKEN, subject)
        if resource.kind in (KIND_PREFIX, KIND_REPO_PREFIX):
            # A range query (search, scan) is allowed if the requested area
            # overlaps a granted area (either contains or is contained by
            # it). The per-document filter then restricts which documents are
            # actually touched, so an overlap can never leak one the caller
            # may not access.
            return resource.identifier.startswith(
                expanded
            ) or expanded.startswith(resource.identifier)
        # A point resource (one document, file, or table) must sit under a
        # granted prefix, matched on component boundaries.
        return _covered_by_prefix(expanded, resource.identifier)


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
    # Corpus reads and search/scan over the whole corpus, plus outbound fetch.
    Grant(
        subject="*",
        actions=frozenset(
            {ACTION_SEARCH, ACTION_READ, ACTION_SCAN, ACTION_FETCH}
        ),
        prefix="",
    ),
    # Read queries against a real referenced table. Scoped to KIND_TABLE so a
    # tableless query (KIND_TABLELESS) is not granted by default.
    Grant(
        subject="*",
        actions=frozenset({ACTION_QUERY}),
        prefix="",
        kinds=frozenset({KIND_TABLE}),
    ),
    # Writes confined to the caller's own document namespace.
    Grant(
        subject="*",
        actions=frozenset({ACTION_WRITE}),
        prefix=f"{SUBJECT_TOKEN}/",
        kinds=frozenset({KIND_DOCUMENT}),
    ),
    # Repository reads and search, kept to the repo kinds so widening or
    # narrowing code access never touches document access. The repo jail
    # is read-only by construction, so no write grant exists for it.
    Grant(
        subject="*",
        actions=frozenset({ACTION_SEARCH, ACTION_READ}),
        prefix="",
        kinds=frozenset({KIND_REPO_FILE, KIND_REPO_PREFIX}),
    ),
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
        # actions and kinds must be lists; a bare string would silently become
        # a set of its characters and match nothing.
        if not isinstance(entry.get("actions"), list):
            raise PolicyError("grant actions must be a list")
        kinds = entry.get("kinds", [])
        if not isinstance(kinds, list):
            raise PolicyError("grant kinds must be a list")
        try:
            grants.append(
                Grant(
                    subject=str(entry["subject"]),
                    actions=frozenset(str(a) for a in entry["actions"]),
                    prefix=str(entry.get("prefix", "")),
                    kinds=frozenset(str(k) for k in kinds),
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
