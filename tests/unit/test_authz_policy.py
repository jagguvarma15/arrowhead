import pytest

from arrowhead.authz.policy import (
    ACTION_FETCH,
    ACTION_INGEST,
    ACTION_READ,
    ACTION_SCAN,
    ACTION_SEARCH,
    ACTION_WRITE,
    AllowAllAuthorizer,
    Grant,
    JailPolicy,
    PolicyError,
    Resource,
    build_authorizer,
    parse_policy,
)
from arrowhead.config import Settings


def doc(path):
    return Resource(kind="document", identifier=path)


def table(name):
    return Resource(kind="table", identifier=name)


def test_default_policy_denies_ingest():
    policy = build_authorizer(Settings(auth_enabled=True))
    assert not policy.authorize(
        "alice", ACTION_INGEST, table("doc_chunks")
    ).allowed


def test_a_grant_allows_ingest_on_its_table():
    policy = parse_policy(
        '{"grants": [{"subject": "*", "actions": ["ingest"], '
        '"kinds": ["table"], "prefix": "doc_chunks"}]}'
    )
    assert policy.authorize("alice", ACTION_INGEST, table("doc_chunks")).allowed
    assert not policy.authorize("alice", ACTION_INGEST, table("other")).allowed


def test_default_deny_when_no_grant_matches():
    policy = JailPolicy([])
    assert not policy.authorize("alice", ACTION_READ, doc("x.txt")).allowed


def test_wildcard_subject_and_action_grant():
    policy = JailPolicy([Grant("*", frozenset({"*"}), "")])
    assert policy.authorize("anyone", ACTION_WRITE, doc("a/b.txt")).allowed


def test_action_must_match():
    policy = JailPolicy([Grant("*", frozenset({ACTION_READ}), "")])
    assert policy.authorize("alice", ACTION_READ, doc("x.txt")).allowed
    assert not policy.authorize("alice", ACTION_WRITE, doc("x.txt")).allowed


def test_prefix_must_match():
    policy = JailPolicy([Grant("alice", frozenset({ACTION_WRITE}), "alice/")])
    assert policy.authorize("alice", ACTION_WRITE, doc("alice/note.txt")).allowed
    assert not policy.authorize("alice", ACTION_WRITE, doc("bob/note.txt")).allowed


def test_subject_token_expansion_scopes_each_caller_to_own_namespace():
    policy = JailPolicy(
        [Grant("*", frozenset({ACTION_WRITE}), "${subject}/")]
    )
    assert policy.authorize("alice", ACTION_WRITE, doc("alice/n.txt")).allowed
    assert not policy.authorize("alice", ACTION_WRITE, doc("bob/n.txt")).allowed


def url(identifier="https://example.com/"):
    return Resource(kind="url", identifier=identifier)


def test_url_fetch_ignores_prefix_but_needs_the_fetch_action():
    policy = JailPolicy([Grant("*", frozenset({ACTION_FETCH}), "docs/")])
    assert policy.authorize("alice", ACTION_FETCH, url()).allowed


def test_read_grant_does_not_permit_url_fetch():
    # A caller can read documents without being able to fetch outbound URLs,
    # which a read grant alone must not imply.
    policy = JailPolicy([Grant("*", frozenset({ACTION_READ}), "")])
    assert policy.authorize("alice", ACTION_READ, doc("x.txt")).allowed
    assert not policy.authorize("alice", ACTION_FETCH, url()).allowed


def test_point_prefix_matches_on_a_component_boundary():
    policy = JailPolicy([Grant("*", frozenset({ACTION_READ}), "notes")])
    assert policy.authorize("a", ACTION_READ, doc("notes")).allowed
    assert policy.authorize("a", ACTION_READ, doc("notes/x.txt")).allowed
    # a sibling that only shares the string prefix must not be reachable
    assert not policy.authorize("a", ACTION_READ, doc("notes-private/x")).allowed


def test_subject_with_traversal_is_refused_in_namespace_expansion():
    policy = JailPolicy([Grant("*", frozenset({ACTION_WRITE}), "${subject}/")])
    assert not policy.authorize("../evil", ACTION_WRITE, doc("../evil/x")).allowed


def test_kind_scoped_grant_separates_file_from_document():
    policy = JailPolicy(
        [Grant("*", frozenset({ACTION_READ}), "", frozenset({"document"}))]
    )
    assert policy.authorize("a", ACTION_READ, doc("x")).allowed
    assert not policy.authorize(
        "a", ACTION_READ, Resource(kind="file", identifier="x")
    ).allowed


def test_parse_policy_rejects_non_list_actions():
    with pytest.raises(PolicyError):
        parse_policy('{"grants": [{"subject": "*", "actions": "read"}]}')


def test_parse_policy_accepts_kinds():
    policy = parse_policy(
        '{"grants": [{"subject": "*", "actions": ["read"], '
        '"prefix": "", "kinds": ["document"]}]}'
    )
    assert policy.authorize("a", ACTION_READ, doc("x")).allowed
    assert not policy.authorize(
        "a", ACTION_READ, Resource(kind="file", identifier="x")
    ).allowed


def prefix(identifier):
    return Resource(kind="prefix", identifier=identifier)


def test_prefix_query_allowed_when_area_overlaps_grant():
    policy = JailPolicy([Grant("*", frozenset({ACTION_SEARCH}), "public/")])
    # requesting the whole corpus overlaps a grant on public/
    assert policy.authorize("alice", ACTION_SEARCH, prefix("")).allowed
    # requesting inside the granted area is allowed
    assert policy.authorize("alice", ACTION_SEARCH, prefix("public/sub")).allowed


def test_prefix_query_denied_when_area_disjoint_from_grant():
    policy = JailPolicy([Grant("*", frozenset({ACTION_SCAN}), "public/")])
    assert not policy.authorize("alice", ACTION_SCAN, prefix("secret/")).allowed


def test_parse_policy_round_trip():
    raw = (
        '{"grants": [{"subject": "alice", "actions": ["read", "write"], '
        '"prefix": "alice/"}]}'
    )
    policy = parse_policy(raw)
    assert policy.authorize("alice", ACTION_WRITE, doc("alice/x.txt")).allowed
    assert not policy.authorize("bob", ACTION_READ, doc("alice/x.txt")).allowed


@pytest.mark.parametrize(
    "raw",
    ["not json", "[]", '{"grants": "no"}', '{"grants": [{"subject": "a"}]}'],
)
def test_invalid_policy_rejected(raw):
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_build_authorizer_allows_all_when_auth_disabled():
    authorizer = build_authorizer(Settings(auth_enabled=False))
    assert isinstance(authorizer, AllowAllAuthorizer)
    assert authorizer.authorize("anon", ACTION_WRITE, doc("any.txt")).allowed


def test_default_policy_shares_reads_but_isolates_writes():
    authorizer = build_authorizer(Settings(auth_enabled=True))
    # any authenticated caller can read/search/scan the whole corpus
    assert authorizer.authorize("alice", ACTION_READ, doc("shared/x.txt")).allowed
    assert authorizer.authorize("alice", ACTION_SEARCH, doc("y.txt")).allowed
    assert authorizer.authorize("alice", ACTION_SCAN, doc("z.txt")).allowed
    # but writes are confined to the caller's own namespace
    assert authorizer.authorize("alice", ACTION_WRITE, doc("alice/n.txt")).allowed
    assert not authorizer.authorize(
        "alice", ACTION_WRITE, doc("bob/n.txt")
    ).allowed


def test_configured_policy_overrides_default():
    policy = '{"grants": [{"subject": "root", "actions": ["*"], "prefix": ""}]}'
    settings = Settings(auth_enabled=True, authz_policy=policy)
    authorizer = build_authorizer(settings)
    assert authorizer.authorize("root", ACTION_WRITE, doc("anywhere.txt")).allowed
    assert not authorizer.authorize("alice", ACTION_READ, doc("x.txt")).allowed
