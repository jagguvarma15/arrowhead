import pytest

from arrowhead.authz.policy import (
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


def test_url_resources_ignore_prefix():
    policy = JailPolicy([Grant("*", frozenset({ACTION_READ}), "docs/")])
    url = Resource(kind="url", identifier="https://example.com/")
    assert policy.authorize("alice", ACTION_READ, url).allowed


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
