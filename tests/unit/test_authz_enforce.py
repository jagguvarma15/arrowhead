import pytest

from arrowhead.authz.enforce import (
    AuthorizationError,
    authorize_action,
    get_authorizer,
)
from arrowhead.authz.policy import ACTION_READ, ACTION_WRITE, Resource


def doc(path):
    return Resource(kind="document", identifier=path)


def set_identity(monkeypatch, subject):
    monkeypatch.setattr(
        "arrowhead.authz.enforce.caller_identity", lambda: subject
    )


def test_allows_when_auth_disabled(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "false")
    get_authorizer.cache_clear()
    set_identity(monkeypatch, "anonymous")
    assert authorize_action(ACTION_WRITE, doc("anything.txt")) == "anonymous"


def test_denies_cross_subject_write_under_default_policy(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    get_authorizer.cache_clear()
    set_identity(monkeypatch, "alice")
    # alice may write her own namespace
    assert authorize_action(ACTION_WRITE, doc("alice/n.txt")) == "alice"
    # but not bob's
    with pytest.raises(AuthorizationError):
        authorize_action(ACTION_WRITE, doc("bob/n.txt"))


def test_read_shared_under_default_policy(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    get_authorizer.cache_clear()
    set_identity(monkeypatch, "alice")
    assert authorize_action(ACTION_READ, doc("bob/n.txt")) == "alice"


def test_denial_message_does_not_echo_resource(monkeypatch):
    monkeypatch.setenv("ARROWHEAD_AUTH_ENABLED", "true")
    get_authorizer.cache_clear()
    set_identity(monkeypatch, "alice")
    with pytest.raises(AuthorizationError) as excinfo:
        authorize_action(ACTION_WRITE, doc("secret/plans.txt"))
    assert "secret/plans.txt" not in str(excinfo.value)
