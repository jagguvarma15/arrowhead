"""Injected settings take effect for the duration of a block, for both plain
settings reads and the settings-derived authorizer, and are gone afterward.
"""

import pytest
from pydantic import ValidationError

from arrowhead.authz.enforce import get_authorizer
from arrowhead.authz.policy import ACTION_WRITE, KIND_DOCUMENT, Resource
from arrowhead.config import Settings, get_settings, use_settings


def test_injected_settings_are_active_only_inside_the_block():
    marker = "arrowhead-injected-corpus"
    injected = Settings(jail_root=marker)
    assert str(get_settings().jail_root) != marker
    with use_settings(injected):
        assert str(get_settings().jail_root) == marker
    assert str(get_settings().jail_root) != marker


def test_injected_settings_reach_the_authorizer():
    # Auth on with a policy that grants nothing: every write must be denied,
    # but only while the injected settings are active.
    injected = Settings(auth_enabled=True, authz_policy='{"grants": []}')
    resource = Resource(kind=KIND_DOCUMENT, identifier="service/notes.md")

    with use_settings(injected):
        decision = get_authorizer().authorize("service", ACTION_WRITE, resource)
    assert decision.allowed is False

    # Outside the block the default (auth disabled) authorizer allows the call.
    assert get_authorizer().authorize("service", ACTION_WRITE, resource).allowed


def test_malformed_egress_port_is_rejected_at_construction():
    with pytest.raises(ValidationError):
        Settings(egress_allowed_ports="8443,notaport")
    with pytest.raises(ValidationError):
        Settings(egress_allowed_ports="70000")
    assert Settings(egress_allowed_ports="8443, 9000").egress_allowed_ports_set() == {
        8443,
        9000,
    }
