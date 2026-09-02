"""The webhook notifier: parsed allowlist, gating, caps, wire behavior."""

import httpx
import pytest
from pydantic import ValidationError as PydanticValidationError

from arrowhead.auth.principal import as_principal
from arrowhead.config import Settings, get_settings
from arrowhead.errors import ToolError
from arrowhead.security.ssrf_guard import BlockedURLError
from arrowhead.tools.notify import _allowlisted, notify_webhook, post_webhook
from arrowhead.tools.registry import active_families

PUBLIC_IP = "93.184.216.34"
ALLOW = ("https://hooks.example.com/ci",)


class TestAllowlistMatching:
    def test_exact_and_boundary_paths_match(self):
        assert _allowlisted("https://hooks.example.com/ci", ALLOW)
        assert _allowlisted("https://hooks.example.com/ci/run/7", ALLOW)
        assert _allowlisted("https://hooks.example.com:443/ci", ALLOW)

    def test_path_prefix_creep_is_refused(self):
        assert not _allowlisted("https://hooks.example.com/cistern", ALLOW)
        assert not _allowlisted("https://hooks.example.com/", ALLOW)

    def test_host_tricks_are_refused(self):
        assert not _allowlisted(
            "https://hooks.example.com@evil.net/ci", ALLOW
        )
        assert not _allowlisted(
            "https://hooks.example.com.evil.net/ci", ALLOW
        )

    def test_scheme_and_port_must_match(self):
        assert not _allowlisted("http://hooks.example.com/ci", ALLOW)
        assert not _allowlisted("https://hooks.example.com:8443/ci", ALLOW)

    def test_trailing_slash_entry_covers_its_subtree(self):
        entries = ("https://hooks.example.com/ci/",)
        assert _allowlisted("https://hooks.example.com/ci/run", entries)
        assert not _allowlisted("https://hooks.example.com/ci", entries)


def test_malformed_allowlist_entry_fails_at_startup():
    with pytest.raises(PydanticValidationError):
        Settings(notify_allowlist="hooks.example.com/ci")


def test_notify_family_registers_only_with_an_allowlist(configure_env):
    configure_env(ARROWHEAD_PROFILE="docs")
    assert "notify" not in active_families()
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    assert "notify" in active_families()


async def test_unconfigured_allowlist_refuses_in_the_body():
    with as_principal("alice", {"notify:send"}):
        with pytest.raises(ToolError):
            await notify_webhook(
                url="https://hooks.example.com/ci", payload={}
            )


async def test_unlisted_url_is_refused(configure_env):
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    with as_principal("alice", {"notify:send"}):
        with pytest.raises(ToolError):
            await notify_webhook(url="https://elsewhere.net/ci", payload={})


async def test_payload_shape_and_size_are_enforced(configure_env):
    configure_env(
        ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci",
        ARROWHEAD_NOTIFY_MAX_PAYLOAD_BYTES="16",
    )
    with as_principal("alice", {"notify:send"}):
        with pytest.raises(ToolError):
            await notify_webhook(
                url="https://hooks.example.com/ci", payload="text"
            )
        with pytest.raises(ToolError):
            await notify_webhook(
                url="https://hooks.example.com/ci",
                payload={"big": "x" * 64},
            )


async def test_post_delivers_and_captures_the_response(
    configure_env, make_resolver
):
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["host"] = request.headers["host"]
        seen["body"] = request.content
        return httpx.Response(200, text="delivered \x1b[2J ok")

    result = await post_webhook(
        "https://hooks.example.com/ci",
        b'{"text": "done"}',
        get_settings(),
        transport=httpx.MockTransport(handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    assert seen == {
        "method": "POST",
        "host": "hooks.example.com",
        "body": b'{"text": "done"}',
    }
    assert result["status"] == 200
    assert "\x1b" not in result["response"]
    assert result["truncated"] is False


async def test_long_response_is_truncated_not_fatal(
    configure_env, make_resolver
):
    configure_env(
        ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci",
        ARROWHEAD_NOTIFY_MAX_RESPONSE_BYTES="8",
    )

    def handler(request):
        return httpx.Response(200, text="a longer body than eight bytes")

    result = await post_webhook(
        "https://hooks.example.com/ci",
        b"{}",
        get_settings(),
        transport=httpx.MockTransport(handler),
        getaddrinfo=make_resolver(PUBLIC_IP),
    )
    assert result["truncated"] is True
    assert len(result["response"]) <= 8


async def test_redirects_are_refused(configure_env, make_resolver):
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")

    def handler(request):
        return httpx.Response(
            302, headers={"location": "https://elsewhere.net/"}
        )

    with pytest.raises(BlockedURLError):
        await post_webhook(
            "https://hooks.example.com/ci",
            b"{}",
            get_settings(),
            transport=httpx.MockTransport(handler),
            getaddrinfo=make_resolver(PUBLIC_IP),
        )
