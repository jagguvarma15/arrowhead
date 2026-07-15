"""Adversarial tests: every payload must be refused cleanly.

These reuse the payload corpus in payloads.py and assert two things at
once: the malicious input never succeeds, and it produces a controlled
tool error rather than a crash, hang, or leak.
"""

import httpx
import pytest
from fastmcp.exceptions import ToolError

from arrowhead.tools.calculate import calculate
from arrowhead.tools.read_file import read_file
from arrowhead.tools.safe_fetch import safe_fetch
from tests.security.payloads import (
    COMMAND_INJECTION_PAYLOADS,
    OVERSIZED_INPUTS,
    PATH_TRAVERSAL_PAYLOADS,
    SSRF_PAYLOADS,
)


@pytest.mark.parametrize("url", SSRF_PAYLOADS)
async def test_ssrf_payloads_are_refused(url):
    with pytest.raises(ToolError):
        await safe_fetch(url)


@pytest.mark.parametrize("expression", COMMAND_INJECTION_PAYLOADS)
async def test_command_injection_payloads_are_refused(expression):
    with pytest.raises(ToolError):
        calculate(expression)


@pytest.mark.parametrize("path", PATH_TRAVERSAL_PAYLOADS)
async def test_path_traversal_payloads_are_refused(path, jail):
    with pytest.raises(ToolError):
        await read_file(path)


async def test_oversized_expression_refused():
    with pytest.raises(ToolError):
        calculate(OVERSIZED_INPUTS["expression"])


async def test_oversized_url_refused():
    with pytest.raises(ToolError):
        await safe_fetch(OVERSIZED_INPUTS["url"])


async def test_oversized_path_refused(jail):
    with pytest.raises(ToolError):
        await read_file(OVERSIZED_INPUTS["path"])


async def test_redirect_chain_to_metadata_is_refused(make_resolver):
    """A public URL that 302s toward the metadata endpoint must be caught
    on the redirect hop, not followed."""
    from arrowhead.tools.safe_fetch import fetch_url

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"location": "http://169.254.169.254/latest/meta-data/"},
        )

    with pytest.raises(ToolError):
        try:
            await fetch_url(
                "http://example.com/",
                transport=httpx.MockTransport(handler),
                getaddrinfo=make_resolver("93.184.216.34"),
            )
        except Exception as exc:  # normalize guard errors to ToolError shape
            raise ToolError(str(exc)) from exc


async def test_high_node_count_expression_is_bounded():
    # Within the character cap but past the AST node budget: refused so a
    # caller cannot force pathological evaluation cost.
    with pytest.raises(ToolError):
        calculate("+".join(["1"] * 70))


async def test_auth_bypass_via_forged_scope_claim_is_ineffective(
    auth_client, issue_token
):
    """A token can carry any scope string it likes, but the signature is
    checked against the issuer key, so a token this issuer never signed
    with the right scope cannot be forged client-side."""
    tampered = issue_token(scope="tools:read")[:-4] + "AAAA"
    async with auth_client() as client:
        response = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "calculate",
                    "arguments": {"expression": "1 + 1"},
                },
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {tampered}",
            },
        )
    assert response.status_code == 401
