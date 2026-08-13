"""The completion providers: wire shapes, hardening, and the factory.

Every failure path is checked for the property that matters: the key
never appears in any raised message, redirects are refused rather than
followed, and error text carries only a type name or a status code.
"""

import json

import httpx
import pytest

from arrowhead.config import Settings
from arrowhead.llm.anthropic_http import AnthropicProvider
from arrowhead.llm.base import CompletionError
from arrowhead.llm.factory import build_completion_provider
from arrowhead.llm.openai_http import OpenAICompatibleProvider

KEY = "sk-test-secret-key-value"


def anthropic_settings(**overrides) -> Settings:
    values = {
        "llm_provider": "anthropic",
        "llm_model": "claude-sonnet-5",
        "llm_api_key": KEY,
        "egress_allowed_hosts": "api.anthropic.com",
    }
    values.update(overrides)
    return Settings(**values)


def openai_settings(**overrides) -> Settings:
    values = {
        "llm_provider": "openai",
        "llm_endpoint": "http://127.0.0.1:11434/v1/chat/completions",
        "llm_model": "llama3",
        "llm_internal_hosts": "127.0.0.1:11434",
    }
    values.update(overrides)
    return Settings(**values)


def resolver(*ips):
    async def getaddrinfo(host, port, **kwargs):
        import socket

        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    return getaddrinfo


class TestAnthropicProvider:
    def transport(self, handler):
        return httpx.MockTransport(handler)

    async def test_happy_path_sends_key_header_and_joins_text(self):
        seen = {}

        def handler(request):
            seen["key"] = request.headers.get("x-api-key")
            seen["version"] = request.headers.get("anthropic-version")
            seen["host"] = request.headers.get("host")
            seen["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "content": [
                        {"type": "text", "text": "It parses "},
                        {"type": "text", "text": "and serves."},
                    ]
                },
            )

        provider = AnthropicProvider(
            anthropic_settings(),
            transport=self.transport(handler),
            getaddrinfo=resolver("93.184.216.34"),
        )
        answer = await provider.complete(
            "explain", system="be brief", max_tokens=64
        )
        assert answer == "It parses and serves."
        assert seen["key"] == KEY
        assert seen["version"]
        assert seen["host"] == "api.anthropic.com"
        assert seen["body"]["system"] == "be brief"
        assert seen["body"]["messages"] == [
            {"role": "user", "content": "explain"}
        ]

    async def test_redirect_is_refused_and_key_never_leaks(self):
        def handler(request):
            return httpx.Response(
                302, headers={"Location": "https://evil.example/steal"}
            )

        provider = AnthropicProvider(
            anthropic_settings(),
            transport=self.transport(handler),
            getaddrinfo=resolver("93.184.216.34"),
        )
        with pytest.raises(CompletionError) as excinfo:
            await provider.complete("x", max_tokens=16)
        assert "redirect" in str(excinfo.value)
        assert KEY not in str(excinfo.value)

    async def test_server_error_is_reduced_to_a_status_code(self):
        def handler(request):
            return httpx.Response(
                500, text=f"boom with {KEY} inside the body"
            )

        provider = AnthropicProvider(
            anthropic_settings(),
            transport=self.transport(handler),
            getaddrinfo=resolver("93.184.216.34"),
        )
        with pytest.raises(CompletionError) as excinfo:
            await provider.complete("x", max_tokens=16)
        message = str(excinfo.value)
        assert "500" in message
        assert KEY not in message
        assert "boom" not in message

    async def test_missing_model_or_key_refuses_at_construction(self):
        with pytest.raises(CompletionError):
            AnthropicProvider(anthropic_settings(llm_model=""))
        with pytest.raises(CompletionError):
            AnthropicProvider(anthropic_settings(llm_api_key=""))


class TestOpenAICompatibleProvider:
    async def test_local_endpoint_needs_the_internal_gate(self):
        provider = OpenAICompatibleProvider(
            openai_settings(llm_internal_hosts=""),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={})
            ),
        )
        with pytest.raises(CompletionError) as excinfo:
            await provider.complete("x", max_tokens=16)
        assert "refused" in str(excinfo.value)

    async def test_gated_local_endpoint_completes(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"role": "assistant", "content": "hi"}}
                    ]
                },
            )

        provider = OpenAICompatibleProvider(
            openai_settings(), transport=httpx.MockTransport(handler)
        )
        answer = await provider.complete("x", max_tokens=16)
        assert answer == "hi"
        # A local server needs no bearer; none is sent without a key.
        assert seen["auth"] is None
        assert seen["url"].startswith("http://127.0.0.1:11434/")

    async def test_shapeless_response_is_a_clean_error(self):
        provider = OpenAICompatibleProvider(
            openai_settings(),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"weird": True})
            ),
        )
        with pytest.raises(CompletionError, match="unexpected shape"):
            await provider.complete("x", max_tokens=16)


class TestFactory:
    def test_none_refuses_clearly(self):
        with pytest.raises(CompletionError, match="ARROWHEAD_LLM_PROVIDER"):
            build_completion_provider(Settings())

    def test_each_backend_constructs(self):
        assert isinstance(
            build_completion_provider(anthropic_settings()), AnthropicProvider
        )
        assert isinstance(
            build_completion_provider(openai_settings()),
            OpenAICompatibleProvider,
        )
