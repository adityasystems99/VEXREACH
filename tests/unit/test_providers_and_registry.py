"""Unit tests for expanded LLM providers, retries, credential readiness, and plugin registry."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from packages.core.config.settings import Settings
from packages.core.engines.ai_intelligence import (
    CredentialMissingError,
    GeminiLLMProvider,
    LLMAnalysisRequest,
    OpenAICompatibleLLMProvider,
    build_llm_provider,
    list_registered_llm_providers,
)
from packages.core.integrations.registry import (
    IntegrationRegistry,
    WebhookNotificationSink,
)


@pytest.mark.unit
def test_gemini_openrouter_retries_and_credential_guard() -> None:
    # Hosted provider requires VEXREACH_LLM_API_KEY when strict credential check enabled
    with pytest.raises(CredentialMissingError, match="VEXREACH_LLM_API_KEY"):
        build_llm_provider(
            Settings(llm_provider="gemini", llm_api_key=None),
            require_credentials=True,
        )

    assert "gemini" in list_registered_llm_providers()
    assert "openrouter" in list_registered_llm_providers()

    req = LLMAnalysisRequest(
        vulnerability_id="CVE-2023-32681",
        package_name="requests",
        ecosystem="pypi",
        system_prompt="sys",
        user_prompt="usr",
    )

    calls = {"gemini": 0}

    def gemini_handler(request: httpx.Request) -> httpx.Response:
        calls["gemini"] += 1
        assert "key=" not in str(request.url)
        assert request.headers.get("x-goog-api-key") == "secret-gem-key"
        if calls["gemini"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "mechanism_summary": "Header redirect leak",
                                            "candidate_symbols": [
                                                {
                                                    "module": "requests",
                                                    "qualified_name": "requests.get",
                                                    "symbol_type": "function",
                                                }
                                            ],
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            },
        )

    gem = build_llm_provider(
        Settings(llm_provider="gemini", llm_model="gemini-2.5-flash", llm_api_key=SecretStr("secret-gem-key")),
        http_client=httpx.Client(transport=httpx.MockTransport(gemini_handler)),
    )
    assert isinstance(gem, GeminiLLMProvider)
    gem_resp = gem.analyze_structured(req)
    assert calls["gemini"] == 2
    assert gem_resp.proposed_symbols[0].qualified_name == "requests.get"

    def openrouter_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-Title") == "VEXReach"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "mechanism_summary": "YAML code exec",
                                    "candidate_symbols": [
                                        {"module": "yaml", "qualified_name": "yaml.load", "symbol_type": "function"}
                                    ],
                                }
                            )
                        }
                    }
                ]
            },
        )

    or_provider = build_llm_provider(
        Settings(llm_provider="openrouter", llm_api_key=SecretStr("or-key")),
        http_client=httpx.Client(transport=httpx.MockTransport(openrouter_handler)),
    )
    assert isinstance(or_provider, OpenAICompatibleLLMProvider)
    assert or_provider.provider_name == "openrouter"
    assert or_provider.analyze_structured(req).proposed_symbols[0].qualified_name == "yaml.load"


@pytest.mark.unit
def test_integration_registry_and_ssrf_safe_webhook_sink() -> None:
    registry = IntegrationRegistry()
    items = registry.inspect_all(Settings(llm_provider="disabled"))
    by_id = {i.integration_id: i for i in items}
    assert by_id["osv_dev"].configured is True
    assert by_id["kubernetes_backend"].enabled is False

    # Webhook sink rejects HTTP, private IPs, and non-allowlisted domains
    bad_http = WebhookNotificationSink("http://hooks.slack.com/services/a/b/c")
    assert bad_http.validate_destination()[0] is False

    bad_ip = WebhookNotificationSink("https://169.254.169.254/hook")
    assert bad_ip.validate_destination()[0] is False

    def ok_handler(request: httpx.Request) -> httpx.Response:
        assert "X-VEXReach-Signature-256" in request.headers
        return httpx.Response(200, json={"ok": True})

    good = WebhookNotificationSink(
        "https://hooks.slack.com/services/T0/B0/X",
        signing_secret="hmac-secret",
        http_client=httpx.Client(transport=httpx.MockTransport(ok_handler)),
    )
    assert good.send_event({"event": "assessment_completed"}) is True
