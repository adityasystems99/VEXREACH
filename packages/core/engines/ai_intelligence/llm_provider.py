"""Interchangeable LLM provider abstraction with retries, Gemini/OpenRouter, and isolation."""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from packages.core.config.settings import Settings, get_settings
from packages.core.utils.logging import get_logger

logger = get_logger("ai_intelligence.llm")

_FORBIDDEN_STATUS_KEYS: frozenset[str] = frozenset(
    {
        "vex_status",
        "status",
        "reachable",
        "is_reachable",
        "not_affected",
        "affected",
        "exploitable",
        "is_exploitable",
        "safe",
        "risk_score",
        "verdict",
    }
)
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


class CredentialMissingError(ValueError):
    """Raised explicitly when a hosted LLM provider requires an API key that is unset."""


class LLMAnalysisRequest(BaseModel):
    """Structured prompt payload sent to a configured LLM provider."""

    vulnerability_id: str
    package_name: str
    ecosystem: str
    system_prompt: str
    user_prompt: str
    max_tokens: int = 1200


class LLMProposedSymbol(BaseModel):
    """Unverified single candidate symbol returned by an LLM."""

    model_config = ConfigDict(extra="allow", strict=False)

    module: str = Field(..., min_length=1)
    qualified_name: str = Field(..., min_length=1)
    symbol_type: Literal["function", "method", "class", "attribute"] = "function"
    rationale: str = Field(default="")


class LLMAnalysisResponse(BaseModel):
    """Validated structured response extracted from an LLM provider."""

    provider_name: str
    model_name: str
    mechanism_summary: str = ""
    affected_component_hint: str | None = None
    proposed_symbols: list[LLMProposedSymbol] = Field(default_factory=list)
    unauthorized_verdict_stripped: bool = False
    warnings: list[str] = Field(default_factory=list)


class _RawLLMJSONPayload(BaseModel):
    model_config = ConfigDict(extra="allow", strict=False)

    mechanism_summary: str = ""
    affected_component_hint: str | None = None
    candidate_symbols: list[LLMProposedSymbol] = Field(default_factory=list)


def parse_llm_json_safely(
    raw_text: str, *, provider_name: str, model_name: str
) -> LLMAnalysisResponse:
    """Parse raw model text strictly, stripping any unauthorized security/VEX verdicts."""
    text = raw_text.strip()
    fence_match = _JSON_FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1)

    try:
        parsed_obj = json.loads(text)
    except json.JSONDecodeError as exc:
        return LLMAnalysisResponse(
            provider_name=provider_name,
            model_name=model_name,
            warnings=[f"LLM output was not valid JSON: {exc}"],
        )

    if not isinstance(parsed_obj, dict):
        return LLMAnalysisResponse(
            provider_name=provider_name,
            model_name=model_name,
            warnings=["LLM JSON root must be an object."],
        )

    warnings: list[str] = []
    unauthorized = False
    found_forbidden = sorted(k for k in parsed_obj if k.lower() in _FORBIDDEN_STATUS_KEYS)
    if found_forbidden:
        unauthorized = True
        warnings.append(
            f"LLM_UNAUTHORIZED_VERDICT_IGNORED: stripped disallowed verdict key(s) {found_forbidden}."
        )
        for bad_key in list(parsed_obj):
            if bad_key.lower() in _FORBIDDEN_STATUS_KEYS:
                parsed_obj.pop(bad_key, None)

    try:
        validated = _RawLLMJSONPayload.model_validate(parsed_obj)
    except ValidationError as exc:
        return LLMAnalysisResponse(
            provider_name=provider_name,
            model_name=model_name,
            unauthorized_verdict_stripped=unauthorized,
            warnings=[*warnings, f"LLM JSON schema validation error: {exc}"],
        )

    clean_proposals: list[LLMProposedSymbol] = []
    for cand in validated.candidate_symbols:
        extra_keys = set(cand.model_extra or {})
        nested_bad = sorted(k for k in extra_keys if k.lower() in _FORBIDDEN_STATUS_KEYS)
        if nested_bad:
            unauthorized = True
            warnings.append(
                f"LLM_UNAUTHORIZED_VERDICT_IGNORED: stripped nested verdict key(s) {nested_bad}."
            )
        clean_proposals.append(
            LLMProposedSymbol(
                module=cand.module.strip(),
                qualified_name=cand.qualified_name.strip(),
                symbol_type=cand.symbol_type,
                rationale=cand.rationale.strip(),
            )
        )

    return LLMAnalysisResponse(
        provider_name=provider_name,
        model_name=model_name,
        mechanism_summary=validated.mechanism_summary.strip(),
        affected_component_hint=(
            validated.affected_component_hint.strip()
            if validated.affected_component_hint
            else None
        ),
        proposed_symbols=clean_proposals,
        unauthorized_verdict_stripped=unauthorized,
        warnings=warnings,
    )


def _post_with_retries(
    client: httpx.Client,
    endpoint: str,
    *,
    json_payload: dict[str, object],
    headers: dict[str, str] | None = None,
    max_retries: int,
    max_response_bytes: int,
    sleep_fn: Callable[[float], None],
) -> httpx.Response:
    """Execute bounded POST with exponential backoff & Retry-After support."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            resp = client.post(endpoint, json=json_payload, headers=headers)
            if len(resp.content) > max_response_bytes:
                raise ValueError("LLM response exceeded configured byte limit.")
            if resp.status_code in {429, 502, 503, 504} and attempt < max_retries:
                retry_after_raw = resp.headers.get("retry-after")
                delay = (
                    min(float(retry_after_raw), 5.0)
                    if retry_after_raw and retry_after_raw.replace(".", "", 1).isdigit()
                    else min(0.5 * (2**attempt), 5.0)
                )
                sleep_fn(delay)
                continue
            return resp
        except httpx.HTTPError as exc:
            last_exc = exc
            if attempt < max_retries:
                sleep_fn(min(0.5 * (2**attempt), 5.0))
                continue
            raise
    assert last_exc is not None
    raise last_exc


class LLMProvider(ABC):
    """Interchangeable LLM provider interface with zero filesystem or shell access."""

    provider_name: str
    model_name: str
    is_local: bool = False

    @abstractmethod
    def analyze_structured(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        """Analyze advisory/patch context and return unverified candidate symbols."""

    def close(self) -> None:
        """Release underlying HTTP connections if owned by this provider."""

    def __enter__(self) -> "LLMProvider":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class DisabledLLMProvider(LLMProvider):
    """Offline no-op LLM provider leaving extraction purely deterministic."""

    def __init__(self) -> None:
        self.provider_name = "disabled"
        self.model_name = "none"
        self.is_local = True

    def analyze_structured(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        return LLMAnalysisResponse(
            provider_name=self.provider_name,
            model_name=self.model_name,
        )


class OpenAICompatibleLLMProvider(LLMProvider):
    """HTTP adapter for OpenAI, OpenRouter, Ollama (`/v1`), and vLLM chat completion APIs."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        provider_label: str = "openai_compatible",
        api_key: str | None = None,
        timeout_seconds: float = 45.0,
        max_retries: int = 2,
        max_response_bytes: int = 2 * 1024 * 1024,
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.provider_name = provider_label
        self.model_name = model
        self.is_local = "localhost" in base_url or "127.0.0.1" in base_url
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes
        self._sleep_fn = sleep_fn
        self._owns_client = http_client is None
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if "openrouter.ai" in self.base_url:
            headers["HTTP-Referer"] = "https://github.com/adityasystems99/VEXREACH"
            headers["X-Title"] = "VEXReach"
        self._headers = headers
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            headers=headers,
            follow_redirects=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def analyze_structured(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        endpoint = f"{self.base_url}/chat/completions"
        payload: dict[str, object] = {
            "model": self.model_name,
            "temperature": 0.0,
            "max_tokens": request.max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
        }
        try:
            resp = _post_with_retries(
                self._client,
                endpoint,
                json_payload=payload,
                headers=self._headers,
                max_retries=self._max_retries,
                max_response_bytes=self._max_response_bytes,
                sleep_fn=self._sleep_fn,
            )
            if resp.status_code >= 400:
                return LLMAnalysisResponse(
                    provider_name=self.provider_name,
                    model_name=self.model_name,
                    warnings=[f"LLM provider '{self.provider_name}' HTTP {resp.status_code}"],
                )
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
            return parse_llm_json_safely(
                content, provider_name=self.provider_name, model_name=self.model_name
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            return LLMAnalysisResponse(
                provider_name=self.provider_name,
                model_name=self.model_name,
                warnings=[f"LLM request failed safely: {exc}"],
            )


class AnthropicLLMProvider(LLMProvider):
    """HTTP adapter for Anthropic Messages API without external SDK lock-in."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.anthropic.com",
        model: str = "claude-3-5-sonnet-latest",
        api_key: str | None = None,
        timeout_seconds: float = 45.0,
        max_retries: int = 2,
        max_response_bytes: int = 2 * 1024 * 1024,
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.provider_name = "anthropic"
        self.model_name = model
        self.is_local = False
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes
        self._sleep_fn = sleep_fn
        self._owns_client = http_client is None
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if api_key:
            headers["x-api-key"] = api_key
        self._headers = headers
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            headers=headers,
            follow_redirects=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def analyze_structured(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        endpoint = f"{self.base_url}/v1/messages"
        payload: dict[str, object] = {
            "model": self.model_name,
            "max_tokens": request.max_tokens,
            "temperature": 0.0,
            "system": request.system_prompt,
            "messages": [{"role": "user", "content": request.user_prompt}],
        }
        try:
            resp = _post_with_retries(
                self._client,
                endpoint,
                json_payload=payload,
                headers=self._headers,
                max_retries=self._max_retries,
                max_response_bytes=self._max_response_bytes,
                sleep_fn=self._sleep_fn,
            )
            if resp.status_code >= 400:
                return LLMAnalysisResponse(
                    provider_name=self.provider_name,
                    model_name=self.model_name,
                    warnings=[f"Anthropic HTTP {resp.status_code}"],
                )
            body = resp.json()
            text_blocks = [
                blk.get("text", "")
                for blk in body.get("content", [])
                if isinstance(blk, dict) and blk.get("type") == "text"
            ]
            return parse_llm_json_safely(
                "\n".join(text_blocks),
                provider_name=self.provider_name,
                model_name=self.model_name,
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            return LLMAnalysisResponse(
                provider_name=self.provider_name,
                model_name=self.model_name,
                warnings=[f"Anthropic request failed safely: {exc}"],
            )


class GeminiLLMProvider(LLMProvider):
    """HTTP adapter for Google Gemini generateContent REST API using header API key auth."""

    def __init__(
        self,
        *,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        model: str = "gemini-2.5-flash",
        api_key: str | None = None,
        timeout_seconds: float = 45.0,
        max_retries: int = 2,
        max_response_bytes: int = 2 * 1024 * 1024,
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.provider_name = "gemini"
        self.model_name = model
        self.is_local = False
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes
        self._sleep_fn = sleep_fn
        self._owns_client = http_client is None
        headers = {"Content-Type": "application/json"}
        if api_key:
            # Send API key in header rather than query string to keep logs/URLs secret-free
            headers["x-goog-api-key"] = api_key
        self._headers = headers
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            headers=headers,
            follow_redirects=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def analyze_structured(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        endpoint = f"{self.base_url}/models/{self.model_name}:generateContent"
        payload: dict[str, object] = {
            "systemInstruction": {"parts": [{"text": request.system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": request.user_prompt}]}],
            "generationConfig": {
                "temperature": 0.0,
                "maxOutputTokens": request.max_tokens,
                "responseMimeType": "application/json",
            },
        }
        try:
            resp = _post_with_retries(
                self._client,
                endpoint,
                json_payload=payload,
                headers=self._headers,
                max_retries=self._max_retries,
                max_response_bytes=self._max_response_bytes,
                sleep_fn=self._sleep_fn,
            )
            if resp.status_code >= 400:
                return LLMAnalysisResponse(
                    provider_name=self.provider_name,
                    model_name=self.model_name,
                    warnings=[f"Gemini HTTP {resp.status_code}"],
                )
            body = resp.json()
            parts = body["candidates"][0]["content"]["parts"]
            text = "\n".join(p.get("text", "") for p in parts if isinstance(p, dict))
            return parse_llm_json_safely(
                text, provider_name=self.provider_name, model_name=self.model_name
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            return LLMAnalysisResponse(
                provider_name=self.provider_name,
                model_name=self.model_name,
                warnings=[f"Gemini request failed safely: {exc}"],
            )


ProviderFactory = Callable[[Settings, httpx.Client | None, bool], LLMProvider]
_CUSTOM_PROVIDER_REGISTRY: dict[str, ProviderFactory] = {}


def register_llm_provider(name: str, factory: ProviderFactory) -> None:
    """Register a custom interchangeable LLM provider adapter by name."""
    _CUSTOM_PROVIDER_REGISTRY[name.strip().lower()] = factory


def list_registered_llm_providers() -> list[str]:
    """Return built-in plus custom registered LLM provider names."""
    built_in = [
        "disabled",
        "heuristic",
        "openai",
        "openai_compatible",
        "openrouter",
        "anthropic",
        "gemini",
        "ollama",
    ]
    return sorted(set(built_in) | set(_CUSTOM_PROVIDER_REGISTRY))


def build_llm_provider(
    settings: Settings | None = None,
    http_client: httpx.Client | None = None,
    *,
    require_credentials: bool = False,
) -> LLMProvider:
    """Instantiate configured LLM provider with explicit missing-credential validation."""
    cfg = settings or get_settings()
    mode = cfg.llm_provider
    api_key = (
        cfg.llm_api_key.get_secret_value().strip() if cfg.llm_api_key else None
    ) or None

    if mode in _CUSTOM_PROVIDER_REGISTRY:
        return _CUSTOM_PROVIDER_REGISTRY[mode](cfg, http_client, require_credentials)

    if mode in {"disabled", "heuristic"}:
        return DisabledLLMProvider()

    if mode == "ollama":
        base_url = cfg.llm_api_base_url or "http://127.0.0.1:11434/v1"
        return OpenAICompatibleLLMProvider(
            base_url=base_url,
            model=cfg.llm_model,
            provider_label="ollama",
            api_key=api_key,
            timeout_seconds=cfg.llm_timeout_seconds,
            max_retries=cfg.llm_max_retries,
            max_response_bytes=cfg.llm_max_response_bytes,
            http_client=http_client,
        )

    if require_credentials and not api_key:
        raise CredentialMissingError(
            f"VEXREACH_LLM_API_KEY is required when VEXREACH_LLM_PROVIDER='{mode}'."
        )

    if mode in {"openai", "openai_compatible", "openrouter"}:
        default_url = (
            "https://openrouter.ai/api/v1"
            if mode == "openrouter"
            else "https://api.openai.com/v1"
        )
        base_url = cfg.llm_api_base_url or default_url
        return OpenAICompatibleLLMProvider(
            base_url=base_url,
            model=cfg.llm_model,
            provider_label=mode,
            api_key=api_key,
            timeout_seconds=cfg.llm_timeout_seconds,
            max_retries=cfg.llm_max_retries,
            max_response_bytes=cfg.llm_max_response_bytes,
            http_client=http_client,
        )

    if mode == "anthropic":
        base_url = cfg.llm_api_base_url or "https://api.anthropic.com"
        return AnthropicLLMProvider(
            base_url=base_url,
            model=cfg.llm_model,
            api_key=api_key,
            timeout_seconds=cfg.llm_timeout_seconds,
            max_retries=cfg.llm_max_retries,
            max_response_bytes=cfg.llm_max_response_bytes,
            http_client=http_client,
        )

    if mode == "gemini":
        base_url = (
            cfg.llm_api_base_url or "https://generativelanguage.googleapis.com/v1beta"
        )
        return GeminiLLMProvider(
            base_url=base_url,
            model=cfg.llm_model,
            api_key=api_key,
            timeout_seconds=cfg.llm_timeout_seconds,
            max_retries=cfg.llm_max_retries,
            max_response_bytes=cfg.llm_max_response_bytes,
            http_client=http_client,
        )

    return DisabledLLMProvider()
