# VEXReach Credentials, LLM Providers & Integrations Guide

VEXReach works out-of-the-box with **zero paid credentials or Kubernetes cluster access**. Deterministic filesystem scanning, OSV vulnerability lookups, Python static reachability, attack-path tracing, risk scoring (via local or public EPSS/KEV feeds), and fail-closed OpenVEX generation all execute without an LLM key.

---

## Configuration & `.env.example`

Copy `.env.example` to `.env` when configuring optional hosted providers or server authentication:

```bash
cp .env.example .env
```

All sensitive secrets use Pydantic `SecretStr` (`VEXREACH_LLM_API_KEY`, `VEXREACH_API_KEYS`) so credentials are never echoed in logs or `repr()` diagnostics.

---

## Supported LLM Providers (`VEXREACH_LLM_PROVIDER`)

| Provider Value | Protocol / Endpoint | Credential Required? | Local Option |
| --- | --- | --- | --- |
| `disabled` (default) | Offline AST + heuristic symbol extraction only | No | Yes |
| `heuristic` | Same offline deterministic mode | No | Yes |
| `ollama` | OpenAI-compatible (`/chat/completions`, default `http://127.0.0.1:11434/v1`) | Optional | Yes |
| `openai` | OpenAI Chat Completions (`https://api.openai.com/v1`) | Yes (`VEXREACH_LLM_API_KEY`) | No |
| `openai_compatible` | Custom `/v1/chat/completions` (vLLM, LiteLLM, etc.) | Depends on host | Optional |
| `openrouter` | OpenRouter API (`https://openrouter.ai/api/v1`) | Yes (`VEXREACH_LLM_API_KEY`) | No |
| `anthropic` | Anthropic Messages (`/v1/messages`) | Yes (`VEXREACH_LLM_API_KEY`) | No |
| `gemini` | Google Gemini `generateContent` (`x-goog-api-key` header) | Yes (`VEXREACH_LLM_API_KEY`) | No |

### Strict Security Boundary
LLMs may ONLY propose candidate symbols or technical summaries from quarantined prompts. All unauthorized keys (`vex_status`, `not_affected`, `reachable`, `exploitable`, `risk_score`) are stripped and ignored, and all outputs undergo deterministic AST validation.
