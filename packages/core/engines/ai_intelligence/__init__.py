"""AI Security Intelligence Engine package (Milestone 3)."""

from packages.core.engines.ai_intelligence.llm_provider import (
    AnthropicLLMProvider,
    CredentialMissingError,
    DisabledLLMProvider,
    GeminiLLMProvider,
    LLMAnalysisRequest,
    LLMAnalysisResponse,
    LLMProposedSymbol,
    LLMProvider,
    OpenAICompatibleLLMProvider,
    build_llm_provider,
    list_registered_llm_providers,
    parse_llm_json_safely,
    register_llm_provider,
)
from packages.core.engines.ai_intelligence.orchestrator import (
    AISecurityIntelligenceOrchestrator,
    extract_advisory_symbol_hints,
)
from packages.core.engines.ai_intelligence.patch_fetcher import (
    PatchFetcher,
    PatchFetchResult,
    normalize_patch_url,
)
from packages.core.engines.ai_intelligence.patch_parser import (
    UnifiedDiffFile,
    UnifiedDiffHunk,
    compare_python_ast_versions,
    extract_patch_record,
    parse_unified_diff,
)
from packages.core.engines.ai_intelligence.sanitizer import PromptSanitizer
from packages.core.engines.ai_intelligence.validator import (
    CandidateSymbolValidator,
    ValidationBatchResult,
)

__all__ = [
    "AISecurityIntelligenceOrchestrator",
    "AnthropicLLMProvider",
    "CandidateSymbolValidator",
    "CredentialMissingError",
    "DisabledLLMProvider",
    "GeminiLLMProvider",
    "LLMAnalysisRequest",
    "LLMAnalysisResponse",
    "LLMProposedSymbol",
    "LLMProvider",
    "OpenAICompatibleLLMProvider",
    "list_registered_llm_providers",
    "register_llm_provider",
    "PatchFetchResult",
    "PatchFetcher",
    "PromptSanitizer",
    "UnifiedDiffFile",
    "UnifiedDiffHunk",
    "ValidationBatchResult",
    "build_llm_provider",
    "compare_python_ast_versions",
    "extract_advisory_symbol_hints",
    "extract_patch_record",
    "normalize_patch_url",
    "parse_llm_json_safely",
    "parse_unified_diff",
]
