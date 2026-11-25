"""VEXReach Discovery Engine: target validation, normalization, and orchestration."""

from packages.core.engines.discovery.normalizer import (
    DiscoveryNormalizer,
    ParsedPURL,
    normalize_cvss,
    normalize_ecosystem,
    normalize_severity,
    parse_purl,
)
from packages.core.engines.discovery.orchestrator import DiscoveryOrchestrator
from packages.core.engines.discovery.target_validator import (
    TargetValidationError,
    TargetValidator,
)

__all__ = [
    "DiscoveryNormalizer",
    "DiscoveryOrchestrator",
    "ParsedPURL",
    "TargetValidationError",
    "TargetValidator",
    "normalize_cvss",
    "normalize_ecosystem",
    "normalize_severity",
    "parse_purl",
]
