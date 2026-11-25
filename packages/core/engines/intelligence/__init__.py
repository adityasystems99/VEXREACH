"""VEXReach Vulnerability Intelligence Engine."""

from packages.core.engines.intelligence.correlator import (
    VulnerabilityCorrelator,
    normalize_package_name,
    normalize_vulnerability_id,
)
from packages.core.engines.intelligence.orchestrator import IntelligenceOrchestrator
from packages.core.engines.intelligence.version_ranges import VersionRangeEvaluator

__all__ = [
    "IntelligenceOrchestrator",
    "VulnerabilityCorrelator",
    "VersionRangeEvaluator",
    "normalize_package_name",
    "normalize_vulnerability_id",
]
