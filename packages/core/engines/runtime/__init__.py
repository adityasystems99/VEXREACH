"""Runtime trace ingestion and conservative symbol correlation (Milestone 10 foundation)."""

from __future__ import annotations

from packages.core.models.discovery import DiscoveryResult
from packages.core.models.extensions import (
    RuntimeEvidenceReport,
    RuntimeObservationRecord,
)


class RuntimeEvidenceCorrelator:
    """Correlates structured runtime symbol traces against discovered vulnerabilities."""

    def ingest_observations(
        self,
        discovery_result: DiscoveryResult,
        observations: list[RuntimeObservationRecord],
        *,
        coverage_percent: float | None = None,
    ) -> tuple[DiscoveryResult, RuntimeEvidenceReport, dict[str, list[str]]]:
        """Correlate observed symbols with candidate vulnerable symbols without asserting safety on misses."""
        observed_set = {obs.qualified_symbol for obs in observations}
        matched_vids: list[str] = []
        runtime_map: dict[str, list[str]] = {}

        if discovery_result.reachability is not None:
            for rr in discovery_result.reachability.results:
                if rr.candidate_symbol is None:
                    continue
                qname = rr.candidate_symbol.qualified_name
                if qname in observed_set:
                    if rr.vulnerability_id not in matched_vids:
                        matched_vids.append(rr.vulnerability_id)
                    runtime_map.setdefault(rr.vulnerability_id, []).append(qname)

        report = RuntimeEvidenceReport(
            assessment_id=discovery_result.assessment_id,
            observations=observations,
            matched_vulnerability_ids=matched_vids,
            instrumentation_coverage_percent=coverage_percent,
        )
        updated = discovery_result.model_copy(update={"runtime_evidence": report})
        return updated, report, runtime_map
