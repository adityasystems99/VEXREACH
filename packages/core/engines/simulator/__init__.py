"""What-If Dependency Upgrade Security Simulator (Milestone 12 foundation)."""

from __future__ import annotations

from packages.core.engines.intelligence.version_ranges import VersionRangeEvaluator
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.extensions import (
    PackageUpgradeProposal,
    SimulatedVulnerabilityDelta,
    WhatIfSimulationReport,
)
from packages.core.models.intelligence import VersionMatchStatus


class WhatIfSimulator:
    """Projects OSV range resolution & impacted call sites without claiming full verification."""

    def __init__(self, range_evaluator: VersionRangeEvaluator | None = None) -> None:
        self._range_eval = range_evaluator or VersionRangeEvaluator()

    def simulate_upgrades(
        self,
        discovery_result: DiscoveryResult,
        proposals: list[PackageUpgradeProposal],
    ) -> WhatIfSimulationReport:
        pkg_by_id = {p.package_id: p for p in discovery_result.packages}
        intel_by_vid = (
            {v.vulnerability_id: v for v in discovery_result.intelligence.vulnerabilities}
            if discovery_result.intelligence is not None
            else {}
        )
        reach_by_vid: dict[str, list[str]] = {}
        if discovery_result.reachability is not None:
            for rr in discovery_result.reachability.results:
                if rr.candidate_symbol and rr.path:
                    reach_by_vid.setdefault(rr.vulnerability_id, []).append(
                        f"{rr.candidate_symbol.qualified_name} (via {' -> '.join(rr.path)})"
                    )

        deltas: list[SimulatedVulnerabilityDelta] = []
        impacted_sites: list[str] = []

        for proposal in proposals:
            prop_name = proposal.package_name.strip().lower()
            matching_pkgs = [
                p for p in discovery_result.packages if p.name.lower() == prop_name
            ]
            if not matching_pkgs:
                continue

            for pkg in matching_pkgs:
                pkg_vulns = [
                    v for v in discovery_result.vulnerabilities if v.package_id == pkg.package_id
                ]
                for vuln in pkg_vulns:
                    intel = intel_by_vid.get(vuln.vulnerability_id)
                    current_status = (
                        intel.overall_version_status.value
                        if intel
                        else VersionMatchStatus.UNKNOWN.value
                    )
                    projected_status = VersionMatchStatus.UNKNOWN.value
                    projected_outcome = "uncertain_range_evaluation"
                    note = "No OSV affected ranges available to evaluate target version cleanly."

                    if intel is not None and intel.affected_ranges:
                        evals = [
                            self._range_eval.evaluate_range(
                                advisory_id=intel.canonical_id,
                                package_id=pkg.package_id,
                                installed_version=proposal.target_version,
                                affected_range=rng,
                            )
                            for rng in intel.affected_ranges
                        ]
                        projected_enum = self._range_eval.aggregate_statuses(evals)
                        projected_status = projected_enum.value
                        if projected_enum == VersionMatchStatus.NOT_AFFECTED:
                            projected_outcome = "resolved_in_advisory_ranges"
                            note = (
                                f"Target version '{proposal.target_version}' is outside OSV affected ranges; "
                                "isolated test execution still required to confirm API compatibility."
                            )
                        elif projected_enum == VersionMatchStatus.AFFECTED:
                            projected_outcome = "remains_affected"
                            note = f"Target version '{proposal.target_version}' remains inside OSV affected range(s)."

                    if vuln.vulnerability_id in reach_by_vid:
                        impacted_sites.extend(reach_by_vid[vuln.vulnerability_id])

                    deltas.append(
                        SimulatedVulnerabilityDelta(
                            vulnerability_id=vuln.vulnerability_id,
                            package_name=pkg.name,
                            current_version=pkg.version,
                            proposed_version=proposal.target_version,
                            current_version_affected=current_status,
                            projected_version_affected=projected_status,
                            projected_status_change=projected_outcome,  # type: ignore[arg-type]
                            notes=note,
                        )
                    )

        return WhatIfSimulationReport(
            assessment_id=discovery_result.assessment_id,
            proposals=proposals,
            vulnerability_deltas=deltas,
            potentially_impacted_call_sites=sorted(set(impacted_sites)),
            validation_status="pending_isolated_test_verification",
        )
