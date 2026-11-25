"""Continuous Evidence drift detector & selective reassessment planner (Milestone 11 foundation)."""

from __future__ import annotations

from pathlib import Path

from packages.core.analysis.python.discovery import PythonSourceDiscovery
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.extensions import (
    ContinuousReassessmentPlan,
    ReassessmentTriggerType,
)


class ContinuousEvidenceTracker:
    """Detects source, dependency, or runtime drift to schedule targeted reassessment."""

    def compute_reassessment_plan(
        self,
        discovery_result: DiscoveryResult,
        *,
        current_target_path: Path | str | None = None,
        updated_sbom_package_versions: dict[str, str] | None = None,
        new_advisory_vulns: list[str] | None = None,
    ) -> ContinuousReassessmentPlan:
        triggers: list[ReassessmentTriggerType] = []
        affected_pkgs: list[str] = []
        affected_vulns: list[str] = []
        engines: list[str] = []
        reasons: list[str] = []

        # 1. Source snapshot hash drift check
        if (
            discovery_result.reachability is not None
            and discovery_result.reachability.source_snapshot_hash
        ):
            target = Path(current_target_path or discovery_result.target.target_path)
            if target.exists():
                curr_hash = PythonSourceDiscovery().discover(target).source_snapshot_hash
                if curr_hash != discovery_result.reachability.source_snapshot_hash:
                    triggers.append(ReassessmentTriggerType.SOURCE_SNAPSHOT_DRIFT)
                    engines.extend(["reachability", "attack_path", "risk", "openvex"])
                    reasons.append("Python source snapshot SHA-256 changed since prior analysis.")

        # 2. Dependency version drift check
        if updated_sbom_package_versions:
            pkg_by_name = {p.name.lower(): p for p in discovery_result.packages}
            for pkg_name, new_ver in sorted(updated_sbom_package_versions.items()):
                old_pkg = pkg_by_name.get(pkg_name.lower())
                if old_pkg is None or old_pkg.version != new_ver:
                    triggers.append(ReassessmentTriggerType.SBOM_DEPENDENCY_DRIFT)
                    affected_pkgs.append(pkg_name)
                    for v in discovery_result.vulnerabilities:
                        if old_pkg and v.package_id == old_pkg.package_id:
                            affected_vulns.append(v.vulnerability_id)
            if affected_pkgs:
                engines.extend(["discovery", "intelligence", "reachability", "risk", "openvex"])
                reasons.append(f"Dependency changes detected for: {sorted(set(affected_pkgs))}.")

        # 3. Newly published advisory drift check
        if new_advisory_vulns:
            triggers.append(ReassessmentTriggerType.ADVISORY_DRIFT)
            affected_vulns.extend(new_advisory_vulns)
            engines.extend(["intelligence", "ai_intelligence", "reachability", "risk", "openvex"])
            reasons.append(f"New advisories published: {sorted(set(new_advisory_vulns))}.")

        dedup_engines = list(dict.fromkeys(engines))
        dedup_triggers = list(dict.fromkeys(triggers))
        req = len(dedup_triggers) > 0
        return ContinuousReassessmentPlan(
            assessment_id=discovery_result.assessment_id,
            reassessment_required=req,
            triggers=dedup_triggers,
            affected_packages=sorted(set(affected_pkgs)),
            affected_vulnerabilities=sorted(set(affected_vulns)),
            engines_to_rerun=dedup_engines,
            explanation=" ".join(reasons) if reasons else "No source, SBOM, or advisory drift detected.",
        )
