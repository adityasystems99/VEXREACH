"""Conservative vulnerability correlation engine between scanner findings and OSV advisories."""

import re

from packages.core.engines.discovery.normalizer import parse_purl
from packages.core.engines.intelligence.version_ranges import VersionRangeEvaluator
from packages.core.models.discovery import PackageRecord, VulnerabilityRecord
from packages.core.models.intelligence import (
    AdvisoryRecord,
    AffectedPackageRange,
    CorrelationEvidence,
    CorrelationOutcome,
    VersionEvaluationResult,
    VersionMatchStatus,
)

_PEP503_RE = re.compile(r"[-_.]+")


def normalize_vulnerability_id(raw_id: str) -> str:
    """Conservatively normalize canonical vulnerability identifier casing without altering tokens."""
    stripped = raw_id.strip()
    upper = stripped.upper()
    # Canonical uppercase prefixes for standard registries while preserving case-sensitive IDs elsewhere
    for prefix in ("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-", "DSA-", "DLA-", "ALSA-"):
        if upper.startswith(prefix):
            if prefix == "GHSA-":
                # GHSA suffixes are lowercase hexadecimal/alphanumeric: GHSA-xxxx-xxxx-xxxx
                return "GHSA-" + stripped[5:].lower()
            return upper
    return stripped


def normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalize package name using ecosystem naming rules (PEP 503 for PyPI)."""
    cleaned = name.strip()
    if ecosystem.strip().lower() == "pypi":
        return _PEP503_RE.sub("-", cleaned).lower()
    if ecosystem.strip().lower() in {"npm", "cargo"}:
        return cleaned.lower()
    return cleaned


def _package_matches_range(package: PackageRecord, affected: AffectedPackageRange) -> bool:
    """Determine if a PackageRecord corresponds to an AffectedPackageRange's package."""
    pkg_eco = package.ecosystem.strip().lower()
    aff_eco = affected.ecosystem.strip().lower()

    if pkg_eco != "unknown" and aff_eco != "unknown" and pkg_eco != aff_eco:
        return False

    # Check unversioned PURL match if both sides supply PURLs
    pkg_purl = parse_purl(package.purl)
    aff_purl = parse_purl(affected.purl)
    if pkg_purl and aff_purl:
        if (
            pkg_purl.ecosystem == aff_purl.ecosystem
            and normalize_package_name(pkg_purl.name, pkg_purl.ecosystem)
            == normalize_package_name(aff_purl.name, aff_purl.ecosystem)
            and (pkg_purl.namespace or "").lower() == (aff_purl.namespace or "").lower()
        ):
            return True

    effective_eco = pkg_eco if pkg_eco != "unknown" else aff_eco
    return normalize_package_name(package.name, effective_eco) == normalize_package_name(
        affected.package_name, effective_eco
    )


class VulnerabilityCorrelator:
    """Correlates scanner findings against OSV advisories while preserving conflicts."""

    def __init__(self, version_evaluator: VersionRangeEvaluator | None = None) -> None:
        self.version_evaluator = version_evaluator or VersionRangeEvaluator()

    def evaluate_package_against_advisory(
        self,
        package: PackageRecord,
        advisory: AdvisoryRecord,
    ) -> tuple[bool | None, list[AffectedPackageRange], list[VersionEvaluationResult], list[str]]:
        """Match package ranges inside advisory and evaluate installed_version against them.

        Returns:
            (package_matched_flag, matching_ranges, version_evaluations, warnings)
        """
        warnings: list[str] = []
        if not advisory.affected_ranges:
            warnings.append(
                f"Advisory '{advisory.advisory_id}' contains no affected package range entries."
            )
            return None, [], [], warnings

        matching_ranges = [
            rng for rng in advisory.affected_ranges if _package_matches_range(package, rng)
        ]
        if not matching_ranges:
            return False, [], [], warnings

        evaluations = [
            self.version_evaluator.evaluate_range(
                advisory_id=advisory.advisory_id,
                package_id=package.package_id,
                installed_version=package.version,
                affected_range=rng,
            )
            for rng in matching_ranges
        ]

        for rng in matching_ranges:
            if rng.last_affected_versions and not rng.fixed_versions:
                warnings.append(
                    f"Advisory '{advisory.advisory_id}' uses 'last_affected' without an explicit "
                    "'fixed' version boundary."
                )

        return True, matching_ranges, evaluations, warnings

    def correlate_finding(
        self,
        finding: VulnerabilityRecord,
        package: PackageRecord,
        candidate_advisories: list[AdvisoryRecord],
    ) -> tuple[
        list[AdvisoryRecord],
        list[AffectedPackageRange],
        list[VersionEvaluationResult],
        list[CorrelationEvidence],
        CorrelationOutcome,
        VersionMatchStatus,
        list[str],
    ]:
        """Correlate a single Trivy finding against candidate OSV advisories conservatively."""
        norm_finding_id = normalize_vulnerability_id(finding.vulnerability_id)
        matched_advisories: list[AdvisoryRecord] = []
        matched_ranges: list[AffectedPackageRange] = []
        all_evals: list[VersionEvaluationResult] = []
        decisions: list[CorrelationEvidence] = []
        warnings: list[str] = []

        for adv in candidate_advisories:
            norm_adv_id = normalize_vulnerability_id(adv.advisory_id)
            norm_aliases = {normalize_vulnerability_id(a): a for a in adv.aliases}

            exact_id_hit = norm_finding_id == norm_adv_id
            alias_hit = norm_finding_id in norm_aliases

            if not exact_id_hit and not alias_hit:
                # Never merge unrelated vulnerabilities solely because they share a package name.
                continue

            pkg_matched, pkg_ranges, pkg_evals, range_warnings = self.evaluate_package_against_advisory(
                package=package,
                advisory=adv,
            )
            warnings.extend(range_warnings)

            matched_advisories.append(adv)
            matched_ranges.extend(pkg_ranges)
            all_evals.extend(pkg_evals)

            agg_ver_status = self.version_evaluator.aggregate_statuses(pkg_evals)
            matched_ids = (
                [adv.advisory_id]
                if exact_id_hit
                else [adv.advisory_id, norm_aliases[norm_finding_id]]
            )

            conflicts: list[str] = []
            if adv.is_withdrawn:
                conflicts.append(
                    f"OSV advisory '{adv.advisory_id}' was withdrawn"
                    + (f" at {adv.withdrawn_at.isoformat()}" if adv.withdrawn_at else "")
                    + ", whereas scanner reported this vulnerability."
                )

            if pkg_matched is False:
                conflicts.append(
                    f"OSV advisory '{adv.advisory_id}' does not list package "
                    f"'{package.ecosystem}:{package.name}' in its affected entries."
                )
            elif pkg_matched is True and agg_ver_status == VersionMatchStatus.NOT_AFFECTED:
                conflicts.append(
                    f"OSV version ranges for '{adv.advisory_id}' indicate installed version "
                    f"'{package.version}' is NOT_AFFECTED, conflicting with scanner finding."
                )

            # Check fixed version discrepancy if both sources supply fixed versions
            if finding.fixed_version and pkg_ranges:
                osv_fixed = {fv for rng in pkg_ranges for fv in rng.fixed_versions}
                if osv_fixed and finding.fixed_version not in osv_fixed:
                    warnings.append(
                        f"Fixed version mismatch for '{finding.vulnerability_id}': "
                        f"scanner reported '{finding.fixed_version}', OSV lists {sorted(osv_fixed)}."
                    )

            if conflicts:
                decisions.append(
                    CorrelationEvidence(
                        advisory_id=adv.advisory_id,
                        outcome=CorrelationOutcome.CONFLICTING_EVIDENCE,
                        reason="; ".join(conflicts),
                        matched_identifiers=matched_ids,
                        conflicts=conflicts,
                    )
                )
                warnings.extend(conflicts)
            elif pkg_matched is None:
                decisions.append(
                    CorrelationEvidence(
                        advisory_id=adv.advisory_id,
                        outcome=CorrelationOutcome.PARTIAL_MATCH,
                        reason=(
                            f"Identifier matched '{adv.advisory_id}', but advisory lacks "
                            "package/range metadata to verify package impact."
                        ),
                        matched_identifiers=matched_ids,
                    )
                )
            elif exact_id_hit:
                decisions.append(
                    CorrelationEvidence(
                        advisory_id=adv.advisory_id,
                        outcome=CorrelationOutcome.EXACT_IDENTIFIER_MATCH,
                        reason=(
                            f"Exact identifier '{finding.vulnerability_id}' matched OSV advisory "
                            f"'{adv.advisory_id}' for package '{package.name}' "
                            f"(version status: {agg_ver_status.value})."
                        ),
                        matched_identifiers=matched_ids,
                    )
                )
            else:
                decisions.append(
                    CorrelationEvidence(
                        advisory_id=adv.advisory_id,
                        outcome=CorrelationOutcome.AUTHORITATIVE_ALIAS_MATCH,
                        reason=(
                            f"Scanner identifier '{finding.vulnerability_id}' matched authoritative "
                            f"alias in OSV advisory '{adv.advisory_id}' for package '{package.name}' "
                            f"(version status: {agg_ver_status.value})."
                        ),
                        matched_identifiers=matched_ids,
                    )
                )

        if not decisions:
            overall_outcome = CorrelationOutcome.NO_MATCH
            overall_ver_status = VersionMatchStatus.UNKNOWN
        else:
            outcomes = {d.outcome for d in decisions}
            if CorrelationOutcome.CONFLICTING_EVIDENCE in outcomes:
                overall_outcome = CorrelationOutcome.CONFLICTING_EVIDENCE
            elif CorrelationOutcome.EXACT_IDENTIFIER_MATCH in outcomes:
                overall_outcome = CorrelationOutcome.EXACT_IDENTIFIER_MATCH
            elif CorrelationOutcome.AUTHORITATIVE_ALIAS_MATCH in outcomes:
                overall_outcome = CorrelationOutcome.AUTHORITATIVE_ALIAS_MATCH
            elif CorrelationOutcome.PARTIAL_MATCH in outcomes:
                overall_outcome = CorrelationOutcome.PARTIAL_MATCH
            else:
                overall_outcome = CorrelationOutcome.PACKAGE_VERSION_MATCH

            overall_ver_status = self.version_evaluator.aggregate_statuses(all_evals)

        return (
            matched_advisories,
            matched_ranges,
            all_evals,
            decisions,
            overall_outcome,
            overall_ver_status,
            list(dict.fromkeys(warnings)),
        )
