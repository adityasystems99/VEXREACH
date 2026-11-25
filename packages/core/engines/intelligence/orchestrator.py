"""Vulnerability Intelligence Engine orchestrating OSV lookup, caching, correlation, and persistence."""

from datetime import datetime, timezone
from typing import Any

from packages.core.config.settings import Settings, get_settings
from packages.core.engines.intelligence.correlator import (
    VulnerabilityCorrelator,
    normalize_vulnerability_id,
)
from packages.core.engines.intelligence.version_ranges import VersionRangeEvaluator
from packages.core.integrations.osv.client import OSVClient
from packages.core.integrations.osv.exceptions import OSVError, OSVNotFoundError
from packages.core.integrations.osv.mapper import map_osv_to_advisory, to_osv_ecosystem
from packages.core.integrations.osv.schemas import (
    OSVPackageSpec,
    OSVQueryRequest,
    OSVVulnerabilityStub,
)
from packages.core.models.discovery import DiscoveryResult, PackageRecord, VulnerabilityRecord
from packages.core.models.intelligence import (
    AdvisoryRecord,
    AffectedPackageRange,
    CorrelationEvidence,
    CorrelationOutcome,
    IntelligenceStatus,
    PackageQueryRecord,
    SeverityInfo,
    VersionMatchStatus,
    VulnerabilityIntelligence,
    VulnerabilityIntelligenceReport,
)
from packages.core.storage.advisory_cache import SQLiteAdvisoryCache
from packages.core.storage.evidence_store import AssessmentArtifacts, EvidenceStore
from packages.core.utils.logging import get_logger

logger = get_logger("intelligence.orchestrator")


def _build_package_query(pkg: PackageRecord) -> tuple[OSVQueryRequest | None, str, str | None]:
    """Build an OSV API v1 query request and canonical cache key for a PackageRecord.

    Returns:
        (OSVQueryRequest or None, query_type, error_or_None)
    """
    if pkg.purl and "@" in pkg.purl.split("?", 1)[0]:
        req = OSVQueryRequest(package=OSVPackageSpec(purl=pkg.purl))
        return req, "purl", None

    osv_eco = to_osv_ecosystem(pkg.ecosystem, pkg.purl)
    if osv_eco and pkg.version and pkg.version.strip():
        req = OSVQueryRequest(
            package=OSVPackageSpec(ecosystem=osv_eco, name=pkg.name),
            version=pkg.version.strip(),
        )
        return req, "ecosystem_name", None

    return (
        None,
        "ecosystem_name",
        (
            f"Skipped OSV package query for '{pkg.package_id}': missing versioned PURL "
            f"or supported OSV ecosystem/version (ecosystem='{pkg.ecosystem}', version='{pkg.version}')."
        ),
    )


def _package_query_cache_key(req: OSVQueryRequest) -> str:
    assert req.package is not None
    if req.package.purl:
        return f"purl:{req.package.purl}"
    return f"eco:{req.package.ecosystem}:{req.package.name}@{req.version or ''}"


def _pick_canonical_id(finding_id: str, advisories: list[AdvisoryRecord]) -> str:
    """Prefer an authoritative CVE ID across matched advisory IDs/aliases when present."""
    candidates = [finding_id]
    for adv in advisories:
        candidates.append(adv.advisory_id)
        candidates.extend(adv.aliases)

    for cand in candidates:
        norm = normalize_vulnerability_id(cand)
        if norm.startswith("CVE-"):
            return norm
    return normalize_vulnerability_id(finding_id)


def _dedup_severities(items: list[SeverityInfo]) -> list[SeverityInfo]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[SeverityInfo] = []
    for item in items:
        key = (item.scheme, item.score, item.source)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


class IntelligenceOrchestrator:
    """Enriches DiscoveryResult findings with authoritative OSV.dev intelligence."""

    def __init__(
        self,
        settings: Settings | None = None,
        osv_client: OSVClient | None = None,
        advisory_cache: SQLiteAdvisoryCache | None = None,
        correlator: VulnerabilityCorrelator | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._owns_client = osv_client is None
        self.osv_client = osv_client or OSVClient(
            base_url=self.settings.osv_api_base_url,
            timeout_seconds=self.settings.osv_timeout_seconds,
            max_response_bytes=self.settings.osv_max_response_bytes,
            batch_size=self.settings.osv_batch_size,
            max_pages=self.settings.osv_max_pages,
            max_retries=self.settings.osv_max_retries,
            user_agent=self.settings.osv_user_agent,
        )
        self.cache: SQLiteAdvisoryCache | None = (
            advisory_cache
            if advisory_cache is not None
            else (
                SQLiteAdvisoryCache(
                    db_path=self.settings.storage_path,
                    ttl_seconds=self.settings.osv_cache_ttl_seconds,
                )
                if self.settings.osv_cache_enabled
                else None
            )
        )
        self.correlator = correlator or VulnerabilityCorrelator(VersionRangeEvaluator())
        self.evidence_store = evidence_store or EvidenceStore(self.settings.default_output_dir)

    def __enter__(self) -> "IntelligenceOrchestrator":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the owned OSV HTTP client connection pool."""
        if self._owns_client:
            self.osv_client.close()

    def enrich(
        self,
        discovery_result: DiscoveryResult,
        artifacts: AssessmentArtifacts | None = None,
        refresh_cache: bool = False,
    ) -> DiscoveryResult:
        """Enrich a DiscoveryResult with OSV intelligence while preserving all original evidence."""
        retrieved_at = datetime.now(timezone.utc)
        warnings: list[str] = []
        errors: list[str] = []

        raw_osv_evidence: dict[str, Any] = {
            "assessment_id": discovery_result.assessment_id,
            "retrieved_at": retrieved_at.isoformat(),
            "api_base_url": self.settings.osv_api_base_url,
            "querybatch": [],
            "vulns": {},
            "not_found": [],
            "errors": [],
        }

        pkg_by_id = {pkg.package_id: pkg for pkg in discovery_result.packages}
        package_query_records: list[PackageQueryRecord] = []
        stubs_by_pkg_id: dict[str, list[OSVVulnerabilityStub]] = {}

        # Step 1: Build OSV batch queries for discovered packages (respecting cache)
        uncached_items: list[tuple[PackageRecord, OSVQueryRequest, str, str]] = []
        cache_hits = 0
        batch_queries_executed = 0
        individual_queries_executed = 0

        for pkg in discovery_result.packages:
            req, qtype, build_err = _build_package_query(pkg)
            if req is None:
                warnings.append(build_err or f"Skipped package query for '{pkg.package_id}'.")
                package_query_records.append(
                    PackageQueryRecord(
                        package_id=pkg.package_id,
                        query_type="ecosystem_name",
                        query_payload={"name": pkg.name, "ecosystem": pkg.ecosystem},
                        succeeded=False,
                        error=build_err,
                    )
                )
                continue

            cache_key = _package_query_cache_key(req)
            if self.cache is not None and not refresh_cache:
                cached_stubs = self.cache.get_package_stubs(cache_key, force_refresh=refresh_cache)
                if cached_stubs is not None:
                    cache_hits += 1
                    stubs_by_pkg_id[pkg.package_id] = cached_stubs
                    package_query_records.append(
                        PackageQueryRecord(
                            package_id=pkg.package_id,
                            query_type=qtype,  # type: ignore[arg-type]
                            query_payload=req.model_dump(exclude_none=True),
                            succeeded=True,
                            from_cache=True,
                            advisory_ids_found=[s.id for s in cached_stubs],
                        )
                    )
                    continue

            uncached_items.append((pkg, req, qtype, cache_key))

        if uncached_items:
            try:
                batch_stubs, raw_batch_resps, req_count = self.osv_client.query_batch(
                    [item[1] for item in uncached_items]
                )
                batch_queries_executed += req_count
                raw_osv_evidence["querybatch"].extend(raw_batch_resps)

                for (pkg, req, qtype, cache_key), stubs in zip(
                    uncached_items, batch_stubs, strict=True
                ):
                    stubs_by_pkg_id[pkg.package_id] = stubs
                    if self.cache is not None:
                        self.cache.put_package_stubs(cache_key, stubs, retrieved_at=retrieved_at)
                    package_query_records.append(
                        PackageQueryRecord(
                            package_id=pkg.package_id,
                            query_type=qtype,  # type: ignore[arg-type]
                            query_payload=req.model_dump(exclude_none=True),
                            succeeded=True,
                            from_cache=False,
                            advisory_ids_found=[s.id for s in stubs],
                        )
                    )
            except OSVError as err:
                err_msg = f"OSV batch package query failed: {err}"
                errors.append(err_msg)
                raw_osv_evidence["errors"].append(err_msg)
                logger.error(err_msg)
                for pkg, req, qtype, _ in uncached_items:
                    package_query_records.append(
                        PackageQueryRecord(
                            package_id=pkg.package_id,
                            query_type=qtype,  # type: ignore[arg-type]
                            query_payload=req.model_dump(exclude_none=True),
                            succeeded=False,
                            error=str(err),
                        )
                    )

        # Step 2: Collect unique advisory IDs from batch stubs first, then uncovered Trivy IDs
        expected_modified_by_id: dict[str, str | None] = {}
        for stubs in stubs_by_pkg_id.values():
            for stub in stubs:
                expected_modified_by_id[stub.id] = stub.modified

        # Step 3: Fetch/load full OSV advisory records (using SQLite cache + modified_at checks)
        advisories_by_id: dict[str, AdvisoryRecord] = {}
        advisories_by_norm_key: dict[str, list[AdvisoryRecord]] = {}
        not_found_ids: set[str] = set()
        failed_vuln_errors: dict[str, str] = {}

        def _index_advisory(adv: AdvisoryRecord) -> None:
            advisories_by_id[adv.advisory_id] = adv
            for ident in [adv.advisory_id, *adv.aliases]:
                norm = normalize_vulnerability_id(ident)
                advisories_by_norm_key.setdefault(norm, [])
                if adv not in advisories_by_norm_key[norm]:
                    advisories_by_norm_key[norm].append(adv)

        def _fetch_or_load_advisory(adv_id: str, expected_mod: str | None) -> None:
            nonlocal cache_hits, individual_queries_executed
            if self.cache is not None and not refresh_cache:
                cached = self.cache.get_advisory(
                    adv_id,
                    expected_modified=expected_mod,
                    force_refresh=refresh_cache,
                )
                if cached is not None:
                    osv_vuln, raw_dict, cached_at = cached
                    cache_hits += 1
                    raw_osv_evidence["vulns"][adv_id] = raw_dict
                    adv_record = map_osv_to_advisory(
                        osv_vuln,
                        retrieved_at=cached_at,
                        from_cache=True,
                    )
                    _index_advisory(adv_record)
                    return

            try:
                osv_vuln, raw_dict = self.osv_client.get_vulnerability(adv_id)
                individual_queries_executed += 1
                raw_osv_evidence["vulns"][adv_id] = raw_dict
                if self.cache is not None:
                    self.cache.put_advisory(
                        osv_vuln.id,
                        osv_vuln.modified,
                        raw_dict,
                        retrieved_at=retrieved_at,
                    )
                    if adv_id != osv_vuln.id:
                        self.cache.put_advisory(
                            adv_id,
                            osv_vuln.modified,
                            raw_dict,
                            retrieved_at=retrieved_at,
                        )
                adv_record = map_osv_to_advisory(
                    osv_vuln,
                    retrieved_at=retrieved_at,
                    from_cache=False,
                )
                _index_advisory(adv_record)
            except OSVNotFoundError:
                individual_queries_executed += 1
                not_found_ids.add(adv_id)
                raw_osv_evidence["not_found"].append(adv_id)
            except (OSVError, ValueError) as err:
                individual_queries_executed += 1
                err_msg = f"Failed retrieving OSV advisory '{adv_id}': {err}"
                failed_vuln_errors[adv_id] = err_msg
                errors.append(err_msg)
                raw_osv_evidence["errors"].append(err_msg)
                logger.warning(err_msg)

        # Fetch batch-discovered advisories first so alias coverage avoids redundant CVE lookups
        for adv_id, expected_mod in expected_modified_by_id.items():
            _fetch_or_load_advisory(adv_id, expected_mod)

        # Only query Trivy finding IDs individually if not already covered by fetched advisories/aliases
        extra_finding_ids: list[str] = []
        for finding in discovery_result.vulnerabilities:
            vid = finding.vulnerability_id
            norm_vid = normalize_vulnerability_id(vid)
            if (
                vid not in expected_modified_by_id
                and vid not in extra_finding_ids
                and norm_vid not in advisories_by_norm_key
            ):
                extra_finding_ids.append(vid)

        for adv_id in extra_finding_ids:
            _fetch_or_load_advisory(adv_id, None)

        # Step 4: Correlate each Trivy finding with retrieved OSV advisories
        enriched_records: list[VulnerabilityIntelligence] = []
        correlated_adv_ids_by_pkg: dict[str, set[str]] = {}

        for finding in discovery_result.vulnerabilities:
            pkg = pkg_by_id[finding.package_id]
            candidate_advisories = self._collect_candidates_for_finding(
                finding=finding,
                stubs=stubs_by_pkg_id.get(pkg.package_id, []),
                advisories_by_id=advisories_by_id,
                advisories_by_norm_key=advisories_by_norm_key,
            )

            (
                matched_advs,
                matched_ranges,
                evals,
                decisions,
                overall_corr,
                overall_ver,
                corr_warnings,
            ) = self.correlator.correlate_finding(
                finding=finding,
                package=pkg,
                candidate_advisories=candidate_advisories,
            )

            finding_warnings = list(corr_warnings)
            for adv in matched_advs:
                correlated_adv_ids_by_pkg.setdefault(pkg.package_id, set()).add(adv.advisory_id)

            finding_query_err = failed_vuln_errors.get(finding.vulnerability_id)
            if finding_query_err:
                finding_warnings.append(finding_query_err)
            elif finding.vulnerability_id in not_found_ids and not matched_advs:
                finding_warnings.append(
                    f"OSV returned 404 (not found) for '{finding.vulnerability_id}'; "
                    "original Trivy finding preserved without OSV advisory."
                )
            elif overall_corr == CorrelationOutcome.NO_MATCH:
                finding_warnings.append(
                    f"No matching OSV advisory correlated for '{finding.vulnerability_id}'; "
                    "original Trivy finding preserved."
                )

            if overall_ver == VersionMatchStatus.UNKNOWN and matched_advs:
                finding_warnings.append(
                    f"Version range status is UNKNOWN for '{finding.vulnerability_id}' "
                    f"on '{pkg.ecosystem}:{pkg.name}@{pkg.version}'."
                )

            aliases: list[str] = []
            fixed_versions: list[str] = []
            severities: list[SeverityInfo] = []
            for adv in matched_advs:
                aliases.extend(adv.aliases)
                severities.extend(adv.severity_information)
            for rng in matched_ranges:
                fixed_versions.extend(rng.fixed_versions)
            if finding.fixed_version:
                fixed_versions.append(finding.fixed_version)

            source_records = ["trivy"] + (["osv"] if matched_advs else [])

            if finding_query_err and not matched_advs:
                item_status = IntelligenceStatus.FAILED
            elif (
                not matched_advs
                or overall_corr in {CorrelationOutcome.PARTIAL_MATCH, CorrelationOutcome.CONFLICTING_EVIDENCE}
                or overall_ver == VersionMatchStatus.UNKNOWN
                or any(a.is_withdrawn for a in matched_advs)
            ):
                item_status = IntelligenceStatus.PARTIALLY_ENRICHED
            else:
                item_status = IntelligenceStatus.ENRICHED

            enriched_records.append(
                VulnerabilityIntelligence(
                    vulnerability_id=finding.vulnerability_id,
                    canonical_id=_pick_canonical_id(finding.vulnerability_id, matched_advs),
                    aliases=list(dict.fromkeys(aliases)),
                    package_id=pkg.package_id,
                    advisories=matched_advs,
                    affected_ranges=matched_ranges,
                    fixed_versions=list(dict.fromkeys(fixed_versions)),
                    severity_information=_dedup_severities(severities),
                    version_evaluations=evals,
                    correlation_decisions=decisions,
                    overall_correlation=overall_corr,
                    overall_version_status=overall_ver,
                    source_records=source_records,
                    intelligence_status=item_status,
                    retrieved_at=retrieved_at,
                    data_quality_warnings=list(dict.fromkeys(finding_warnings)),
                )
            )

        # Step 5: Surface OSV-only package-version advisories not already correlated to a Trivy finding
        for pkg in discovery_result.packages:
            seen_for_pkg = correlated_adv_ids_by_pkg.get(pkg.package_id, set())
            for stub in stubs_by_pkg_id.get(pkg.package_id, []):
                adv = advisories_by_id.get(stub.id)
                if adv is None or adv.advisory_id in seen_for_pkg:
                    continue
                if adv.is_withdrawn:
                    continue

                pkg_matched, pkg_ranges, pkg_evals, range_warnings = (
                    self.correlator.evaluate_package_against_advisory(pkg, adv)
                )
                agg_ver = self.correlator.version_evaluator.aggregate_statuses(pkg_evals)
                if pkg_matched is False or agg_ver == VersionMatchStatus.NOT_AFFECTED:
                    continue

                seen_for_pkg.add(adv.advisory_id)
                fixed_vers = list(
                    dict.fromkeys(fv for rng in pkg_ranges for fv in rng.fixed_versions)
                )
                decision = CorrelationEvidence(
                    advisory_id=adv.advisory_id,
                    outcome=CorrelationOutcome.PACKAGE_VERSION_MATCH,
                    reason=(
                        f"OSV package query for '{pkg.package_id}' matched advisory "
                        f"'{adv.advisory_id}' (version status: {agg_ver.value})."
                    ),
                    matched_identifiers=[adv.advisory_id],
                )
                item_warnings = list(range_warnings)
                if agg_ver == VersionMatchStatus.UNKNOWN:
                    item_warnings.append(
                        f"OSV matched '{pkg.package_id}' via batch query, but version range "
                        "evaluation remained UNKNOWN."
                    )

                enriched_records.append(
                    VulnerabilityIntelligence(
                        vulnerability_id=adv.advisory_id,
                        canonical_id=_pick_canonical_id(adv.advisory_id, [adv]),
                        aliases=list(adv.aliases),
                        package_id=pkg.package_id,
                        advisories=[adv],
                        affected_ranges=pkg_ranges,
                        fixed_versions=fixed_vers,
                        severity_information=_dedup_severities(adv.severity_information),
                        version_evaluations=pkg_evals,
                        correlation_decisions=[decision],
                        overall_correlation=CorrelationOutcome.PACKAGE_VERSION_MATCH,
                        overall_version_status=agg_ver,
                        source_records=["osv"],
                        intelligence_status=(
                            IntelligenceStatus.ENRICHED
                            if agg_ver == VersionMatchStatus.AFFECTED
                            else IntelligenceStatus.PARTIALLY_ENRICHED
                        ),
                        retrieved_at=retrieved_at,
                        data_quality_warnings=list(dict.fromkeys(item_warnings)),
                    )
                )

        # Step 6: Compute report summary and overall IntelligenceStatus
        dedup_warnings = list(dict.fromkeys(warnings))
        dedup_errors = list(dict.fromkeys(errors))
        unique_retrieved_advs = list(advisories_by_id.values())

        identifier_correlations = sum(
            1
            for rec in enriched_records
            if rec.overall_correlation
            in {
                CorrelationOutcome.EXACT_IDENTIFIER_MATCH,
                CorrelationOutcome.AUTHORITATIVE_ALIAS_MATCH,
            }
        )
        affected_ranges_evaluated = sum(len(rec.version_evaluations) for rec in enriched_records)
        conflicting_records = sum(
            1
            for rec in enriched_records
            if rec.overall_correlation == CorrelationOutcome.CONFLICTING_EVIDENCE
        )
        incomplete_records = sum(
            1
            for rec in enriched_records
            if rec.intelligence_status != IntelligenceStatus.ENRICHED
            or rec.overall_version_status == VersionMatchStatus.UNKNOWN
        )
        withdrawn_count = sum(1 for adv in unique_retrieved_advs if adv.is_withdrawn)

        overall_status = self._determine_overall_status(
            findings_count=len(discovery_result.vulnerabilities),
            package_queries=package_query_records,
            enriched_records=enriched_records,
            advisories_count=len(unique_retrieved_advs),
            errors=dedup_errors,
            conflicting_records=conflicting_records,
            incomplete_records=incomplete_records,
        )

        report = VulnerabilityIntelligenceReport(
            assessment_id=discovery_result.assessment_id,
            intelligence_status=overall_status,
            retrieved_at=retrieved_at,
            findings_discovered=len(discovery_result.vulnerabilities),
            advisories_retrieved=len(unique_retrieved_advs),
            identifier_correlations=identifier_correlations,
            affected_ranges_evaluated=affected_ranges_evaluated,
            conflicting_records=conflicting_records,
            incomplete_intelligence_records=incomplete_records,
            withdrawn_advisories=withdrawn_count,
            cache_hits=cache_hits,
            batch_queries_executed=batch_queries_executed,
            individual_queries_executed=individual_queries_executed,
            package_queries=package_query_records,
            vulnerabilities=enriched_records,
            warnings=dedup_warnings,
            errors=dedup_errors,
        )

        enriched_result = discovery_result.model_copy(update={"intelligence": report})

        # Step 7: Persist raw OSV responses and updated assessment JSON
        if artifacts is not None:
            raw_hash = self.evidence_store.persist_raw_osv_evidence(artifacts, raw_osv_evidence)
            report.raw_osv_evidence_path = str(artifacts.raw_osv_responses_path)
            report.raw_osv_sha256 = raw_hash
            self.evidence_store.persist_assessment(artifacts, enriched_result)

        return enriched_result

    @staticmethod
    def _collect_candidates_for_finding(
        finding: VulnerabilityRecord,
        stubs: list[OSVVulnerabilityStub],
        advisories_by_id: dict[str, AdvisoryRecord],
        advisories_by_norm_key: dict[str, list[AdvisoryRecord]],
    ) -> list[AdvisoryRecord]:
        candidates: list[AdvisoryRecord] = []
        seen_ids: set[str] = set()

        def _add(adv: AdvisoryRecord | None) -> None:
            if adv is not None and adv.advisory_id not in seen_ids:
                seen_ids.add(adv.advisory_id)
                candidates.append(adv)

        _add(advisories_by_id.get(finding.vulnerability_id))
        norm_id = normalize_vulnerability_id(finding.vulnerability_id)
        for adv in advisories_by_norm_key.get(norm_id, []):
            _add(adv)
        for stub in stubs:
            _add(advisories_by_id.get(stub.id))
        return candidates

    @staticmethod
    def _determine_overall_status(
        findings_count: int,
        package_queries: list[PackageQueryRecord],
        enriched_records: list[VulnerabilityIntelligence],
        advisories_count: int,
        errors: list[str],
        conflicting_records: int,
        incomplete_records: int,
    ) -> IntelligenceStatus:
        any_query_failed = any(not q.succeeded for q in package_queries)
        any_query_succeeded = any(q.succeeded for q in package_queries)

        if not enriched_records and findings_count == 0:
            if errors and not any_query_succeeded:
                return IntelligenceStatus.FAILED
            if errors or any_query_failed:
                return IntelligenceStatus.PARTIALLY_ENRICHED
            return IntelligenceStatus.NO_FINDINGS

        if advisories_count == 0 and errors:
            return IntelligenceStatus.FAILED

        if (
            errors
            or any_query_failed
            or conflicting_records > 0
            or incomplete_records > 0
            or any(rec.intelligence_status != IntelligenceStatus.ENRICHED for rec in enriched_records)
        ):
            return IntelligenceStatus.PARTIALLY_ENRICHED

        return IntelligenceStatus.ENRICHED
