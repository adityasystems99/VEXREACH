"""Discovery Engine orchestrator coordinating validation, scanning, parsing, and persistence."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from packages.core.config.settings import Settings, get_settings
from packages.core.engines.discovery.normalizer import DiscoveryNormalizer
from packages.core.engines.discovery.target_validator import (
    TargetValidationError,
    TargetValidator,
)
from packages.core.integrations.cyclonedx.parser import (
    CycloneDXParseError,
    CycloneDXParseResult,
    CycloneDXParser,
)
from packages.core.integrations.trivy.client import TrivyClient, TrivyError
from packages.core.integrations.trivy.parser import TrivyParseError, TrivyReport, TrivyReportParser
from packages.core.models.discovery import (
    AssessmentTarget,
    DiscoveryResult,
    SBOMCompletenessStatus,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
    TargetType,
)
from packages.core.storage.evidence_store import AssessmentArtifacts, EvidenceStore
from packages.core.utils.logging import get_logger

logger = get_logger("discovery.orchestrator")


class DiscoveryOrchestrator:
    """Coordinates the end-to-end Discovery workflow while preserving raw evidence and errors."""

    def __init__(
        self,
        settings: Settings | None = None,
        trivy_client: TrivyClient | None = None,
        target_validator: TargetValidator | None = None,
        cyclonedx_parser: CycloneDXParser | None = None,
        trivy_parser: TrivyReportParser | None = None,
        normalizer: DiscoveryNormalizer | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.trivy_client = trivy_client or TrivyClient(
            binary_path=self.settings.trivy_path,
            max_output_bytes=self.settings.max_scanner_output_bytes,
        )
        self.target_validator = target_validator or TargetValidator()
        self.cyclonedx_parser = cyclonedx_parser or CycloneDXParser()
        self.trivy_parser = trivy_parser or TrivyReportParser()
        self.normalizer = normalizer or DiscoveryNormalizer()
        self.evidence_store = evidence_store or EvidenceStore(self.settings.default_output_dir)

    def run_discovery(
        self,
        target_path: str | Path,
        output_dir: Path | None = None,
        timeout: int | None = None,
    ) -> tuple[DiscoveryResult, AssessmentArtifacts | None]:
        """Execute full filesystem discovery and return (DiscoveryResult, persisted artifacts)."""
        assessment_id = str(uuid4())
        scan_started_at = datetime.now(timezone.utc)
        effective_timeout = timeout if timeout is not None else self.settings.trivy_timeout_seconds

        errors: list[str] = []
        warnings: list[str] = []

        # Step 1: Validate target path without executing target code
        try:
            target = self.target_validator.validate(target_path)
        except TargetValidationError as err:
            errors.append(str(err))
            safe_raw = str(target_path).strip() or "<empty>"
            target = AssessmentTarget(
                target_id="invalid-target",
                target_path=safe_raw,
                target_type=TargetType.FILESYSTEM,
            )
            failed_result = self._build_failed_result(
                assessment_id=assessment_id,
                target=target,
                scan_started_at=scan_started_at,
                scanner_version=None,
                errors=errors,
                warnings=warnings,
            )
            artifacts = self._try_persist_failure(assessment_id, output_dir, failed_result, warnings)
            return failed_result, artifacts

        # Prepare evidence output directory
        artifacts = self.evidence_store.prepare_artifacts(
            assessment_id=assessment_id,
            explicit_output_dir=output_dir,
        )

        # Step 2: Check Trivy availability and detect version
        scanner_version: str | None = None
        try:
            version_info = self.trivy_client.get_version(timeout=min(15, effective_timeout))
            scanner_version = version_info.version
            logger.info("Detected Trivy version %s", scanner_version)
        except TrivyError as err:
            errors.append(str(err))
            failed_result = self._build_failed_result(
                assessment_id=assessment_id,
                target=target,
                scan_started_at=scan_started_at,
                scanner_version=None,
                errors=errors,
                warnings=warnings,
            )
            self.evidence_store.persist_assessment(artifacts, failed_result)
            return failed_result, artifacts

        canonical_target = Path(target.target_path)

        # Step 3: Generate CycloneDX SBOM via Trivy
        cdx_result: CycloneDXParseResult | None = None
        sbom_succeeded = False
        try:
            sbom_cmd_res = self.trivy_client.generate_cyclonedx_sbom(
                target_dir=canonical_target,
                output_file=artifacts.sbom_cyclonedx_path,
                timeout=effective_timeout,
            )
            cdx_result = self.cyclonedx_parser.parse(
                sbom_cmd_res.parsed_json,
                detected_manifests=target.detected_manifests,
            )
            warnings.extend(cdx_result.warnings)
            sbom_succeeded = True
        except (TrivyError, CycloneDXParseError) as err:
            errors.append(f"SBOM generation/parsing failed: {err}")
            logger.error("SBOM stage failed", extra={"error": str(err)})

        # Step 4: Execute Trivy filesystem vulnerability scan
        trivy_report: TrivyReport | None = None
        vuln_scan_succeeded = False
        try:
            vuln_cmd_res = self.trivy_client.scan_filesystem_vulnerabilities(
                target_dir=canonical_target,
                output_file=artifacts.raw_trivy_vuln_path,
                timeout=effective_timeout,
            )
            trivy_report = self.trivy_parser.parse(vuln_cmd_res.parsed_json)
            vuln_scan_succeeded = True
        except (TrivyError, TrivyParseError) as err:
            errors.append(f"Vulnerability scan/parsing failed: {err}")
            logger.error("Vulnerability scan stage failed", extra={"error": str(err)})

        # Step 5: Normalize available data and determine truthful scan_status
        detection_ts = datetime.now(timezone.utc)
        packages, vulnerabilities, sbom_pkg_ids, norm_warnings = self.normalizer.normalize(
            cyclonedx_result=cdx_result,
            trivy_report=trivy_report,
            detection_timestamp=detection_ts,
            scanner_source="trivy",
        )
        warnings.extend(norm_warnings)

        if not target.detected_manifests and not packages:
            warnings.append(
                "No recognized dependency manifests were found in target directory; "
                "zero packages discovered."
            )

        if sbom_succeeded and vuln_scan_succeeded:
            scan_status = ScanStatus.COMPLETED
        elif sbom_succeeded or vuln_scan_succeeded:
            scan_status = ScanStatus.PARTIAL
        else:
            scan_status = ScanStatus.FAILED

        sbom_record = SBOMRecord(
            format="cyclonedx",
            format_version=cdx_result.bom.spec_version if cdx_result else None,
            document_path=(
                str(artifacts.sbom_cyclonedx_path)
                if artifacts.sbom_cyclonedx_path.is_file()
                else None
            ),
            packages=sbom_pkg_ids,
            generation_timestamp=cdx_result.generation_timestamp if cdx_result else None,
            completeness_status=(
                cdx_result.completeness_status
                if cdx_result is not None
                else SBOMCompletenessStatus.FAILED
            ),
        )

        scan_completed_at = datetime.now(timezone.utc)
        dedup_warnings = list(dict.fromkeys(warnings))
        dedup_errors = list(dict.fromkeys(errors))

        result = DiscoveryResult(
            assessment_id=assessment_id,
            target=target,
            scan_metadata=ScanMetadata(
                scanner_name="trivy",
                scanner_version=scanner_version,
                scan_started_at=scan_started_at,
                scan_completed_at=scan_completed_at,
                scan_status=scan_status,
                errors=list(dedup_errors),
                warnings=list(dedup_warnings),
            ),
            sbom=sbom_record,
            packages=packages,
            vulnerabilities=vulnerabilities,
            warnings=dedup_warnings,
            errors=dedup_errors,
        )

        # Step 6: Persist raw + normalized artifacts & provenance
        self.evidence_store.persist_assessment(artifacts, result)
        return result, artifacts

    @staticmethod
    def _build_failed_result(
        assessment_id: str,
        target: AssessmentTarget,
        scan_started_at: datetime,
        scanner_version: str | None,
        errors: list[str],
        warnings: list[str],
    ) -> DiscoveryResult:
        return DiscoveryResult(
            assessment_id=assessment_id,
            target=target,
            scan_metadata=ScanMetadata(
                scanner_name="trivy",
                scanner_version=scanner_version,
                scan_started_at=scan_started_at,
                scan_completed_at=datetime.now(timezone.utc),
                scan_status=ScanStatus.FAILED,
                errors=list(errors),
                warnings=list(warnings),
            ),
            sbom=SBOMRecord(completeness_status=SBOMCompletenessStatus.FAILED),
            packages=[],
            vulnerabilities=[],
            warnings=list(warnings),
            errors=list(errors),
        )

    def _try_persist_failure(
        self,
        assessment_id: str,
        output_dir: Path | None,
        failed_result: DiscoveryResult,
        warnings: list[str],
    ) -> AssessmentArtifacts | None:
        try:
            artifacts = self.evidence_store.prepare_artifacts(
                assessment_id=assessment_id,
                explicit_output_dir=output_dir,
            )
            self.evidence_store.persist_assessment(artifacts, failed_result)
            return artifacts
        except OSError as err:
            warnings.append(f"Unable to persist failure assessment report: {err}")
            return None
