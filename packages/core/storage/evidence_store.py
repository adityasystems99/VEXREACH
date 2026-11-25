"""File-backed evidence store preserving raw scanner outputs, OSV responses, SBOMs, and provenance."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packages.core.models.discovery import DiscoveryResult
from packages.core.utils.safe_path import calculate_file_sha256, safe_resolve_path

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]+$")


@dataclass(frozen=True)
class AssessmentArtifacts:
    """Paths to all persisted files for a single assessment."""

    assessment_dir: Path
    raw_trivy_vuln_path: Path
    sbom_cyclonedx_path: Path
    raw_osv_responses_path: Path
    assessment_json_path: Path
    provenance_path: Path
    reachability_analysis_path: Path | None = None
    call_graph_path: Path | None = None
    candidate_symbols_path: Path | None = None


class EvidenceStore:
    """Persists raw scanner & OSV artifacts alongside normalized assessment reports and SHA-256 hashes."""

    def __init__(self, base_output_dir: Path) -> None:
        self.base_output_dir = base_output_dir

    def prepare_artifacts(
        self,
        assessment_id: str,
        explicit_output_dir: Path | None = None,
    ) -> AssessmentArtifacts:
        """Create and validate the directory layout for an assessment."""
        if not _SAFE_ID_PATTERN.match(assessment_id):
            raise ValueError(f"Unsafe assessment_id format: '{assessment_id}'")

        if explicit_output_dir is not None:
            assessment_dir = explicit_output_dir.resolve()
        else:
            self.base_output_dir.mkdir(parents=True, exist_ok=True)
            assessment_dir = safe_resolve_path(self.base_output_dir, assessment_id)

        assessment_dir.mkdir(parents=True, exist_ok=True)

        return self._build_artifacts(assessment_dir)

    def persist_reachability_artifacts(
        self,
        artifacts: AssessmentArtifacts,
        report: Any,
        *,
        call_graph_artifact: dict[str, Any] | None = None,
        manifest: Any | None = None,
        write_standalone_provenance: bool = False,
    ) -> dict[str, str]:
        """Persist Python static reachability report, call graph, and symbol manifest."""
        artifacts.assessment_dir.mkdir(parents=True, exist_ok=True)
        hashes: dict[str, str] = {}

        reach_path = artifacts.reachability_analysis_path or safe_resolve_path(
            artifacts.assessment_dir, "reachability-analysis.json"
        )
        reach_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        hashes["reachability-analysis.json"] = calculate_file_sha256(reach_path)

        if call_graph_artifact is not None:
            cg_path = artifacts.call_graph_path or safe_resolve_path(
                artifacts.assessment_dir, "call-graph.json"
            )
            cg_path.write_text(
                json.dumps(call_graph_artifact, indent=2), encoding="utf-8"
            )
            hashes["call-graph.json"] = calculate_file_sha256(cg_path)

        if manifest is not None:
            sym_path = artifacts.candidate_symbols_path or safe_resolve_path(
                artifacts.assessment_dir, "candidate-symbols.json"
            )
            sym_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
            hashes["candidate-symbols.json"] = calculate_file_sha256(sym_path)

        if write_standalone_provenance:
            provenance_payload: dict[str, Any] = {
                "analysis_id": report.analysis_id,
                "analyzer_name": report.analyzer_name,
                "analyzer_version": report.analyzer_version,
                "language": report.language,
                "analyzed_at": report.analyzed_at.isoformat(),
                "source_snapshot_hash": report.source_snapshot_hash,
                "manifest_sha256": report.manifest_sha256,
                "reachability_state_counts": report.state_counts(),
                "evidence_hashes": hashes,
            }
            artifacts.provenance_path.write_text(
                json.dumps(provenance_payload, indent=2), encoding="utf-8"
            )

        return hashes

    @staticmethod
    def _build_artifacts(assessment_dir: Path) -> AssessmentArtifacts:
        return AssessmentArtifacts(
            assessment_dir=assessment_dir,
            raw_trivy_vuln_path=safe_resolve_path(assessment_dir, "raw-trivy-vuln.json"),
            sbom_cyclonedx_path=safe_resolve_path(assessment_dir, "sbom-cyclonedx.json"),
            raw_osv_responses_path=safe_resolve_path(assessment_dir, "raw-osv-responses.json"),
            assessment_json_path=safe_resolve_path(assessment_dir, "discovery-assessment.json"),
            provenance_path=safe_resolve_path(assessment_dir, "provenance.json"),
            reachability_analysis_path=safe_resolve_path(
                assessment_dir, "reachability-analysis.json"
            ),
            call_graph_path=safe_resolve_path(assessment_dir, "call-graph.json"),
            candidate_symbols_path=safe_resolve_path(
                assessment_dir, "candidate-symbols.json"
            ),
        )

    def persist_raw_osv_evidence(
        self,
        artifacts: AssessmentArtifacts,
        raw_payload: dict[str, Any],
    ) -> str:
        """Persist raw OSV API payloads to raw-osv-responses.json and return SHA-256 digest."""
        artifacts.assessment_dir.mkdir(parents=True, exist_ok=True)
        artifacts.raw_osv_responses_path.write_text(
            json.dumps(raw_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return calculate_file_sha256(artifacts.raw_osv_responses_path)

    def persist_assessment(
        self,
        artifacts: AssessmentArtifacts,
        result: DiscoveryResult,
    ) -> dict[str, str]:
        """Hash existing raw artifacts, embed hashes in DiscoveryResult, and write JSON reports."""
        evidence_hashes: dict[str, str] = {}

        if artifacts.raw_trivy_vuln_path.is_file():
            evidence_hashes["raw-trivy-vuln.json"] = calculate_file_sha256(
                artifacts.raw_trivy_vuln_path
            )

        if artifacts.sbom_cyclonedx_path.is_file():
            sbom_hash = calculate_file_sha256(artifacts.sbom_cyclonedx_path)
            evidence_hashes["sbom-cyclonedx.json"] = sbom_hash
            result.sbom.document_sha256 = sbom_hash
            result.sbom.document_path = str(artifacts.sbom_cyclonedx_path)

        if artifacts.raw_osv_responses_path.is_file():
            osv_hash = calculate_file_sha256(artifacts.raw_osv_responses_path)
            evidence_hashes["raw-osv-responses.json"] = osv_hash
            if result.intelligence is not None:
                result.intelligence.raw_osv_evidence_path = str(artifacts.raw_osv_responses_path)
                result.intelligence.raw_osv_sha256 = osv_hash

        if (
            artifacts.reachability_analysis_path is not None
            and artifacts.reachability_analysis_path.is_file()
        ):
            evidence_hashes["reachability-analysis.json"] = calculate_file_sha256(
                artifacts.reachability_analysis_path
            )
        if artifacts.call_graph_path is not None and artifacts.call_graph_path.is_file():
            evidence_hashes["call-graph.json"] = calculate_file_sha256(
                artifacts.call_graph_path
            )
        if (
            artifacts.candidate_symbols_path is not None
            and artifacts.candidate_symbols_path.is_file()
        ):
            evidence_hashes["candidate-symbols.json"] = calculate_file_sha256(
                artifacts.candidate_symbols_path
            )

        result.scan_metadata.evidence_hashes = dict(evidence_hashes)

        assessment_json = result.model_dump_json(indent=2)
        artifacts.assessment_json_path.write_text(assessment_json, encoding="utf-8")
        evidence_hashes["discovery-assessment.json"] = calculate_file_sha256(
            artifacts.assessment_json_path
        )

        provenance_payload: dict[str, Any] = {
            "assessment_id": result.assessment_id,
            "target_id": result.target.target_id,
            "target_path": result.target.target_path,
            "scanner_name": result.scan_metadata.scanner_name,
            "scanner_version": result.scan_metadata.scanner_version,
            "scan_status": result.scan_metadata.scan_status.value,
            "sbom_completeness": result.sbom.completeness_status.value,
            "scan_started_at": result.scan_metadata.scan_started_at.isoformat(),
            "scan_completed_at": (
                result.scan_metadata.scan_completed_at.isoformat()
                if result.scan_metadata.scan_completed_at
                else None
            ),
            "artifacts": evidence_hashes,
        }
        if result.intelligence is not None:
            provenance_payload["intelligence_status"] = (
                result.intelligence.intelligence_status.value
            )
            provenance_payload["intelligence_retrieved_at"] = (
                result.intelligence.retrieved_at.isoformat()
            )
        if result.reachability is not None:
            provenance_payload["reachability_analyzer"] = result.reachability.analyzer_name
            provenance_payload["reachability_analyzed_at"] = (
                result.reachability.analyzed_at.isoformat()
            )
            provenance_payload["reachability_state_counts"] = (
                result.reachability.state_counts()
            )
            provenance_payload["source_snapshot_hash"] = (
                result.reachability.source_snapshot_hash
            )

        artifacts.provenance_path.write_text(
            json.dumps(provenance_payload, indent=2),
            encoding="utf-8",
        )

        return evidence_hashes

    def load_assessment(
        self,
        assessment_id_or_dir: str | Path,
    ) -> tuple[DiscoveryResult, AssessmentArtifacts]:
        """Load a previously persisted DiscoveryResult by assessment_id or explicit directory path."""
        candidate = Path(assessment_id_or_dir)
        if candidate.is_dir() and (candidate / "discovery-assessment.json").is_file():
            assessment_dir = candidate.resolve()
        else:
            assessment_id = str(assessment_id_or_dir).strip()
            if not _SAFE_ID_PATTERN.match(assessment_id):
                raise ValueError(f"Unsafe or invalid assessment_id: '{assessment_id}'")
            assessment_dir = safe_resolve_path(self.base_output_dir, assessment_id)

        artifacts = self._build_artifacts(assessment_dir)
        if not artifacts.assessment_json_path.is_file():
            raise FileNotFoundError(
                f"Assessment file not found for '{assessment_id_or_dir}' at "
                f"{artifacts.assessment_json_path}"
            )

        raw_text = artifacts.assessment_json_path.read_text(encoding="utf-8")
        result = DiscoveryResult.model_validate_json(raw_text)
        return result, artifacts
