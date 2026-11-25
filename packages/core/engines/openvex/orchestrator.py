"""Evidence aggregation and OpenVEX 0.2.0 orchestration engine (Milestone 5)."""

from __future__ import annotations

from pathlib import Path

from packages.core.config.settings import Settings, get_settings
from packages.core.engines.openvex.validator import validate_openvex_document
from packages.core.models.discovery import DiscoveryResult
from packages.core.models.openvex import OpenVEXPolicyReport
from packages.core.policies.vex_policy import evaluate_vex_policy
from packages.core.storage.evidence_store import AssessmentArtifacts, EvidenceStore
from packages.core.storage.vex_history import SQLiteVEXStore
from packages.core.utils.logging import get_logger

logger = get_logger("openvex.orchestrator")


class OpenVEXOrchestrator:
    """Evaluates evidence policies, validates OpenVEX 0.2.0 documents, and tracks history."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        vex_history_store: SQLiteVEXStore | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._history = vex_history_store or SQLiteVEXStore(self._settings.storage_path)
        self._evidence_store = evidence_store

    def generate(
        self,
        discovery_result: DiscoveryResult,
        *,
        artifacts: AssessmentArtifacts | None = None,
        author: str = "VEXReach Deterministic Policy Engine",
        runtime_observations: dict[str, list[str]] | None = None,
    ) -> tuple[DiscoveryResult, OpenVEXPolicyReport]:
        """Evaluate accumulated evidence, validate OpenVEX JSON-LD, persist, and track version."""
        next_ver = self._history.next_version_for_target(discovery_result.target.target_path)
        report = evaluate_vex_policy(
            discovery_result,
            document_version=next_ver,
            author=author,
            runtime_observations=runtime_observations,
        )
        valid, errors = validate_openvex_document(report.openvex_document)
        if not valid:
            raise ValueError(f"Generated OpenVEX document failed schema validation: {errors}")

        report = report.model_copy(update={"schema_valid": valid, "schema_errors": errors})

        vex_file_path: Path | None = None
        if artifacts is not None and self._evidence_store is not None:
            hashes = self._evidence_store.persist_openvex_artifacts(artifacts, report)
            vex_file_path = artifacts.openvex_path
            report = report.model_copy(
                update={
                    "openvex_sha256": hashes.get("openvex.vex.json"),
                    "openvex_file_path": str(vex_file_path) if vex_file_path else None,
                }
            )

        doc_sha = self._history.record_document(
            target_path=discovery_result.target.target_path,
            assessment_id=discovery_result.assessment_id,
            document=report.openvex_document,
            status_counts=report.status_counts,
            document_file_path=vex_file_path,
        )
        if report.openvex_sha256 is None:
            report = report.model_copy(update={"openvex_sha256": doc_sha})

        updated_result = discovery_result.model_copy(update={"policy_evaluation": report})
        if artifacts is not None and self._evidence_store is not None:
            self._evidence_store.persist_assessment(
                artifacts=artifacts, result=updated_result
            )

        logger.info(
            "Generated OpenVEX v%d document (%s) status_counts=%s",
            report.openvex_document.version,
            report.openvex_document.id,
            report.status_counts,
        )
        return updated_result, report
