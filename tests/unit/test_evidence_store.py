"""Unit tests for file-backed EvidenceStore persistence and provenance hashing."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from packages.core.models.discovery import (
    AssessmentTarget,
    DiscoveryResult,
    SBOMCompletenessStatus,
    SBOMRecord,
    ScanMetadata,
    ScanStatus,
)
from packages.core.storage.evidence_store import EvidenceStore


@pytest.mark.unit
def test_evidence_store_persists_artifacts_and_hashes(tmp_path: Path) -> None:
    """EvidenceStore writes assessment + provenance JSON with SHA-256 hashes of raw artifacts."""
    store = EvidenceStore(base_output_dir=tmp_path)
    artifacts = store.prepare_artifacts(assessment_id="assess-123")

    artifacts.raw_trivy_vuln_path.write_text('{"SchemaVersion": 2, "Results": []}', encoding="utf-8")
    artifacts.sbom_cyclonedx_path.write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")

    now = datetime.now(timezone.utc)
    result = DiscoveryResult(
        assessment_id="assess-123",
        target=AssessmentTarget(target_id="t1", target_path="/tmp/app", created_at=now),
        scan_metadata=ScanMetadata(
            scanner_version="0.58.1",
            scan_started_at=now,
            scan_completed_at=now,
            scan_status=ScanStatus.COMPLETED,
        ),
        sbom=SBOMRecord(
            format_version="1.5",
            completeness_status=SBOMCompletenessStatus.COMPLETE,
        ),
    )

    hashes = store.persist_assessment(artifacts, result)
    assert "raw-trivy-vuln.json" in hashes
    assert "sbom-cyclonedx.json" in hashes
    assert "discovery-assessment.json" in hashes
    assert artifacts.assessment_json_path.is_file()
    assert artifacts.provenance_path.is_file()

    prov = json.loads(artifacts.provenance_path.read_text(encoding="utf-8"))
    assert prov["assessment_id"] == "assess-123"
    assert prov["artifacts"]["sbom-cyclonedx.json"] == result.sbom.document_sha256


@pytest.mark.unit
def test_evidence_store_rejects_unsafe_assessment_id(tmp_path: Path) -> None:
    """Path traversal attempts in assessment_id are rejected."""
    store = EvidenceStore(base_output_dir=tmp_path)
    with pytest.raises(ValueError, match="Unsafe assessment_id"):
        store.prepare_artifacts(assessment_id="../../escape")
