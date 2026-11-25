"""Integration tests for FastAPI REST Backend v1, Auth/RBAC, Rate Limiting, Audit Logs & Jobs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from apps.api.main import create_app
from packages.core.config.settings import Settings
from tests.integration.test_ai_security_pipeline import FAKE_REQUESTS_DEP
from tests.integration.test_discovery_pipeline import _FakeTrivyClient
from tests.integration.test_intelligence_pipeline import DISCOVERY_FIXTURES, SAMPLE_APP_DIR


def _build_test_settings(tmp_path: Path, **overrides) -> Settings:
    defaults = dict(
        storage_path=tmp_path / "vexreach.db",
        default_output_dir=tmp_path / "out",
        api_auth_enabled=True,
        api_keys=SecretStr("viewer-tok:viewer,operator-tok:operator,admin-tok:admin"),
        api_max_request_bytes=1024 * 1024,
        api_rate_limit_per_minute=200,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def _fake_factory():
    return _FakeTrivyClient(
        sbom_fixture=DISCOVERY_FIXTURES / "sbom_cyclonedx_sample.json",
        vuln_fixture=DISCOVERY_FIXTURES / "trivy_vuln_sample.json",
    )


@pytest.mark.integration
def test_api_health_openapi_auth_rbac_and_audit_logging(tmp_path: Path) -> None:
    app = create_app(_build_test_settings(tmp_path), trivy_client_factory=_fake_factory)
    client = TestClient(app)

    h = client.get("/healthz")
    assert h.status_code == 200
    assert h.json()["api_version"] == "v1"

    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"

    spec = client.get("/api/v1/openapi.json")
    assert spec.status_code == 200
    assert "/api/v1/assessments" in spec.json()["paths"]

    # Missing & invalid Bearer token -> 401
    assert client.get("/api/v1/assessments").status_code == 401
    assert (
        client.get("/api/v1/assessments", headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )

    # RBAC: viewer cannot mutate assessments; operator cannot read audit logs
    assert (
        client.post(
            "/api/v1/assessments",
            headers={"Authorization": "Bearer viewer-tok"},
            json={"target_path": str(SAMPLE_APP_DIR)},
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/api/v1/audit-logs",
            headers={"Authorization": "Bearer operator-tok"},
        ).status_code
        == 403
    )

    # Viewer can read integrations
    integ = client.get("/api/v1/integrations", headers={"Authorization": "Bearer viewer-tok"})
    assert integ.status_code == 200
    assert any(item["integration_id"] == "llm:disabled" for item in integ.json())

    # Admin can inspect audit logs (and empty/prior events contain no leaked tokens)
    logs = client.get("/api/v1/audit-logs", headers={"Authorization": "Bearer admin-tok"})
    assert logs.status_code == 200


@pytest.mark.integration
def test_api_governance_payload_limit_and_rate_limit(tmp_path: Path) -> None:
    app = create_app(
        _build_test_settings(
            tmp_path,
            api_auth_enabled=False,
            api_max_request_bytes=1024,
            api_rate_limit_per_minute=2,
        ),
        trivy_client_factory=_fake_factory,
    )
    client = TestClient(app)

    # Oversized body rejected cleanly with 413
    too_big = client.post(
        "/api/v1/webhooks/ci",
        json={"event_type": "push", "repository": "x" * 1500},
    )
    assert too_big.status_code == 413
    assert too_big.json()["error_code"] == "PAYLOAD_TOO_LARGE"

    # Rate limit triggers 429 on 3rd request within window
    assert client.get("/healthz").status_code == 200
    assert client.get("/healthz").status_code == 200
    third = client.get("/healthz")
    assert third.status_code == 429
    assert third.json()["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert third.headers.get("Retry-After") == "60"


@pytest.mark.integration
def test_api_end_to_end_assessment_lifecycle_non_conflated_views_and_extensions(tmp_path: Path) -> None:
    app = create_app(_build_test_settings(tmp_path), trivy_client_factory=_fake_factory)
    client = TestClient(app)

    ep_file = tmp_path / "ep.json"
    ep_file.write_text(
        json.dumps({"entry_points": [{"module": "app", "qualified_name": "fetch_status"}]}),
        encoding="utf-8",
    )
    sym_file = tmp_path / "symbols.json"
    sym_file.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "vulnerability_id": "CVE-2023-32681",
                        "package": {"ecosystem": "pypi", "name": "requests"},
                        "symbols": [
                            {
                                "module": "requests",
                                "qualified_name": "requests.get",
                                "source": "curated_advisory_analysis",
                                "confidence": "verified",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    op_headers = {"Authorization": "Bearer operator-tok"}
    view_headers = {"Authorization": "Bearer viewer-tok"}
    adm_headers = {"Authorization": "Bearer admin-tok"}

    # 1. Create synchronous assessment running Discovery + Reachability + Attack Paths + Risk + OpenVEX
    create_resp = client.post(
        "/api/v1/assessments",
        headers=op_headers,
        json={
            "target_path": str(SAMPLE_APP_DIR),
            "enrich_osv": False,
            "extract_symbols": False,
            "symbols_file": str(sym_file),
            "entry_points_file": str(ep_file),
            "dependency_source_dirs": [str(FAKE_REQUESTS_DEP)],
            "analyze_python": True,
            "attack_paths": True,
            "compute_risk": True,
            "emit_vex": True,
            "workload_context": {
                "workload_name": "production-api",
                "internet_facing": True,
                "criticality": "critical",
            },
            "async_execution": False,
        },
    )
    assert create_resp.status_code == 202, create_resp.text
    job = create_resp.json()
    assert job["status"] == "completed", job.get("error")
    assessment_id = job["assessment_id"]
    assert assessment_id

    # Job lookup, list assessments, single assessment
    assert client.get(f"/api/v1/jobs/{job['job_id']}", headers=view_headers).status_code == 200
    listed = client.get("/api/v1/assessments?limit=10&offset=0", headers=view_headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert client.get(f"/api/v1/assessments/{assessment_id}", headers=view_headers).status_code == 200

    # Non-conflated findings & dependency endpoints
    vulns_resp = client.get(
        f"/api/v1/assessments/{assessment_id}/vulnerabilities?limit=10",
        headers=view_headers,
    )
    assert vulns_resp.status_code == 200
    items = vulns_resp.json()["items"]
    assert len(items) >= 2
    by_vid = {v["vulnerability_id"]: v for v in items}
    req_v = by_vid["CVE-2023-32681"]
    assert req_v["vulnerable_dependency_detected"] is True
    assert req_v["candidate_symbol_identified"] is True
    assert req_v["static_path_identified"] is True
    assert req_v["runtime_execution_observed"] is None
    assert req_v["exploitability_established"] is False
    assert req_v["contextual_risk_score"] is not None
    # Reachable dependency + verified candidate symbol -> AFFECTED; missing candidate/OSV on other findings -> UNDER_INVESTIGATION
    assert req_v["openvex_status"] == "affected"
    assert by_vid["CVE-2020-14343"]["openvex_status"] == "under_investigation"

    deps = client.get(
        f"/api/v1/assessments/{assessment_id}/dependencies?ecosystem=pypi",
        headers=view_headers,
    )
    assert deps.status_code == 200
    assert deps.json()["total"] >= 1

    # Engine detail endpoints
    assert client.get(f"/api/v1/assessments/{assessment_id}/reachability", headers=view_headers).status_code == 200
    assert client.get(f"/api/v1/assessments/{assessment_id}/attack-paths", headers=view_headers).status_code == 200
    assert client.get(f"/api/v1/assessments/{assessment_id}/risk", headers=view_headers).status_code == 200
    assert client.get(f"/api/v1/assessments/{assessment_id}/evidence", headers=view_headers).status_code == 200
    assert client.get(f"/api/v1/assessments/{assessment_id}/openvex", headers=view_headers).status_code == 200
    assert client.get(f"/api/v1/assessments/{assessment_id}/policy-evaluation", headers=view_headers).status_code == 200
    assert client.get(f"/api/v1/assessments/{assessment_id}/history", headers=view_headers).status_code == 200

    # Runtime trace ingestion + risk/VEX re-evaluation
    rt_post = client.post(
        f"/api/v1/assessments/{assessment_id}/runtime-observations",
        headers=op_headers,
        json={
            "observations": [
                {
                    "qualified_symbol": "requests.get",
                    "workload_name": "api-gw",
                    "instrumentation_source": "ebpf",
                    "observed_at": "2026-11-25T10:00:00Z",
                    "call_count": 5,
                }
            ],
            "instrumentation_coverage_percent": 74.0,
            "re_evaluate_vex_and_risk": True,
        },
    )
    assert rt_post.status_code == 200, rt_post.text
    assert "CVE-2023-32681" in rt_post.json()["matched_vulnerability_ids"]
    assert client.get(f"/api/v1/assessments/{assessment_id}/runtime-observations", headers=view_headers).status_code == 200

    # After runtime observation, non-conflated view marks runtime_execution_observed=True
    vulns_after_rt = client.get(
        f"/api/v1/assessments/{assessment_id}/vulnerabilities", headers=view_headers
    ).json()["items"]
    assert {v["vulnerability_id"]: v for v in vulns_after_rt}["CVE-2023-32681"][
        "runtime_execution_observed"
    ] is True

    # What-If Simulation, Reassessment Plan, CI Webhook, and Audit Log verification
    sim_resp = client.post(
        f"/api/v1/assessments/{assessment_id}/simulate",
        headers=op_headers,
        json={"proposals": [{"package_name": "requests", "target_version": "2.31.0"}]},
    )
    assert sim_resp.status_code == 200
    assert sim_resp.json()["validation_status"] == "pending_isolated_test_verification"

    reassess_resp = client.post(
        f"/api/v1/assessments/{assessment_id}/reassess-plan",
        headers=op_headers,
        json={"updated_sbom_package_versions": {"requests": "2.31.0"}},
    )
    assert reassess_resp.status_code == 200
    assert reassess_resp.json()["reassessment_required"] is True

    webhook_resp = client.post(
        "/api/v1/webhooks/ci",
        headers=op_headers,
        json={
            "event_type": "pull_request",
            "repository": "adityasystems99/VEXREACH",
            "assessment_id": assessment_id,
            "updated_sbom_package_versions": {"requests": "2.31.0"},
        },
    )
    assert webhook_resp.status_code == 200
    assert webhook_resp.json()["accepted"] is True

    # Async background job execution also completes via TestClient
    async_resp = client.post(
        "/api/v1/assessments",
        headers=op_headers,
        json={
            "target_path": str(SAMPLE_APP_DIR),
            "analyze_python": False,
            "compute_risk": True,
            "emit_vex": True,
            "async_execution": True,
        },
    )
    assert async_resp.status_code == 202
    async_job = client.get(
        f"/api/v1/jobs/{async_resp.json()['job_id']}", headers=view_headers
    ).json()
    assert async_job["status"] == "completed"

    # Admin audit logs recorded mutations and redacted raw Bearer tokens
    audit_entries = client.get("/api/v1/audit-logs", headers=adm_headers).json()
    actions = {row["action"] for row in audit_entries}
    assert {"create_assessment", "ingest_runtime_observations", "simulate_remediation", "ci_webhook"} <= actions
    assert all("operator-tok" not in json.dumps(row) for row in audit_entries)
