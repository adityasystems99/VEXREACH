"""Unit tests for Attack Path surface classification and conservative taint tracing."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.core.analysis.python import PythonReachabilityAnalyzer, load_symbol_manifest
from packages.core.engines.attack_path import AttackPathOrchestrator
from packages.core.models.attack_path import ExposureSurface, TaintFlowStatus

ATTACK_APP = (
    Path(__file__).resolve().parent.parent / "fixtures" / "attack_path" / "web_app"
)


@pytest.mark.unit
def test_attack_path_separates_exposure_auth_constant_vs_tainted_and_safeloader() -> None:
    manifest, sha = load_symbol_manifest(ATTACK_APP / "symbols.json")
    reach_bundle = PythonReachabilityAnalyzer().analyze_repository(
        ATTACK_APP, manifest=manifest, manifest_sha256=sha
    )
    report = AttackPathOrchestrator().analyze_from_reachability(
        target_path=ATTACK_APP,
        reachability_report=reach_bundle.report,
    )

    by_ep = {p.entry_point: p for p in report.paths}

    # 1. Public FastAPI endpoint passing untrusted payload -> TAINTED_FLOW_OBSERVED + NETWORK_HTTP_PUBLIC
    pub = by_ep["routes.public_parse"]
    assert pub.exposure_surface == ExposureSurface.NETWORK_HTTP_PUBLIC
    assert pub.is_network_exposed is True
    assert pub.data_flow_status == TaintFlowStatus.TAINTED_FLOW_OBSERVED
    assert pub.auth_barriers == []
    assert len(pub.missing_evidence) >= 1
    assert any(s.role == "sink_argument" for s in pub.data_flow_steps)

    # 2. Authenticated FastAPI endpoint with Depends(get_current_user) -> NETWORK_HTTP_AUTHENTICATED
    auth = by_ep["routes.auth_parse"]
    assert auth.exposure_surface == ExposureSurface.NETWORK_HTTP_AUTHENTICATED
    assert len(auth.auth_barriers) == 1
    assert "get_current_user" in auth.auth_barriers[0].mechanism
    assert auth.data_flow_status == TaintFlowStatus.TAINTED_FLOW_OBSERVED

    # 3. Call path to yaml.load with constant string only -> CALL_PATH_ONLY_TAINT_NOT_PROVEN
    const = by_ep["routes.health_cfg"]
    assert const.exposure_surface == ExposureSurface.NETWORK_HTTP_PUBLIC
    assert const.data_flow_status == TaintFlowStatus.CALL_PATH_ONLY_TAINT_NOT_PROVEN

    # 4. SafeLoader barrier detected cleanly at sink -> SANITIZED_OR_VALIDATED
    safe = by_ep["routes.safe_parse"]
    assert safe.data_flow_status == TaintFlowStatus.SANITIZED_OR_VALIDATED
    assert any(b.barrier_type == "safe_loader" for b in safe.validation_barriers)
