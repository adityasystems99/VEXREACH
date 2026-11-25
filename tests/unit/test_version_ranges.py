"""Exhaustive boundary tests for ecosystem-aware OSV version range evaluation."""

import pytest

from packages.core.engines.intelligence.version_ranges import VersionRangeEvaluator
from packages.core.models.intelligence import (
    AffectedPackageRange,
    OSVRangeType,
    RangeEvent,
    VersionMatchStatus,
)


def _make_range(
    ecosystem: str,
    range_type: OSVRangeType,
    events: list[tuple[str, str]],
    affected_versions: list[str] | None = None,
) -> AffectedPackageRange:
    return AffectedPackageRange(
        ecosystem=ecosystem,
        package_name="demo-pkg",
        range_type=range_type,
        events=[RangeEvent(event_type=et, value=val) for et, val in events],  # type: ignore[arg-type]
        affected_versions=affected_versions or [],
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        ("2.2.9", VersionMatchStatus.NOT_AFFECTED),      # Before introduced
        ("2.3.0", VersionMatchStatus.AFFECTED),          # Exact introduced
        ("2.28.1", VersionMatchStatus.AFFECTED),         # Between introduced and fixed
        ("2.31.0", VersionMatchStatus.NOT_AFFECTED),      # Exact fixed (exclusive)
        ("2.32.0", VersionMatchStatus.NOT_AFFECTED),      # After fixed
        ("2.31.0rc1", VersionMatchStatus.AFFECTED),      # PEP 440 pre-release < 2.31.0!
        ("2.31.0.post1", VersionMatchStatus.NOT_AFFECTED),
    ],
)
def test_pypi_pep440_boundaries(installed: str, expected: VersionMatchStatus) -> None:
    """Verify PEP 440 PyPI boundary conditions including pre-release and post-release ordering."""
    rng = _make_range("pypi", OSVRangeType.ECOSYSTEM, [("introduced", "2.3.0"), ("fixed", "2.31.0")])
    res = VersionRangeEvaluator().evaluate_range("GHSA-1", "pkg-1", installed, rng)
    assert res.status == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        ("0.9.9", VersionMatchStatus.NOT_AFFECTED),
        ("1.0.0-alpha", VersionMatchStatus.NOT_AFFECTED),     # Pre-release < 1.0.0
        ("1.0.0", VersionMatchStatus.AFFECTED),              # Exact introduced
        ("1.2.0-beta.2", VersionMatchStatus.AFFECTED),       # Pre-release < 1.2.0
        ("1.2.0+build999", VersionMatchStatus.NOT_AFFECTED), # Build metadata ignored -> == 1.2.0
        ("1.2.0", VersionMatchStatus.NOT_AFFECTED),
        ("1.2.1", VersionMatchStatus.NOT_AFFECTED),
    ],
)
def test_semver_2_0_0_boundaries(installed: str, expected: VersionMatchStatus) -> None:
    """Verify SemVer 2.0.0 pre-release and build-metadata boundary semantics."""
    rng = _make_range("npm", OSVRangeType.SEMVER, [("introduced", "1.0.0"), ("fixed", "1.2.0")])
    res = VersionRangeEvaluator().evaluate_range("GHSA-2", "pkg-2", installed, rng)
    assert res.status == expected


@pytest.mark.unit
def test_golang_semver_with_leading_v_and_pseudo_versions() -> None:
    """Go module versions with leading 'v' and pseudo-versions compare accurately."""
    rng = _make_range("golang", OSVRangeType.SEMVER, [("introduced", "0"), ("fixed", "1.9.1")])
    evaluator = VersionRangeEvaluator()

    assert evaluator.evaluate_range("GO-1", "go-pkg", "v1.9.0", rng).status == VersionMatchStatus.AFFECTED
    assert (
        evaluator.evaluate_range("GO-1", "go-pkg", "v0.0.0-20220101120000-abcdef", rng).status
        == VersionMatchStatus.AFFECTED
    )
    assert evaluator.evaluate_range("GO-1", "go-pkg", "v1.9.1", rng).status == VersionMatchStatus.NOT_AFFECTED


@pytest.mark.unit
def test_open_ended_range_and_last_affected_boundary() -> None:
    """Verify open-ended introduced-only ranges and inclusive last_affected boundaries."""
    evaluator = VersionRangeEvaluator()

    open_rng = _make_range("pypi", OSVRangeType.ECOSYSTEM, [("introduced", "1.5.0")])
    assert evaluator.evaluate_range("CVE-1", "p", "1.4.9", open_rng).status == VersionMatchStatus.NOT_AFFECTED
    assert evaluator.evaluate_range("CVE-1", "p", "1.5.0", open_rng).status == VersionMatchStatus.AFFECTED
    assert evaluator.evaluate_range("CVE-1", "p", "99.0.0", open_rng).status == VersionMatchStatus.AFFECTED

    la_rng = _make_range(
        "pypi",
        OSVRangeType.ECOSYSTEM,
        [("introduced", "1.0.0"), ("last_affected", "1.2.3")],
    )
    assert evaluator.evaluate_range("CVE-2", "p", "1.2.3", la_rng).status == VersionMatchStatus.AFFECTED
    above = evaluator.evaluate_range("CVE-2", "p", "1.2.4", la_rng)
    assert above.status == VersionMatchStatus.NOT_AFFECTED
    assert "last_affected" in above.explanation


@pytest.mark.unit
def test_multiple_intervals_in_single_range_and_kleene_uncertainty() -> None:
    """Verify multi-branch ranges and conservative Kleene aggregation across ranges."""
    evaluator = VersionRangeEvaluator()
    multi_rng = _make_range(
        "pypi",
        OSVRangeType.ECOSYSTEM,
        [
            ("introduced", "1.26.0"),
            ("fixed", "1.26.18"),
            ("introduced", "2.0.0"),
            ("fixed", "2.0.7"),
        ],
    )
    assert evaluator.evaluate_range("CVE-M", "p", "1.26.15", multi_rng).status == VersionMatchStatus.AFFECTED
    assert evaluator.evaluate_range("CVE-M", "p", "1.26.18", multi_rng).status == VersionMatchStatus.NOT_AFFECTED
    assert evaluator.evaluate_range("CVE-M", "p", "2.0.5", multi_rng).status == VersionMatchStatus.AFFECTED
    assert evaluator.evaluate_range("CVE-M", "p", "2.0.7", multi_rng).status == VersionMatchStatus.NOT_AFFECTED

    # Kleene logic: NOT_AFFECTED + UNKNOWN => UNKNOWN (never claim unaffected when one range is unknown)
    r1 = evaluator.evaluate_range("CVE-M", "p", "2.0.7", multi_rng)
    git_rng = _make_range("pypi", OSVRangeType.GIT, [("introduced", "abc123"), ("fixed", "def456")])
    r2 = evaluator.evaluate_range("CVE-M", "p", "2.0.7", git_rng)
    assert r2.status == VersionMatchStatus.UNKNOWN
    assert evaluator.aggregate_statuses([r1, r2]) == VersionMatchStatus.UNKNOWN


@pytest.mark.unit
def test_missing_version_and_unsupported_version_schemes_return_unknown() -> None:
    """Missing version, GIT commits, Debian/Maven schemes, and unparseable strings yield UNKNOWN."""
    evaluator = VersionRangeEvaluator()
    pypi_rng = _make_range("pypi", OSVRangeType.ECOSYSTEM, [("introduced", "1.0"), ("fixed", "2.0")])
    assert evaluator.evaluate_range("CVE-1", "p", None, pypi_rng).status == VersionMatchStatus.UNKNOWN
    assert evaluator.evaluate_range("CVE-1", "p", "", pypi_rng).status == VersionMatchStatus.UNKNOWN
    assert evaluator.evaluate_range("CVE-1", "p", "not!a!pep440", pypi_rng).status == VersionMatchStatus.UNKNOWN

    deb_rng = _make_range(
        "deb",
        OSVRangeType.ECOSYSTEM,
        [("introduced", "0"), ("fixed", "3.0.11-1~deb12u2")],
    )
    deb_eval = evaluator.evaluate_range("DSA-1", "p", "3.0.11-1~deb12u1", deb_rng)
    assert deb_eval.status == VersionMatchStatus.UNKNOWN
    assert "Unsupported version scheme" in deb_eval.explanation

    # Explicit exact match in affected_versions still succeeds even for unsupported range schemes
    deb_exact = _make_range(
        "deb",
        OSVRangeType.ECOSYSTEM,
        [("introduced", "0"), ("fixed", "3.0.11-1~deb12u2")],
        affected_versions=["3.0.11-1~deb12u1"],
    )
    assert evaluator.evaluate_range("DSA-1", "p", "3.0.11-1~deb12u1", deb_exact).status == VersionMatchStatus.AFFECTED
