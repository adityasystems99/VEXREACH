"""Ecosystem-aware version comparison and OSV range boundary evaluator."""

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from packages.core.models.intelligence import (
    AffectedPackageRange,
    OSVRangeType,
    RangeEvent,
    VersionEvaluationResult,
    VersionMatchStatus,
)

# Strict SemVer 2.0.0 pattern (with optional single leading 'v'/'V' handled by caller for Go)
_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@dataclass(frozen=True)
class _ParsedSemVer:
    """Comparable SemVer 2.0.0 tuple ignoring build metadata per SemVer spec section 10."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] | None

    @classmethod
    def parse(cls, raw: str, allow_leading_v: bool = False) -> "_ParsedSemVer | None":
        text = raw.strip()
        if not text:
            return None
        if allow_leading_v and text[0] in {"v", "V"}:
            text = text[1:]
        match = _SEMVER_RE.match(text)
        if not match:
            return None
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3))
        pre_str = match.group(4)
        prerelease = tuple(pre_str.split(".")) if pre_str else None
        return cls(major=major, minor=minor, patch=patch, prerelease=prerelease)

    def compare(self, other: "_ParsedSemVer") -> int:
        """Return -1 if self < other, 0 if equal, 1 if self > other."""
        core_self = (self.major, self.minor, self.patch)
        core_other = (other.major, other.minor, other.patch)
        if core_self < core_other:
            return -1
        if core_self > core_other:
            return 1

        # Same major.minor.patch: normal release > pre-release
        if self.prerelease is None and other.prerelease is None:
            return 0
        if self.prerelease is None:
            return 1
        if other.prerelease is None:
            return -1

        for left, right in zip(self.prerelease, other.prerelease, strict=False):
            if left == right:
                continue
            left_num = left.isdigit()
            right_num = right.isdigit()
            if left_num and right_num:
                return -1 if int(left) < int(right) else 1
            if left_num != right_num:
                # Numeric identifiers always have lower precedence than non-numeric
                return -1 if left_num else 1
            return -1 if left < right else 1

        if len(self.prerelease) < len(other.prerelease):
            return -1
        if len(self.prerelease) > len(other.prerelease):
            return 1
        return 0


def _compare_versions(
    left_raw: str,
    right_raw: str,
    range_type: OSVRangeType,
    ecosystem: str,
) -> tuple[int | None, str | None]:
    """Compare two version strings using ecosystem-appropriate semantics.

    Returns:
        (cmp_result in {-1, 0, 1}, None) on success, or (None, reason) if unsupported/invalid.
    """
    eco = ecosystem.strip().lower()

    if range_type == OSVRangeType.GIT:
        return None, "GIT commit-hash ranges cannot be evaluated against package version strings."

    if range_type == OSVRangeType.UNKNOWN:
        return None, "OSV range type is unknown; cannot safely evaluate version order."

    # SemVer 2.0.0 comparator (applies to SEMVER ranges, plus npm/cargo/golang ECOSYSTEM ranges)
    if range_type == OSVRangeType.SEMVER or eco in {"golang", "go", "npm", "cargo"}:
        allow_v = eco in {"golang", "go"}
        v_left = _ParsedSemVer.parse(left_raw, allow_leading_v=allow_v)
        v_right = _ParsedSemVer.parse(right_raw, allow_leading_v=allow_v)
        if v_left is None or v_right is None:
            return (
                None,
                f"Version '{left_raw}' or '{right_raw}' is not valid SemVer 2.0.0 "
                f"for ecosystem '{ecosystem}'.",
            )
        return v_left.compare(v_right), None

    # PEP 440 comparator for PyPI ECOSYSTEM ranges
    if range_type == OSVRangeType.ECOSYSTEM and eco == "pypi":
        try:
            p_left = Version(left_raw.strip())
            p_right = Version(right_raw.strip())
        except InvalidVersion as err:
            return None, f"Invalid PEP 440 PyPI version during comparison: {err}"
        if p_left < p_right:
            return -1, None
        if p_left > p_right:
            return 1, None
        return 0, None

    return (
        None,
        f"Unsupported version scheme '{range_type.value}' for ecosystem '{ecosystem}'; "
        "preserving unknown status rather than guessing.",
    )


def _ge_introduced(
    installed: str,
    intro_val: str,
    range_type: OSVRangeType,
    ecosystem: str,
) -> tuple[bool | None, str | None]:
    """Evaluate installed >= introduced, honoring OSV sentinel '0'."""
    if intro_val.strip() == "0":
        # Still verify installed itself is parseable under the scheme so garbage versions stay UNKNOWN.
        cmp_self, err = _compare_versions(installed, installed, range_type, ecosystem)
        if cmp_self is None:
            return None, err
        return True, None
    cmp_res, err = _compare_versions(installed, intro_val, range_type, ecosystem)
    if cmp_res is None:
        return None, err
    return cmp_res >= 0, None


class VersionRangeEvaluator:
    """Evaluates installed package versions conservatively against OSV AffectedPackageRanges."""

    def evaluate_range(
        self,
        advisory_id: str,
        package_id: str,
        installed_version: str | None,
        affected_range: AffectedPackageRange,
    ) -> VersionEvaluationResult:
        """Evaluate a single AffectedPackageRange against installed_version."""
        eco = affected_range.ecosystem
        fixed_list = list(affected_range.fixed_versions)

        if not installed_version or not installed_version.strip():
            return VersionEvaluationResult(
                advisory_id=advisory_id,
                package_id=package_id,
                installed_version=installed_version,
                ecosystem=eco,
                status=VersionMatchStatus.UNKNOWN,
                explanation="Installed package version is missing; cannot evaluate range.",
                matched_range_type=affected_range.range_type.value,
                evaluated_events=list(affected_range.events),
                fixed_versions=fixed_list,
            )

        clean_installed = installed_version.strip()

        # Check explicit affected[].versions list first if populated
        if clean_installed in affected_range.affected_versions:
            return VersionEvaluationResult(
                advisory_id=advisory_id,
                package_id=package_id,
                installed_version=clean_installed,
                ecosystem=eco,
                status=VersionMatchStatus.AFFECTED,
                explanation=(
                    f"Installed version '{clean_installed}' appears explicitly in "
                    "OSV affected.versions list."
                ),
                matched_range_type=affected_range.range_type.value,
                evaluated_events=list(affected_range.events),
                fixed_versions=fixed_list,
            )

        if not affected_range.events:
            if affected_range.affected_versions:
                # Explicit versions list present without ranges, and installed not in list:
                # only claim NOT_AFFECTED if ecosystem supports exact/canonical check; otherwise cautious.
                return VersionEvaluationResult(
                    advisory_id=advisory_id,
                    package_id=package_id,
                    installed_version=clean_installed,
                    ecosystem=eco,
                    status=VersionMatchStatus.UNKNOWN,
                    explanation=(
                        "Advisory lists explicit affected.versions without ranges and "
                        f"'{clean_installed}' was not an exact string match."
                    ),
                    matched_range_type=affected_range.range_type.value,
                    evaluated_events=[],
                    fixed_versions=fixed_list,
                )
            return VersionEvaluationResult(
                advisory_id=advisory_id,
                package_id=package_id,
                installed_version=clean_installed,
                ecosystem=eco,
                status=VersionMatchStatus.UNKNOWN,
                explanation="Advisory affected entry contains neither version ranges nor explicit versions.",
                matched_range_type=affected_range.range_type.value,
                evaluated_events=[],
                fixed_versions=fixed_list,
            )

        if affected_range.range_type in {OSVRangeType.GIT, OSVRangeType.UNKNOWN}:
            return VersionEvaluationResult(
                advisory_id=advisory_id,
                package_id=package_id,
                installed_version=clean_installed,
                ecosystem=eco,
                status=VersionMatchStatus.UNKNOWN,
                explanation=(
                    f"Range type '{affected_range.range_type.value}' cannot be evaluated "
                    "against package versions; original range preserved."
                ),
                matched_range_type=affected_range.range_type.value,
                evaluated_events=list(affected_range.events),
                fixed_versions=fixed_list,
            )

        status, explanation = self._evaluate_event_sequence(
            installed=clean_installed,
            events=affected_range.events,
            range_type=affected_range.range_type,
            ecosystem=eco,
        )
        return VersionEvaluationResult(
            advisory_id=advisory_id,
            package_id=package_id,
            installed_version=clean_installed,
            ecosystem=eco,
            status=status,
            explanation=explanation,
            matched_range_type=affected_range.range_type.value,
            evaluated_events=list(affected_range.events),
            fixed_versions=fixed_list,
        )

    def _evaluate_event_sequence(
        self,
        installed: str,
        events: list[RangeEvent],
        range_type: OSVRangeType,
        ecosystem: str,
    ) -> tuple[VersionMatchStatus, str]:
        """Evaluate OSV ordered event intervals using Kleene 3-valued logic."""
        interval_statuses: list[tuple[VersionMatchStatus, str]] = []
        active_intro: str | None = None

        for ev in events:
            if ev.event_type == "introduced":
                if active_intro is not None:
                    # Unclosed previous interval; evaluate as open-ended conservatively
                    interval_statuses.append(
                        self._eval_open_interval(installed, active_intro, range_type, ecosystem)
                    )
                active_intro = ev.value
            elif ev.event_type == "fixed":
                if active_intro is None:
                    interval_statuses.append(
                        (
                            VersionMatchStatus.UNKNOWN,
                            f"Encountered 'fixed' ({ev.value}) without preceding 'introduced' event.",
                        )
                    )
                    continue
                interval_statuses.append(
                    self._eval_half_open_interval(
                        installed, active_intro, ev.value, range_type, ecosystem
                    )
                )
                active_intro = None
            elif ev.event_type == "last_affected":
                if active_intro is None:
                    interval_statuses.append(
                        (
                            VersionMatchStatus.UNKNOWN,
                            f"Encountered 'last_affected' ({ev.value}) without preceding 'introduced' event.",
                        )
                    )
                    continue
                interval_statuses.append(
                    self._eval_closed_interval(
                        installed, active_intro, ev.value, range_type, ecosystem
                    )
                )
                active_intro = None
            elif ev.event_type == "limit":
                interval_statuses.append(
                    (
                        VersionMatchStatus.UNKNOWN,
                        f"Range contains 'limit' event ({ev.value}) whose upper fix boundary "
                        "cannot be assumed safe without an explicit 'fixed' event.",
                    )
                )
                active_intro = None

        if active_intro is not None:
            interval_statuses.append(
                self._eval_open_interval(installed, active_intro, range_type, ecosystem)
            )

        if not interval_statuses:
            return VersionMatchStatus.UNKNOWN, "No evaluable intervals found in range events."

        # Kleene 3-valued aggregation: AFFECTED > UNKNOWN > NOT_AFFECTED
        for status, reason in interval_statuses:
            if status == VersionMatchStatus.AFFECTED:
                return VersionMatchStatus.AFFECTED, reason

        for status, reason in interval_statuses:
            if status == VersionMatchStatus.UNKNOWN:
                return VersionMatchStatus.UNKNOWN, reason

        return VersionMatchStatus.NOT_AFFECTED, "; ".join(reason for _, reason in interval_statuses)

    @staticmethod
    def _eval_open_interval(
        installed: str,
        intro: str,
        range_type: OSVRangeType,
        ecosystem: str,
    ) -> tuple[VersionMatchStatus, str]:
        ge_intro, err = _ge_introduced(installed, intro, range_type, ecosystem)
        if ge_intro is None:
            return VersionMatchStatus.UNKNOWN, err or "Version comparison failed."
        if ge_intro:
            return (
                VersionMatchStatus.AFFECTED,
                f"Version '{installed}' is >= introduced '{intro}' in open-ended affected range.",
            )
        return (
            VersionMatchStatus.NOT_AFFECTED,
            f"Version '{installed}' is < introduced '{intro}'.",
        )

    @staticmethod
    def _eval_half_open_interval(
        installed: str,
        intro: str,
        fixed: str,
        range_type: OSVRangeType,
        ecosystem: str,
    ) -> tuple[VersionMatchStatus, str]:
        ge_intro, err1 = _ge_introduced(installed, intro, range_type, ecosystem)
        if ge_intro is None:
            return VersionMatchStatus.UNKNOWN, err1 or "Introduced version comparison failed."

        cmp_fixed, err2 = _compare_versions(installed, fixed, range_type, ecosystem)
        if cmp_fixed is None:
            return VersionMatchStatus.UNKNOWN, err2 or "Fixed version comparison failed."

        if ge_intro and cmp_fixed < 0:
            return (
                VersionMatchStatus.AFFECTED,
                f"Version '{installed}' falls within [{intro}, {fixed}).",
            )
        if not ge_intro:
            return (
                VersionMatchStatus.NOT_AFFECTED,
                f"Version '{installed}' is before introduced '{intro}'.",
            )
        if cmp_fixed == 0:
            return (
                VersionMatchStatus.NOT_AFFECTED,
                f"Version '{installed}' matches fixed version '{fixed}'.",
            )
        return (
            VersionMatchStatus.NOT_AFFECTED,
            f"Version '{installed}' is after fixed version '{fixed}'.",
        )

    @staticmethod
    def _eval_closed_interval(
        installed: str,
        intro: str,
        last_affected: str,
        range_type: OSVRangeType,
        ecosystem: str,
    ) -> tuple[VersionMatchStatus, str]:
        ge_intro, err1 = _ge_introduced(installed, intro, range_type, ecosystem)
        if ge_intro is None:
            return VersionMatchStatus.UNKNOWN, err1 or "Introduced version comparison failed."

        cmp_last, err2 = _compare_versions(installed, last_affected, range_type, ecosystem)
        if cmp_last is None:
            return VersionMatchStatus.UNKNOWN, err2 or "Last-affected version comparison failed."

        if ge_intro and cmp_last <= 0:
            return (
                VersionMatchStatus.AFFECTED,
                f"Version '{installed}' falls within [{intro}, {last_affected}] (inclusive).",
            )
        if not ge_intro:
            return (
                VersionMatchStatus.NOT_AFFECTED,
                f"Version '{installed}' is before introduced '{intro}'.",
            )
        return (
            VersionMatchStatus.NOT_AFFECTED,
            f"Version '{installed}' is above last_affected '{last_affected}' "
            "(caution: advisory did not specify an explicit fixed version).",
        )

    @staticmethod
    def aggregate_statuses(evaluations: list[VersionEvaluationResult]) -> VersionMatchStatus:
        """Aggregate multiple range evaluations conservatively (AFFECTED > UNKNOWN > NOT_AFFECTED)."""
        if not evaluations:
            return VersionMatchStatus.UNKNOWN
        statuses = {ev.status for ev in evaluations}
        if VersionMatchStatus.AFFECTED in statuses:
            return VersionMatchStatus.AFFECTED
        if VersionMatchStatus.UNKNOWN in statuses:
            return VersionMatchStatus.UNKNOWN
        return VersionMatchStatus.NOT_AFFECTED
