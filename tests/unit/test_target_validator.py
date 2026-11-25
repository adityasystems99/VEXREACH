"""Unit tests for TargetValidator path, permission, and manifest safety checks."""

import os
from pathlib import Path

import pytest

from packages.core.engines.discovery.target_validator import (
    TargetValidationError,
    TargetValidator,
)


@pytest.mark.unit
def test_validate_valid_repository_detects_manifests_without_executing(tmp_path: Path) -> None:
    """Valid directory returns canonical AssessmentTarget with manifest/ecosystem hints."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.28.1\n", encoding="utf-8")
    # Put an intentionally broken setup.py to prove TargetValidator never executes/parses Python code
    (repo / "setup.py").write_text("raise RuntimeError('MUST NEVER EXECUTE')", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "requirements.txt").write_text("ignored==1.0\n", encoding="utf-8")

    validator = TargetValidator()
    target = validator.validate(repo)

    assert target.target_path == str(repo.resolve())
    assert "pypi" in target.detected_ecosystems
    assert "requirements.txt" in target.detected_manifests
    assert "setup.py" in target.detected_manifests
    assert ".git/requirements.txt" not in target.detected_manifests


@pytest.mark.unit
def test_validate_missing_directory_raises(tmp_path: Path) -> None:
    """Non-existent path raises TargetValidationError."""
    validator = TargetValidator()
    with pytest.raises(TargetValidationError, match="does not exist"):
        validator.validate(tmp_path / "does-not-exist")


@pytest.mark.unit
def test_validate_empty_path_raises() -> None:
    """Blank or empty path raises TargetValidationError."""
    validator = TargetValidator()
    with pytest.raises(TargetValidationError, match="cannot be empty"):
        validator.validate("   ")


@pytest.mark.unit
def test_validate_file_instead_of_directory_raises(tmp_path: Path) -> None:
    """Regular file path raises TargetValidationError."""
    file_path = tmp_path / "app.py"
    file_path.write_text("print('hi')", encoding="utf-8")

    validator = TargetValidator()
    with pytest.raises(TargetValidationError, match="must be a directory"):
        validator.validate(file_path)


@pytest.mark.unit
def test_validate_permission_error_handled_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PermissionError during directory scan raises clean TargetValidationError."""
    repo = tmp_path / "locked_repo"
    repo.mkdir()

    def _deny_scandir(_path: Path) -> None:
        raise PermissionError("Access denied")

    monkeypatch.setattr(os, "scandir", _deny_scandir)
    validator = TargetValidator()
    with pytest.raises(TargetValidationError, match="Permission denied"):
        validator.validate(repo)
