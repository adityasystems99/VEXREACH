"""Unit tests for safe path resolution and path traversal security."""

from pathlib import Path
import pytest
from packages.core.utils.safe_path import (
    PathTraversalError,
    calculate_file_sha256,
    safe_resolve_path,
)


@pytest.mark.unit
def test_safe_resolve_valid_path(tmp_path: Path) -> None:
    """Verify resolving a valid child path within base directory."""
    child = tmp_path / "subdir" / "file.py"
    child.parent.mkdir()
    child.write_text("print('hello')")

    resolved = safe_resolve_path(tmp_path, "subdir/file.py")
    assert resolved == child.resolve()


@pytest.mark.unit
def test_path_traversal_detection(tmp_path: Path) -> None:
    """Verify that an untrusted path attempting to escape base directory raises PathTraversalError."""
    base_dir = tmp_path / "sandbox"
    base_dir.mkdir()

    with pytest.raises(PathTraversalError):
        safe_resolve_path(base_dir, "../outside.txt")

    with pytest.raises(PathTraversalError):
        safe_resolve_path(base_dir, "../../etc/passwd")


@pytest.mark.unit
def test_calculate_file_sha256(tmp_path: Path) -> None:
    """Verify SHA-256 calculation on known content."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("vexreach-deterministic-security")

    digest = calculate_file_sha256(test_file)
    assert len(digest) == 64
    # Check reproducible hash
    digest_again = calculate_file_sha256(test_file)
    assert digest == digest_again
