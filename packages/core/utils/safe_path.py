"""Safe path resolution and cryptographic utilities to mitigate traversal attacks."""

import hashlib
from pathlib import Path


class PathTraversalError(Exception):
    """Raised when an untrusted path attempts to escape the root boundary directory."""


def safe_resolve_path(base_dir: Path, untrusted_path: Path | str) -> Path:
    """Safely resolve a path relative to a base directory, preventing path traversal attacks.

    Args:
        base_dir: The trusted root directory that must contain the resolved target.
        untrusted_path: The untrusted user-supplied or manifest-supplied relative path.

    Returns:
        The canonicalized, verified Path.

    Raises:
        PathTraversalError: If the resolved path lies outside base_dir.
    """
    resolved_base = base_dir.resolve()
    target_path = (resolved_base / untrusted_path).resolve()

    try:
        target_path.relative_to(resolved_base)
    except ValueError as err:
        raise PathTraversalError(
            f"Path traversal detected: '{untrusted_path}' escapes root '{base_dir}'"
        ) from err

    return target_path


def calculate_file_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hash of a file efficiently using streaming chunks.

    Args:
        file_path: Absolute or relative path to the file.
        chunk_size: Byte buffer size for reading.

    Returns:
        Hexadecimal digest string.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()
