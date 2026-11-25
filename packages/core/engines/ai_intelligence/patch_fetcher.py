"""Safe, allowlisted upstream patch diff retriever (HTTP or local files)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

from packages.core.config.settings import Settings, get_settings
from packages.core.models.ai_intelligence import PatchFetchStatus
from packages.core.utils.safe_path import calculate_file_sha256

_GITHUB_COMMIT_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+)/commit/(?P<sha>[0-9a-fA-F]{7,40})(?:\.diff|\.patch)?/?$"
)
_GITHUB_PR_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+)/pull/(?P<num>\d+)(?:\.diff|\.patch)?/?$"
)
_LOCAL_PATCH_SUFFIXES = (".diff", ".patch")


@dataclass(frozen=True)
class PatchFetchResult:
    """Raw upstream or local patch payload plus fetch status and digest."""

    source_ref: str
    fetch_status: PatchFetchStatus
    patch_text: str | None = None
    patch_sha256: str | None = None
    warning: str | None = None


def normalize_patch_url(url: str) -> str | None:
    """Normalize supported GitHub commit/PR URLs to `.diff` endpoints."""
    cleaned = url.strip()
    commit_match = _GITHUB_COMMIT_RE.match(cleaned)
    if commit_match:
        owner = commit_match.group("owner")
        repo = commit_match.group("repo")
        sha = commit_match.group("sha")
        return f"https://github.com/{owner}/{repo}/commit/{sha}.diff"

    pr_match = _GITHUB_PR_RE.match(cleaned)
    if pr_match:
        owner = pr_match.group("owner")
        repo = pr_match.group("repo")
        num = pr_match.group("num")
        return f"https://github.com/{owner}/{repo}/pull/{num}.diff"

    if cleaned.endswith(_LOCAL_PATCH_SUFFIXES):
        return cleaned
    return None


def _is_forbidden_host(hostname: str) -> bool:
    low = hostname.lower()
    if low in {"localhost", "127.0.0.1", "::1"} or low.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(low)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


class PatchFetcher:
    """Fetches upstream vulnerability patch diffs from allowlisted HTTPS hosts or local files."""

    def __init__(
        self,
        settings: Settings | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(self._settings.patch_fetch_timeout_seconds),
            headers={"User-Agent": self._settings.osv_user_agent, "Accept": "text/plain"},
            follow_redirects=False,
        )

    def __enter__(self) -> "PatchFetcher":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def extract_candidate_urls(self, references: list[str]) -> list[str]:
        """Extract normalized candidate diff URLs from advisory reference URLs."""
        urls: list[str] = []
        seen: set[str] = set()
        for ref in references:
            normalized = normalize_patch_url(ref)
            if normalized and normalized not in seen:
                seen.add(normalized)
                urls.append(normalized)
        return urls

    def validate_url(self, url: str) -> tuple[bool, str | None]:
        """Enforce HTTPS and explicit host allowlist to prevent SSRF."""
        parsed = urlparse(url.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            return False, f"Blocked non-HTTPS or malformed patch URL: '{url}'"
        host = parsed.hostname.lower()
        if _is_forbidden_host(host):
            return False, f"Blocked private/loopback patch host: '{host}'"
        allowed = {h.lower() for h in self._settings.patch_allowed_hosts}
        if host not in allowed:
            return False, f"Blocked patch host '{host}' not in allowlist {sorted(allowed)}"
        return True, None

    def load_local_patch(self, path: Path | str) -> PatchFetchResult:
        """Read a local `.diff`/`.patch` file safely within configured size limits."""
        target = Path(path)
        if not target.is_file():
            return PatchFetchResult(
                source_ref=str(target),
                fetch_status=PatchFetchStatus.UNAVAILABLE,
                warning=f"Patch file not found: {target}",
            )
        if target.is_symlink():
            return PatchFetchResult(
                source_ref=str(target),
                fetch_status=PatchFetchStatus.BLOCKED_UNTRUSTED_URL,
                warning=f"Refused symlink patch path: {target}",
            )
        size = target.stat().st_size
        if size > self._settings.patch_max_bytes:
            return PatchFetchResult(
                source_ref=str(target),
                fetch_status=PatchFetchStatus.SIZE_LIMIT_EXCEEDED,
                warning=f"Local patch exceeds max size ({size} > {self._settings.patch_max_bytes}).",
            )
        sha256 = calculate_file_sha256(target)
        text = target.read_text(encoding="utf-8", errors="replace")
        return PatchFetchResult(
            source_ref=target.as_posix(),
            fetch_status=PatchFetchStatus.LOCAL_FIXTURE,
            patch_text=text,
            patch_sha256=sha256,
        )

    def fetch_url(self, url: str) -> PatchFetchResult:
        """Fetch an upstream patch diff from an allowlisted HTTPS URL with size caps."""
        ok, err = self.validate_url(url)
        if not ok:
            return PatchFetchResult(
                source_ref=url,
                fetch_status=PatchFetchStatus.BLOCKED_UNTRUSTED_URL,
                warning=err,
            )

        try:
            with self._client.stream("GET", url) as resp:
                if resp.status_code in {301, 302, 303, 307, 308}:
                    loc = resp.headers.get("location", "")
                    loc_ok, loc_err = self.validate_url(loc)
                    if not loc_ok:
                        return PatchFetchResult(
                            source_ref=url,
                            fetch_status=PatchFetchStatus.BLOCKED_UNTRUSTED_URL,
                            warning=f"Redirect rejected ({loc_err})",
                        )
                    return self._fetch_direct(loc, original_ref=url)

                if resp.status_code >= 400:
                    return PatchFetchResult(
                        source_ref=url,
                        fetch_status=PatchFetchStatus.FETCH_ERROR,
                        warning=f"Upstream patch HTTP {resp.status_code} for {url}",
                    )
                return self._read_bounded_stream(resp, source_ref=url)
        except httpx.HTTPError as exc:
            return PatchFetchResult(
                source_ref=url,
                fetch_status=PatchFetchStatus.FETCH_ERROR,
                warning=f"Patch fetch network error for {url}: {exc}",
            )

    def _fetch_direct(self, url: str, *, original_ref: str) -> PatchFetchResult:
        with self._client.stream("GET", url) as resp:
            if resp.status_code >= 400:
                return PatchFetchResult(
                    source_ref=original_ref,
                    fetch_status=PatchFetchStatus.FETCH_ERROR,
                    warning=f"Upstream patch HTTP {resp.status_code} on redirect {url}",
                )
            return self._read_bounded_stream(resp, source_ref=original_ref)

    def _read_bounded_stream(
        self, resp: httpx.Response, *, source_ref: str
    ) -> PatchFetchResult:
        chunks: list[bytes] = []
        total = 0
        limit = self._settings.patch_max_bytes
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > limit:
                return PatchFetchResult(
                    source_ref=source_ref,
                    fetch_status=PatchFetchStatus.SIZE_LIMIT_EXCEEDED,
                    warning=f"Upstream patch response exceeded {limit} bytes.",
                )
            chunks.append(chunk)
        raw = b"".join(chunks)
        digest = hashlib.sha256(raw).hexdigest()
        return PatchFetchResult(
            source_ref=source_ref,
            fetch_status=PatchFetchStatus.RETRIEVED,
            patch_text=raw.decode("utf-8", errors="replace"),
            patch_sha256=digest,
        )
