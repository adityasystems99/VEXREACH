"""Connection-pooled, bounded HTTP client for the official OSV.dev v1 API."""

import json
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from pydantic import ValidationError

from packages.core.integrations.osv.exceptions import (
    OSVHTTPError,
    OSVInvalidResponseError,
    OSVNetworkError,
    OSVNotFoundError,
    OSVRateLimitError,
    OSVTimeoutError,
)
from packages.core.integrations.osv.schemas import (
    OSVBatchQueryRequest,
    OSVBatchQueryResponse,
    OSVQueryRequest,
    OSVQueryResponse,
    OSVVulnerability,
    OSVVulnerabilityStub,
)
from packages.core.utils.logging import get_logger

logger = get_logger("integrations.osv")

_SAFE_VULN_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]+$")
_MAX_SNIPPET_CHARS = 512
_MAX_BACKOFF_SECONDS = 5.0


def _validate_base_url(base_url: str) -> str:
    """Verify OSV base URL uses HTTP(S) and normalize trailing slash."""
    cleaned = base_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError(f"Invalid OSV API base URL: '{base_url}'")
    return cleaned


def _parse_retry_after(header_val: str | None) -> float | None:
    if not header_val:
        return None
    try:
        seconds = float(header_val.strip())
        if seconds >= 0:
            return min(seconds, _MAX_BACKOFF_SECONDS)
    except ValueError:
        return None
    return None


class OSVClient:
    """Synchronous HTTP client for https://api.osv.dev/v1/ with timeouts, size bounds, and retries."""

    def __init__(
        self,
        base_url: str = "https://api.osv.dev/v1",
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 20 * 1024 * 1024,
        batch_size: int = 100,
        max_pages: int = 5,
        max_retries: int = 2,
        user_agent: str = "VEXReach/0.1.0",
        http_client: httpx.Client | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = _validate_base_url(base_url)
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.batch_size = max(1, min(batch_size, 1000))
        self.max_pages = max(1, max_pages)
        self.max_retries = max(0, max_retries)
        self.sleep_fn = sleep_fn
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout_seconds),
            headers={
                "User-Agent": user_agent,
                "Accept": "application/json",
            },
            follow_redirects=False,
        )

    def __enter__(self) -> "OSVClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool if owned by this client."""
        if self._owns_client:
            self._client.close()

    def get_vulnerability(self, vuln_id: str) -> tuple[OSVVulnerability, dict[str, Any]]:
        """Retrieve full advisory details via GET /v1/vulns/{id}."""
        cleaned = vuln_id.strip()
        if not cleaned or ".." in cleaned or not _SAFE_VULN_ID_RE.match(cleaned):
            raise ValueError(f"Unsafe or invalid vulnerability ID for OSV lookup: '{vuln_id}'")

        endpoint = f"{self.base_url}/vulns/{quote(cleaned, safe='')}"
        raw_payload = self._request_json("GET", endpoint, not_found_is_specific=True)
        try:
            parsed = OSVVulnerability.model_validate(raw_payload)
        except ValidationError as err:
            raise OSVInvalidResponseError(
                f"OSV /vulns/{cleaned} response violated schema: {err}"
            ) from err
        return parsed, raw_payload

    def query(self, request: OSVQueryRequest) -> tuple[list[OSVVulnerability], list[dict[str, Any]]]:
        """Query vulnerabilities for a single package/version/PURL via POST /v1/query."""
        endpoint = f"{self.base_url}/query"
        all_vulns: list[OSVVulnerability] = []
        raw_responses: list[dict[str, Any]] = []
        current_req = request

        for _page in range(self.max_pages):
            body = current_req.model_dump(exclude_none=True)
            raw_payload = self._request_json("POST", endpoint, json_body=body)
            raw_responses.append(raw_payload)

            try:
                resp = OSVQueryResponse.model_validate(raw_payload)
            except ValidationError as err:
                raise OSVInvalidResponseError(
                    f"OSV /query response violated schema: {err}"
                ) from err

            all_vulns.extend(resp.vulns)
            if not resp.next_page_token:
                break
            current_req = current_req.model_copy(update={"page_token": resp.next_page_token})

        return all_vulns, raw_responses

    def query_batch(
        self,
        queries: list[OSVQueryRequest],
    ) -> tuple[list[list[OSVVulnerabilityStub]], list[dict[str, Any]], int]:
        """Execute POST /v1/querybatch in bounded chunks and paginate incomplete items selectively.

        Returns:
            (stubs_per_query, raw_batch_responses, http_requests_made)
        """
        if not queries:
            return [], [], 0

        endpoint = f"{self.base_url}/querybatch"
        stubs_by_index: list[list[OSVVulnerabilityStub]] = [[] for _ in queries]
        raw_responses: list[dict[str, Any]] = []
        requests_made = 0

        for start in range(0, len(queries), self.batch_size):
            chunk_indices = list(range(start, min(start + self.batch_size, len(queries))))
            pending: list[tuple[int, OSVQueryRequest]] = [
                (idx, queries[idx]) for idx in chunk_indices
            ]

            for _page in range(self.max_pages):
                if not pending:
                    break
                batch_req = OSVBatchQueryRequest(queries=[req for _, req in pending])
                raw_payload = self._request_json(
                    "POST",
                    endpoint,
                    json_body=batch_req.model_dump(exclude_none=True),
                )
                requests_made += 1
                raw_responses.append(raw_payload)

                try:
                    batch_resp = OSVBatchQueryResponse.model_validate(raw_payload)
                except ValidationError as err:
                    raise OSVInvalidResponseError(
                        f"OSV /querybatch response violated schema: {err}"
                    ) from err

                if len(batch_resp.results) != len(pending):
                    raise OSVInvalidResponseError(
                        f"OSV /querybatch returned {len(batch_resp.results)} result(s) "
                        f"for {len(pending)} query item(s); refusing misaligned correlation."
                    )

                next_pending: list[tuple[int, OSVQueryRequest]] = []
                for (orig_idx, orig_req), result_item in zip(
                    pending, batch_resp.results, strict=True
                ):
                    stubs_by_index[orig_idx].extend(result_item.vulns)
                    if result_item.next_page_token:
                        next_pending.append(
                            (
                                orig_idx,
                                orig_req.model_copy(
                                    update={"page_token": result_item.next_page_token}
                                ),
                            )
                        )
                pending = next_pending

            if pending:
                logger.warning(
                    "OSV /querybatch pagination truncated at max_pages=%d for %d query items",
                    self.max_pages,
                    len(pending),
                )

        return stubs_by_index, raw_responses, requests_made

    def _request_json(
        self,
        method: str,
        url: str,
        json_body: dict[str, Any] | None = None,
        not_found_is_specific: bool = False,
    ) -> dict[str, Any]:
        """Execute an HTTP request with bounded streaming, retries on 429/5xx, and JSON validation."""
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                with self._client.stream(method, url, json=json_body) as response:
                    status = response.status_code

                    if status == 404 and not_found_is_specific:
                        snippet = self._read_bounded_bytes(response).decode("utf-8", errors="replace")[
                            :_MAX_SNIPPET_CHARS
                        ]
                        raise OSVNotFoundError(
                            f"OSV vulnerability resource not found (HTTP 404): {url}",
                            status_code=404,
                            response_snippet=snippet,
                        )

                    if status == 429:
                        retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                        snippet = self._read_bounded_bytes(response).decode("utf-8", errors="replace")[
                            :_MAX_SNIPPET_CHARS
                        ]
                        if attempt < self.max_retries:
                            delay = retry_after if retry_after is not None else min(0.5 * (2**attempt), _MAX_BACKOFF_SECONDS)
                            self.sleep_fn(delay)
                            continue
                        raise OSVRateLimitError(
                            f"OSV API rate limit exceeded (HTTP 429) for {url}",
                            status_code=429,
                            retry_after=retry_after,
                            response_snippet=snippet,
                        )

                    if status in {500, 502, 503, 504}:
                        snippet = self._read_bounded_bytes(response).decode("utf-8", errors="replace")[
                            :_MAX_SNIPPET_CHARS
                        ]
                        if attempt < self.max_retries:
                            self.sleep_fn(min(0.5 * (2**attempt), _MAX_BACKOFF_SECONDS))
                            continue
                        raise OSVHTTPError(
                            f"OSV API server error HTTP {status} for {url}: {snippet}",
                            status_code=status,
                            response_snippet=snippet,
                        )

                    if status < 200 or status >= 300:
                        snippet = self._read_bounded_bytes(response).decode("utf-8", errors="replace")[
                            :_MAX_SNIPPET_CHARS
                        ]
                        raise OSVHTTPError(
                            f"OSV API returned HTTP {status} for {url}: {snippet}",
                            status_code=status,
                            response_snippet=snippet,
                        )

                    raw_bytes = self._read_bounded_bytes(response)
                    return self._parse_json_object(raw_bytes, url)

            except httpx.TimeoutException as err:
                last_exc = OSVTimeoutError(
                    f"OSV API request timed out after {self.timeout_seconds}s: {url}"
                )
                if attempt < self.max_retries:
                    self.sleep_fn(min(0.25 * (2**attempt), _MAX_BACKOFF_SECONDS))
                    continue
                raise last_exc from err
            except httpx.TransportError as err:
                last_exc = OSVNetworkError(f"OSV API network transport error for {url}: {err}")
                if attempt < self.max_retries:
                    self.sleep_fn(min(0.25 * (2**attempt), _MAX_BACKOFF_SECONDS))
                    continue
                raise last_exc from err

        if last_exc is not None:  # pragma: no cover - defensive fallback
            raise last_exc
        raise OSVNetworkError(f"Unexpected failure calling OSV API: {url}")  # pragma: no cover

    def _read_bounded_bytes(self, response: httpx.Response) -> bytes:
        """Read streaming response body while enforcing max_response_bytes."""
        content_len = response.headers.get("Content-Length")
        if content_len:
            try:
                declared = int(content_len)
                if declared > self.max_response_bytes:
                    raise OSVInvalidResponseError(
                        f"OSV response Content-Length ({declared} bytes) exceeds limit "
                        f"({self.max_response_bytes} bytes)."
                    )
            except ValueError:
                pass

        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self.max_response_bytes:
                raise OSVInvalidResponseError(
                    f"OSV response body exceeded limit ({self.max_response_bytes} bytes)."
                )
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _parse_json_object(raw_bytes: bytes, url: str) -> dict[str, Any]:
        """Decode UTF-8 response bytes and enforce JSON dictionary root."""
        if not raw_bytes.strip():
            raise OSVInvalidResponseError(f"OSV API returned an empty response body for {url}")
        try:
            decoded = json.loads(raw_bytes.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise OSVInvalidResponseError(
                f"OSV API returned malformed JSON for {url}: {err}"
            ) from err
        if not isinstance(decoded, dict):
            raise OSVInvalidResponseError(
                f"Expected JSON object from OSV API for {url}, got {type(decoded).__name__}."
            )
        return decoded
