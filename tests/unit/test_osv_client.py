"""Unit tests for OSVClient HTTP contracts, pagination, retries, and security bounds."""

import json
from pathlib import Path

import httpx
import pytest

from packages.core.integrations.osv.client import OSVClient
from packages.core.integrations.osv.exceptions import (
    OSVHTTPError,
    OSVInvalidResponseError,
    OSVNetworkError,
    OSVNotFoundError,
    OSVRateLimitError,
    OSVTimeoutError,
)
from packages.core.integrations.osv.schemas import OSVPackageSpec, OSVQueryRequest

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "intelligence"


@pytest.mark.unit
def test_osv_get_vulnerability_success_and_404() -> None:
    """GET /v1/vulns/{id} parses valid advisory and raises OSVNotFoundError on 404."""
    sample = json.loads(
        (FIXTURES_DIR / "osv_ghsa_requests_2023_32681.json").read_text(encoding="utf-8")
    )

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/vulns/GHSA-j8r2-6x86-q33q"):
            return httpx.Response(200, json=sample)
        return httpx.Response(404, json={"message": "Bug not found"})

    http_client = httpx.Client(transport=httpx.MockTransport(_handler))
    with OSVClient(http_client=http_client) as client:
        vuln, raw = client.get_vulnerability("GHSA-j8r2-6x86-q33q")
        assert vuln.id == "GHSA-j8r2-6x86-q33q"
        assert raw["id"] == "GHSA-j8r2-6x86-q33q"

        with pytest.raises(OSVNotFoundError):
            client.get_vulnerability("UNKNOWN-9999")


@pytest.mark.unit
def test_osv_get_vulnerability_rejects_unsafe_ids() -> None:
    """Path traversal or illegal characters in vuln_id raise ValueError before HTTP call."""
    http_client = httpx.Client(transport=httpx.MockTransport(lambda _req: httpx.Response(200, json={})))
    with OSVClient(http_client=http_client) as client:
        for bad_id in ("", "../etc/passwd", "CVE/2023", "id with spaces"):
            with pytest.raises(ValueError, match="Unsafe or invalid vulnerability ID"):
                client.get_vulnerability(bad_id)


@pytest.mark.unit
def test_osv_query_batch_handles_chunking_and_selective_pagination() -> None:
    """POST /v1/querybatch chunks requests and follows next_page_token only for paginated items."""
    calls: list[dict[str, object]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        calls.append(body)
        queries = body["queries"]
        if len(calls) == 1:
            # First page for 2 queries; only index 0 requests pagination
            assert len(queries) == 2
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-1", "modified": "2026-01-01T00:00:00Z"}], "next_page_token": "tok-2"},
                        {"vulns": [{"id": "GHSA-2", "modified": "2026-01-02T00:00:00Z"}]},
                    ]
                },
            )
        # Second call must ONLY contain the paginated query with page_token="tok-2"
        assert len(queries) == 1
        assert queries[0]["page_token"] == "tok-2"
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-3", "modified": "2026-01-03T00:00:00Z"}]}]},
        )

    http_client = httpx.Client(transport=httpx.MockTransport(_handler))
    with OSVClient(http_client=http_client, batch_size=10) as client:
        stubs, raw_pages, req_count = client.query_batch(
            [
                OSVQueryRequest(package=OSVPackageSpec(purl="pkg:pypi/requests@2.28.1")),
                OSVQueryRequest(package=OSVPackageSpec(purl="pkg:pypi/urllib3@1.26.15")),
            ]
        )

    assert req_count == 2
    assert len(raw_pages) == 2
    assert [s.id for s in stubs[0]] == ["GHSA-1", "GHSA-3"]
    assert [s.id for s in stubs[1]] == ["GHSA-2"]


@pytest.mark.unit
def test_osv_query_batch_rejects_mismatched_result_length() -> None:
    """Refuse correlated batch result if OSV returns fewer/more items than queried."""
    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"vulns": []}]})  # 1 instead of 2

    http_client = httpx.Client(transport=httpx.MockTransport(_handler))
    with OSVClient(http_client=http_client) as client:
        with pytest.raises(OSVInvalidResponseError, match="refusing misaligned correlation"):
            client.query_batch(
                [
                    OSVQueryRequest(package=OSVPackageSpec(purl="pkg:pypi/a@1.0")),
                    OSVQueryRequest(package=OSVPackageSpec(purl="pkg:pypi/b@1.0")),
                ]
            )


@pytest.mark.unit
def test_osv_rate_limit_retries_and_raises() -> None:
    """HTTP 429 retries up to max_retries using Retry-After and raises OSVRateLimitError."""
    attempts = 0
    sleeps: list[float] = []

    def _handler(_req: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(429, headers={"Retry-After": "1"}, text="rate limited")

    http_client = httpx.Client(transport=httpx.MockTransport(_handler))
    with OSVClient(http_client=http_client, max_retries=2, sleep_fn=sleeps.append) as client:
        with pytest.raises(OSVRateLimitError) as exc_info:
            client.get_vulnerability("CVE-2023-32681")

    assert attempts == 3
    assert sleeps == [1.0, 1.0]
    assert exc_info.value.retry_after == 1.0


@pytest.mark.unit
def test_osv_400_does_not_retry_and_503_retries() -> None:
    """Client error 400 fails immediately; server error 503 retries cleanly."""
    bad_attempts = 0

    def _bad_req(_req: httpx.Request) -> httpx.Response:
        nonlocal bad_attempts
        bad_attempts += 1
        return httpx.Response(400, json={"message": "invalid query"})

    with OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_bad_req)),
        max_retries=2,
        sleep_fn=lambda _s: None,
    ) as client:
        with pytest.raises(OSVHTTPError) as exc:
            client.get_vulnerability("CVE-2023-0001")
    assert bad_attempts == 1
    assert exc.value.status_code == 400

    srv_attempts = 0

    def _srv_err(_req: httpx.Request) -> httpx.Response:
        nonlocal srv_attempts
        srv_attempts += 1
        return httpx.Response(503, text="unavailable")

    with OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_srv_err)),
        max_retries=1,
        sleep_fn=lambda _s: None,
    ) as client:
        with pytest.raises(OSVHTTPError) as exc2:
            client.get_vulnerability("CVE-2023-0001")
    assert srv_attempts == 2
    assert exc2.value.status_code == 503


@pytest.mark.unit
def test_osv_timeout_network_oversized_and_malformed_json() -> None:
    """Timeouts, transport errors, oversized payloads, and malformed JSON raise typed errors."""
    def _timeout(_req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    with OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_timeout)),
        max_retries=0,
    ) as c1:
        with pytest.raises(OSVTimeoutError):
            c1.get_vulnerability("CVE-2023-0001")

    def _net_err(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("DNS lookup failed")

    with OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_net_err)),
        max_retries=0,
    ) as c2:
        with pytest.raises(OSVNetworkError):
            c2.get_vulnerability("CVE-2023-0001")

    def _oversized_cl(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"id": "' + b"A" * 2048 + b'"}')

    with OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_oversized_cl)),
        max_response_bytes=1024,
    ) as c3:
        with pytest.raises(OSVInvalidResponseError, match="exceeds limit"):
            c3.get_vulnerability("CVE-2023-0001")

    def _oversized_no_cl(_req: httpx.Request) -> httpx.Response:
        resp = httpx.Response(200, stream=httpx.ByteStream(b'{"id": "' + b"A" * 2048 + b'"}'))
        resp.headers.pop("content-length", None)
        return resp

    with OSVClient(
        http_client=httpx.Client(transport=httpx.MockTransport(_oversized_no_cl)),
        max_response_bytes=1024,
    ) as c3_stream:
        with pytest.raises(OSVInvalidResponseError, match="exceeded limit"):
            c3_stream.get_vulnerability("CVE-2023-0001")

    def _malformed(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{bad json")

    with OSVClient(http_client=httpx.Client(transport=httpx.MockTransport(_malformed))) as c4:
        with pytest.raises(OSVInvalidResponseError, match="malformed JSON"):
            c4.get_vulnerability("CVE-2023-0001")
