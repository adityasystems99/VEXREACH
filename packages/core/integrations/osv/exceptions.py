"""Typed exceptions for OSV.dev API integration failures."""


class OSVError(Exception):
    """Base exception for all OSV client or schema failures."""


class OSVNetworkError(OSVError):
    """Raised when a transport, DNS, TLS, or connection error occurs."""


class OSVTimeoutError(OSVError):
    """Raised when an OSV HTTP request exceeds the configured timeout."""


class OSVHTTPError(OSVError):
    """Raised when the OSV API returns an unexpected non-2xx HTTP status."""

    def __init__(
        self,
        message: str,
        status_code: int,
        response_snippet: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_snippet = response_snippet


class OSVNotFoundError(OSVHTTPError):
    """Raised when GET /v1/vulns/{id} returns HTTP 404."""


class OSVRateLimitError(OSVHTTPError):
    """Raised when OSV API returns HTTP 429 Too Many Requests after retries."""

    def __init__(
        self,
        message: str,
        status_code: int = 429,
        retry_after: float | None = None,
        response_snippet: str = "",
    ) -> None:
        super().__init__(message, status_code=status_code, response_snippet=response_snippet)
        self.retry_after = retry_after


class OSVInvalidResponseError(OSVError):
    """Raised when an OSV API payload exceeds size limits, is malformed JSON, or violates schema."""
