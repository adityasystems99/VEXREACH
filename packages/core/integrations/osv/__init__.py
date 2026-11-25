"""OSV.dev API v1 integration adapter."""

from packages.core.integrations.osv.client import OSVClient
from packages.core.integrations.osv.exceptions import (
    OSVError,
    OSVHTTPError,
    OSVInvalidResponseError,
    OSVNetworkError,
    OSVNotFoundError,
    OSVRateLimitError,
    OSVTimeoutError,
)
from packages.core.integrations.osv.mapper import (
    from_osv_ecosystem,
    map_osv_to_advisory,
    to_osv_ecosystem,
)
from packages.core.integrations.osv.schemas import (
    OSVAffected,
    OSVAffectedPackage,
    OSVBatchQueryRequest,
    OSVBatchQueryResponse,
    OSVBatchQueryResultItem,
    OSVEvent,
    OSVPackageSpec,
    OSVQueryRequest,
    OSVQueryResponse,
    OSVRange,
    OSVReference,
    OSVSeverity,
    OSVVulnerability,
    OSVVulnerabilityStub,
)

__all__ = [
    "OSVClient",
    "OSVError",
    "OSVHTTPError",
    "OSVInvalidResponseError",
    "OSVNetworkError",
    "OSVNotFoundError",
    "OSVRateLimitError",
    "OSVTimeoutError",
    "OSVAffected",
    "OSVAffectedPackage",
    "OSVBatchQueryRequest",
    "OSVBatchQueryResponse",
    "OSVBatchQueryResultItem",
    "OSVEvent",
    "OSVPackageSpec",
    "OSVQueryRequest",
    "OSVQueryResponse",
    "OSVRange",
    "OSVReference",
    "OSVSeverity",
    "OSVVulnerability",
    "OSVVulnerabilityStub",
    "from_osv_ecosystem",
    "map_osv_to_advisory",
    "to_osv_ecosystem",
]
