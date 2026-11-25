"""Authentication, RBAC, rate limiting, request-size limits, and SQLite audit logging."""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from packages.core.config.settings import Settings, get_settings

RoleType = Literal["viewer", "operator", "admin"]
_ROLE_RANK: dict[RoleType, int] = {"viewer": 1, "operator": 2, "admin": 3}

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthPrincipal:
    """Authenticated API identity & role."""

    actor_id: str
    role: RoleType


def parse_api_key_map(settings: Settings) -> dict[str, RoleType]:
    """Parse `VEXREACH_API_KEYS` formatted as `token1:admin,token2:operator`."""
    if settings.api_keys is None:
        return {}
    raw = settings.api_keys.get_secret_value().strip()
    if not raw:
        return {}
    mapping: dict[str, RoleType] = {}
    for entry in raw.split(","):
        cleaned = entry.strip()
        if not cleaned:
            continue
        if ":" in cleaned:
            token, role = cleaned.split(":", 1)
            role_low = role.strip().lower()
            if role_low not in _ROLE_RANK:
                role_low = "viewer"
            mapping[token.strip()] = role_low  # type: ignore[assignment]
        else:
            mapping[cleaned] = "operator"
    return mapping


def _redact_token_id(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return f"key:{digest}"


def require_role(required_role: RoleType):
    """FastAPI dependency enforcing Bearer auth + RBAC when `VEXREACH_API_AUTH_ENABLED=true`."""

    def _dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    ) -> AuthPrincipal:
        settings: Settings = getattr(request.app.state, "settings", get_settings())
        if not settings.api_auth_enabled:
            return AuthPrincipal(actor_id="local-dev", role="admin")

        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer API token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        key_map = parse_api_key_map(settings)
        matched_role: RoleType | None = None
        matched_actor: str | None = None
        presented = credentials.credentials.strip()
        for valid_token, role in key_map.items():
            if hmac.compare_digest(presented.encode("utf-8"), valid_token.encode("utf-8")):
                matched_role = role
                matched_actor = _redact_token_id(valid_token)
                break

        if matched_role is None or matched_actor is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if _ROLE_RANK[matched_role] < _ROLE_RANK[required_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{matched_role}' lacks required permission '{required_role}'.",
            )
        return AuthPrincipal(actor_id=matched_actor, role=matched_role)

    return _dependency


class AuditLogger:
    """SQLite-persisted immutable security audit log (redacts tokens and sensitive payloads)."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    request_id TEXT,
                    detail TEXT
                )
                """
            )

    def log(
        self,
        *,
        principal: AuthPrincipal,
        action: str,
        resource: str,
        status_code: int,
        request_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    timestamp, actor_id, actor_role, action, resource, status_code, request_id, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    principal.actor_id,
                    principal.role,
                    action,
                    resource,
                    status_code,
                    request_id,
                    detail[:300] if detail else None,
                ),
            )

    def list_recent(self, limit: int = 100) -> list[dict[str, object]]:
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, timestamp, actor_id, actor_role, action, resource, status_code, request_id, detail
                FROM audit_logs ORDER BY id DESC LIMIT ?
                """,
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(r) for r in rows]


class RequestGovernanceMiddleware(BaseHTTPMiddleware):
    """Enforces maximum body byte limits and per-client sliding-window rate limits."""

    def __init__(
        self,
        app,
        *,
        max_request_bytes: int = 5 * 1024 * 1024,
        rate_limit_per_minute: int = 120,
    ) -> None:
        super().__init__(app)
        self._max_bytes = max_request_bytes
        self._rate_limit = rate_limit_per_minute
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):
        content_len = request.headers.get("content-length")
        if content_len and content_len.isdigit() and int(content_len) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={
                    "error_code": "PAYLOAD_TOO_LARGE",
                    "message": f"Request payload exceeds {self._max_bytes} byte limit.",
                },
            )

        body = await request.body()
        if len(body) > self._max_bytes:
            return JSONResponse(
                status_code=413,
                content={
                    "error_code": "PAYLOAD_TOO_LARGE",
                    "message": f"Request payload exceeds {self._max_bytes} byte limit.",
                },
            )

        client_key = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with self._lock:
            dq = self._buckets[client_key]
            cutoff = now - 60.0
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self._rate_limit:
                return JSONResponse(
                    status_code=429,
                    headers={"Retry-After": "60"},
                    content={
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "message": "API rate limit exceeded; retry shortly.",
                    },
                )
            dq.append(now)

        return await call_next(request)
