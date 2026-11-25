"""Controlled integration & plugin registry with explicit least-privilege boundaries."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from pydantic import Field

from packages.core.config.settings import Settings, get_settings
from packages.core.models.base import VEXReachBaseModel


class IntegrationCategory(str, Enum):
    """Supported backend plugin/integration adapter categories."""

    SCANNER = "scanner"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    THREAT_INTELLIGENCE = "threat_intelligence"
    PATCH_SOURCE = "patch_source"
    LLM_PROVIDER = "llm_provider"
    NOTIFICATION = "notification"
    CICD = "cicd"
    KUBERNETES = "kubernetes"


class IntegrationDescriptor(VEXReachBaseModel):
    """Machine-readable status and capability contract for an external integration."""

    integration_id: str
    name: str
    category: IntegrationCategory
    enabled: bool
    configured: bool
    auth_configured: bool
    is_local: bool = False
    capabilities: list[str] = Field(default_factory=list)
    permission_boundary: str
    missing_requirements: list[str] = Field(default_factory=list)


class NotificationAdapter(Protocol):
    """Protocol implemented by notification sinks (webhooks, PR reporters, SIEM)."""

    adapter_id: str

    def send_event(self, payload: dict[str, Any]) -> bool:
        """Deliver structured notification payload without altering VEX status."""


@dataclass
class WebhookNotificationSink:
    """Least-privilege SSRF-guarded HTTPS webhook dispatcher (optional HMAC signature)."""

    webhook_url: str
    adapter_id: str = "https_webhook"
    signing_secret: str | None = None
    allowed_hosts: tuple[str, ...] = ("hooks.slack.com", "api.github.com")
    timeout_seconds: float = 10.0
    http_client: httpx.Client | None = None

    def validate_destination(self) -> tuple[bool, str | None]:
        parsed = urlparse(self.webhook_url.strip())
        if parsed.scheme != "https" or not parsed.hostname:
            return False, "Webhook URL must use HTTPS."
        host = parsed.hostname.lower()
        if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
            return False, f"Refusing local/loopback webhook target '{host}'."
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, f"Refusing private/metadata IP '{host}'."
        except ValueError:
            pass
        if host not in {h.lower() for h in self.allowed_hosts}:
            return False, f"Webhook host '{host}' is not in allowlist {sorted(self.allowed_hosts)}."
        return True, None

    def send_event(self, payload: dict[str, Any]) -> bool:
        ok, err = self.validate_destination()
        if not ok:
            raise ValueError(err)
        import json

        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.signing_secret:
            sig = hmac.new(
                self.signing_secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            headers["X-VEXReach-Signature-256"] = f"sha256={sig}"

        if self.http_client is not None:
            resp = self.http_client.post(self.webhook_url, content=body, headers=headers)
        else:
            with httpx.Client(
                timeout=httpx.Timeout(self.timeout_seconds), follow_redirects=False
            ) as client:
                resp = client.post(self.webhook_url, content=body, headers=headers)
        return 200 <= resp.status_code < 300


@dataclass
class IntegrationRegistry:
    """Central registry tracking backend provider adapters cleanly without arbitrary plugin exec."""

    _custom_descriptors: dict[str, Callable[[Settings], IntegrationDescriptor]] = field(
        default_factory=dict
    )

    def register(
        self,
        integration_id: str,
        inspector: Callable[[Settings], IntegrationDescriptor],
    ) -> None:
        self._custom_descriptors[integration_id] = inspector

    def inspect_all(self, settings: Settings | None = None) -> list[IntegrationDescriptor]:
        cfg = settings or get_settings()
        trivy_found = shutil.which(cfg.trivy_path) is not None
        llm_key_present = cfg.llm_api_key is not None and bool(
            cfg.llm_api_key.get_secret_value().strip()
        )
        hosted_llm = cfg.llm_provider in {
            "openai",
            "openai_compatible",
            "openrouter",
            "anthropic",
            "gemini",
        }
        llm_missing: list[str] = []
        if hosted_llm and not llm_key_present:
            llm_missing.append("VEXREACH_LLM_API_KEY not configured for hosted LLM provider.")

        descriptors = [
            IntegrationDescriptor(
                integration_id="trivy",
                name="Trivy Scanner",
                category=IntegrationCategory.SCANNER,
                enabled=True,
                configured=trivy_found,
                auth_configured=True,
                is_local=True,
                capabilities=["filesystem_sbom", "filesystem_vuln_scan"],
                permission_boundary="Read-only target directory inspection; shell=False; bounded output.",
                missing_requirements=[]
                if trivy_found
                else [f"Binary '{cfg.trivy_path}' not found on host PATH."],
            ),
            IntegrationDescriptor(
                integration_id="go_static_analyzer",
                name="Go AST Static Reachability Analyzer",
                category=IntegrationCategory.SCANNER,
                enabled=True,
                configured=bool(
                    (cfg.go_analyzer_binary_path and Path(cfg.go_analyzer_binary_path).is_file())
                    or shutil.which(cfg.go_path)
                    or (os.name == "nt" and Path(r"C:\Program Files\Go\bin\go.exe").is_file())
                ),
                auth_configured=True,
                is_local=True,
                capabilities=["go_ast_call_graph", "go_mod_analysis", "entry_point_reachability"],
                permission_boundary="Read-only Go source AST parsing via shell=False subprocess; zero target code execution.",
                missing_requirements=[]
                if (
                    (cfg.go_analyzer_binary_path and Path(cfg.go_analyzer_binary_path).is_file())
                    or shutil.which(cfg.go_path)
                    or (os.name == "nt" and Path(r"C:\Program Files\Go\bin\go.exe").is_file())
                )
                else [f"Go compiler '{cfg.go_path}' not found on host PATH and no precompiled analyzer configured."],
            ),
            IntegrationDescriptor(
                integration_id="osv_dev",
                name="OSV.dev API v1",
                category=IntegrationCategory.VULNERABILITY_INTELLIGENCE,
                enabled=True,
                configured=True,
                auth_configured=True,
                is_local=False,
                capabilities=["batch_query", "advisory_lookup", "sqlite_cache"],
                permission_boundary="Unauthenticated HTTPS read-only queries to api.osv.dev; untrusted response schema validation.",
            ),
            IntegrationDescriptor(
                integration_id="epss_and_kev",
                name="FIRST EPSS & CISA KEV",
                category=IntegrationCategory.THREAT_INTELLIGENCE,
                enabled=True,
                configured=True,
                auth_configured=True,
                is_local=False,
                capabilities=["epss_scores", "kev_catalog", "offline_snapshot"],
                permission_boundary="Read-only HTTPS feeds or local JSON files; never assigns exploitability.",
            ),
            IntegrationDescriptor(
                integration_id="github_patch_diff",
                name="Upstream Patch Diff Fetcher",
                category=IntegrationCategory.PATCH_SOURCE,
                enabled=True,
                configured=True,
                auth_configured=True,
                capabilities=["allowlisted_https_diff", "local_diff_files", "ast_hunk_diff"],
                permission_boundary="HTTPS host allowlist + SSRF private IP block + size caps; never runs git clone hooks.",
            ),
            IntegrationDescriptor(
                integration_id=f"llm:{cfg.llm_provider}",
                name=f"LLM Adapter ({cfg.llm_provider})",
                category=IntegrationCategory.LLM_PROVIDER,
                enabled=cfg.llm_provider not in {"disabled"},
                configured=(cfg.llm_provider in {"disabled", "heuristic", "ollama"}) or llm_key_present,
                auth_configured=llm_key_present or cfg.llm_provider in {"disabled", "heuristic", "ollama"},
                is_local=cfg.llm_provider in {"disabled", "heuristic", "ollama"},
                capabilities=["quarantined_advisory_summary", "unverified_symbol_proposals"],
                permission_boundary="Zero shell/filesystem access; untrusted prompt quarantine; disallowed security status stripping.",
                missing_requirements=llm_missing,
            ),
            IntegrationDescriptor(
                integration_id="kubernetes_backend",
                name="Kubernetes Backend Adapter",
                category=IntegrationCategory.KUBERNETES,
                enabled=cfg.kubernetes_enabled,
                configured=cfg.kubernetes_enabled,
                auth_configured=bool(cfg.kubeconfig_path),
                is_local=False,
                capabilities=["namespace_job_manifests", "vulnerability_assessment_crd"],
                permission_boundary=f"Optional externally configured kubeconfig/in-cluster SA scoped to namespace '{cfg.kubernetes_namespace}'.",
                missing_requirements=[]
                if cfg.kubernetes_enabled
                else ["Disabled by default (VEXREACH_KUBERNETES_ENABLED=false); standalone CLI/API works without cluster."],
            ),
        ]
        for key in sorted(self._custom_descriptors):
            descriptors.append(self._custom_descriptors[key](cfg))
        return descriptors
