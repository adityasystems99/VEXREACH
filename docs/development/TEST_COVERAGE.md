# VEXReach Test Coverage & Verification Matrix

**Last Verified:** 2026-11-25  
- Python (`pytest -v -rs`): **163 passed, 3 skipped in 44.34s**  
- Go (`go test -v ./...`): **7 passed** (`go_worker/internal/analyzer`: `3 passed`; `vexreach-operator`: `4 passed`)

---

## 1. Unit & Integration Suite Breakdown

| Test File | Scope | External Mocks / Dependencies | Status |
| --- | --- | --- | --- |
| `tests/unit/test_cli.py` | Typer CLI `--help`, `version`, `check-config`, `analyze --help`, subcommand presence | Pure Typer `CliRunner` | Verified |
| `tests/unit/test_config.py` | `Settings` env overrides (`VEXREACH_*`) & defaults | None | Verified |
| `tests/unit/test_logging.py` | Console & JSON log formatters | None | Verified |
| `tests/unit/test_safe_path.py` | Path traversal defense & SHA-256 hashing | `tmp_path` | Verified |
| `tests/unit/test_models.py` | Legacy foundation + OpenVEX serialization | None | Verified |
| `tests/unit/test_discovery_models.py` | Referential integrity of `DiscoveryResult`, `PackageRecord`, `VulnerabilityRecord` | None | Verified |
| `tests/unit/test_target_validator.py` | Directory existence, permissions, manifest hints (zero execution) | `tmp_path` | Verified |
| `tests/unit/test_trivy_client.py` | Trivy binary checks, timeouts, output caps, JSON shape checks | Mocked `subprocess.run` | Verified |
| `tests/unit/test_trivy_parser.py` | Valid/clean/malformed Trivy JSON parsing | Fixture files | Verified |
| `tests/unit/test_cyclonedx_parser.py` | CycloneDX 1.4–1.6 components, scopes, completeness status | Fixture files | Verified |
| `tests/unit/test_normalizer.py` | PURL parsing, ecosystem normalization, CVSS deduplication | None | Verified |
| `tests/unit/test_evidence_store.py` | Evidence persistence, SHA-256 hashing, round-trip `load_assessment` | `tmp_path` | Verified |
| `tests/unit/test_osv_client.py` | Batch chunking, pagination, rate-limit retries, response caps, errors | `httpx.MockTransport` | Verified |
| `tests/unit/test_osv_schemas_and_mapper.py` | OSV v1 schema parsing & ecosystem normalization | Fixture files | Verified |
| `tests/unit/test_correlator.py` | Exact/alias matching, conflict preservation, partial enrichment | None | Verified |
| `tests/unit/test_advisory_cache.py` | SQLite TTL, `modified` invalidation, SHA-256 tamper eviction | `tmp_path` SQLite | Verified |
| `tests/unit/test_version_ranges.py` | PyPI PEP 440, SemVer 2.0.0, Go `v`-prefix/pseudo, Kleene 3-valued ranges | None | Verified |
| `tests/unit/test_reachability_models.py` | 6-state taxonomy, `CandidateVulnerableSymbol` AI guard, manifest serialization | None | Verified |
| `tests/unit/test_python_parser_and_symbols.py` | Python discovery, `src/` layout, syntax/decode guards, AST symbols | `tmp_path` (1 Windows symlink skip) | Verified |
| `tests/unit/test_import_and_call_resolver.py` | Absolute/relative/aliased/scoped imports, wildcards, class/method/dynamic calls | `tmp_path` | Verified |
| `tests/unit/test_call_graph_and_entry_points.py` | Bounded DiGraph, multi-site edge merging, cycles, `nx.has_path`, FastAPI/Flask/Typer/Click/config | `tmp_path` | Verified |
| `tests/unit/test_dependency_symbols.py` | Manifest formats, PyPI-import resolution, non-executing AST verification | `fake_dep_sources` | Verified |
| `tests/unit/test_ai_sanitizer_and_llm.py` | Prompt injection detection, nonce framing, unauthorized verdict stripping, OpenAI/Anthropic/Disabled providers | `httpx.MockTransport` | Verified |
| `tests/unit/test_patch_parser_and_validator.py` | Patch SSRF/redirect/size blocking, AST version diff comparator, cross-package & hallucination rejection | `httpx.MockTransport` + `fake_requests_dep` | Verified |
| `tests/unit/test_attack_path.py` | Public/authenticated HTTP surfaces, `Depends` auth barrier, tainted vs constant vs `SafeLoader` flows | Fixture `web_app` | Verified |
| `tests/unit/test_openvex_policy_and_validator.py` | OpenVEX 0.2.0 schema invariants + fail-closed `not_affected` vs `under_investigation` gates | Synthetic `DiscoveryResult` | Verified |
| `tests/integration/test_discovery_pipeline.py` | End-to-end Discovery + CLI `scan` (partial/failed exit codes) | `_FakeTrivyClient` (1 live Trivy skip) | Verified |
| `tests/integration/test_intelligence_pipeline.py` | Discovery -> OSV enrichment + SQLite cache + `intelligence` CLI | `_FakeTrivyClient` + `MockTransport` (1 offline live OSV skip) | Verified |
| `tests/integration/test_python_reachability.py` | Fixtures A–M + CLI `analyze` persistence + Discovery -> OSV -> Python Reachability | `_FakeTrivyClient` + `MockTransport` + Fixtures A–M | Verified |
| `tests/integration/test_ai_security_pipeline.py` | Poisoned diff + adversarial LLM -> AST validator -> Reachability + CLI `extract-symbols` | `_FakeTrivyClient` + `MockTransport` + `fake_requests_dep` | Verified |
| `tests/integration/test_attack_path_pipeline.py` | Discovery -> Reachability -> Attack Paths -> `EvidenceStore` -> CLI `attack-paths` | `_FakeTrivyClient` + `MockTransport` | Verified |
| `tests/integration/test_openvex_mvp_pipeline.py` | Full end-to-end Python MVP -> OpenVEX 0.2.0 schema validation -> `SQLiteVEXStore` monotonic history -> CLI `vex` | `_FakeTrivyClient` + `MockTransport` + `fake_requests_dep` | Verified |
| `tests/unit/test_risk_intelligence.py` | Threat feed EPSS/KEV parsing & deterministic `[0..100]` contextual risk prioritization | `httpx.MockTransport` | Verified |
| `tests/unit/test_providers_and_registry.py` | Gemini (`x-goog-api-key`) & OpenRouter retries, `CredentialMissingError`, `IntegrationRegistry`, SSRF-safe HMAC webhook sink | `httpx.MockTransport` | Verified |
| `tests/unit/test_runtime_continuous_simulator.py` | Runtime observation correlation (and non-observation safety), source/SBOM/advisory drift detection, What-If OSV upgrade range simulation | `tmp_path` | Verified |
| `tests/unit/test_deployment_and_k8s.py` | Offline K8s CRD/Job manifest builders, offline cluster inspection, YAML validation & least-privilege RBAC/non-root Docker assertions | `tmp_path`, `pyyaml` | Verified |
| `tests/unit/test_benchmark_runner.py` | Reproducible Python (`15/15`) & Go (`6/6`) static reachability benchmarks (`0` false-safe regressions) | Fixtures A–M & Go fixtures | Verified |
| `tests/integration/test_api_backend.py` | FastAPI REST v1 lifecycle: `/healthz`, `/readyz`, OpenAPI, Bearer RBAC (`401`/`403`), `413`/`429`, async/sync jobs, non-conflated views, runtime, simulate, reassess, webhooks, audit logs | FastAPI `TestClient` + `_FakeTrivyClient` | Verified |
| `tests/integration/test_go_reachability_pipeline.py` | Go AST reachability -> Attack Path -> Risk -> OpenVEX 0.2.0 + CLI `analyze --language go` + FastAPI `analyze_go` | Live compiled `go_worker` + `_FakeTrivyClient` | Verified |
| `packages/core/analysis/go_worker/.../*_test.go` | Go AST direct/HTTP router reachability, no-path vs `reflect` uncertainty, depth limit & missing symbol failure | Pure Go test runner (`go test`) | Verified |
| `operators/vexreach-operator/.../*_test.go` | `VulnerabilityAssessment` CRD JSON round-trip, least-privilege Job manifest builder, conservative status reconciliation | Pure Go test runner (`go test`) | Verified |

---

## 2. Roadmap Scenario Corpus Coverage (Section 11)

| Scenario | Status | Fixture / Test |
| --- | --- | --- |
| A. Vulnerable dependency with static path | Covered | `fixture_a_direct`, `fixture_b_multilevel`, `test_end_to_end_python_mvp_to_validated_openvex_and_history` |
| B. Vulnerable dependency with no path in static subset | Covered | `fixture_e_no_path`, `fixture_l_multiple_symbols`, `test_openvex_policy_and_validator.py` |
| C. Incomplete/conflicting advisory intelligence | Covered | `test_discovery_to_intelligence_enrichment_and_caching`, `test_end_to_end_python_mvp_to_validated_openvex_and_history` |
| D. Dynamic behavior preventing negative verdict | Covered | `fixture_f_dynamic_getattr`, `test_openvex_policy_and_validator.py` |
| Prompt injection & invalid/hallucinated AI output | Covered | `poisoned_patch.diff`, `test_ai_sanitizer_and_llm.py`, `test_patch_parser_and_validator.py`, `test_ai_security_pipeline.py` |
| Attack path vs call path separation | Covered | `tests/fixtures/attack_path/web_app/routes.py`, `test_attack_path.py` |
| OpenVEX policy completeness & schema validation | Covered | `test_openvex_policy_and_validator.py`, `test_openvex_mvp_pipeline.py` |
| E. Dependency upgrade removing vulnerable function | Covered | `test_what_if_simulator_evaluates_osv_ranges_and_requires_isolated_tests`, `test_api_end_to_end_assessment_lifecycle_non_conflated_views_and_extensions` |
| F/G. Runtime observation / insufficient coverage | Covered | `test_runtime_correlator_and_non_observation_never_triggers_not_affected`, `test_api_end_to_end_assessment_lifecycle_non_conflated_views_and_extensions` |
| H. Kubernetes workload assessment & RBAC | Covered (Manifest/Job/Operator Spec) | `test_deployment_and_k8s.py` *(Go operator compilation blocked locally without Go SDK)* |
