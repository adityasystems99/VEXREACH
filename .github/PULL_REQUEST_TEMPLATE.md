## Summary
Describe the backend change cleanly and list the affected engines, API routes, deployment manifests, or docs.

## Security & Evidence Checklist
- [ ] Preserves strict separation across dependency presence, candidate symbol, static path, runtime execution, and exploitability.
- [ ] Does not emit `not_affected` from incomplete scans, missing dependency verification, or non-observation at runtime.
- [ ] Keeps all LLM inputs quarantined (advisories/diffs treated as untrusted text) and validates structured outputs deterministically.
- [ ] Introduces zero hardcoded secrets, URL credentials, or overly broad RBAC (`cluster-admin`).
- [ ] Includes updated tests (`pytest`) and API contract docs (`docs/api/openapi.v1.json` if API changed).
