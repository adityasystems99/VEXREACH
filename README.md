# VEXReach

> **AI-Assisted, Kubernetes-Native Vulnerability Intelligence Platform**

VEXReach bridges the critical gap between **package vulnerability presence** and **practical exploitability** by correlating Software Bill of Materials (SBOM), upstream security advisories, source-code call graphs, and runtime execution evidence.

---

## The Problem

Modern application security tools produce excessive false alarms because they rely on lockfiles or container manifests. A vulnerable library present in a deployment might:
1. Never have its vulnerable functions invoked.
2. Only be reachable through unexposed or authenticated internal paths.
3. Be shielded by input validation or configuration barriers.

## The VEXReach Approach

VEXReach computes verifiable vulnerability reachability:
- **Presence vs. Reachability**: Determines if the vulnerable function is statically reachable from application entry points.
- **Dynamic Uncertainty Preservation**: If dynamic dispatch (`getattr`, `eval`) obscures execution paths, VEXReach reports `under_investigation` rather than falsely declaring safety.
- **AI as Investigator, Not Oracle**: LLMs parse unstructured advisories and upstream patch diffs, but 100% of VEX statuses are evaluated by deterministic, auditable rules.
- **Standardized Output**: Emits machine-readable **OpenVEX 0.2.0** documents with traceable provenance.

---

## Architecture Overview

VEXReach is architected as an 8-engine modular monolith:

1. **Discovery Engine**: Ingests SBOMs (CycloneDX, SPDX), queries OSV and NVD.
2. **AI Security Intelligence Engine**: Analyzes upstream git patches to pinpoint vulnerable function signatures.
3. **Hybrid Reachability Engine**: Parses application ASTs and builds interprocedural call graphs.
4. **Attack Path Intelligence**: Traces external ingress routes and trust boundaries.
5. **Risk Intelligence**: Contextualizes risk via CVSS, EPSS, and KEV.
6. **What-If Security Simulator**: Pre-evaluates dependency upgrades and breaking changes.
7. **Continuous Evidence Intelligence**: Monitors drift and triggers targeted reassessments.
8. **Evidence & OpenVEX Engine**: Applies deterministic policies and generates verifiable OpenVEX statements.

For detailed architecture documentation, see:
- [System Architecture](docs/architecture/SYSTEM_ARCHITECTURE.md)
- [Data Flow Specification](docs/architecture/DATA_FLOW.md)
- [Threat Model](docs/threat-model/THREAT_MODEL.md)
- [Architecture Decision Records](docs/decisions/)

---

## Quickstart

### Prerequisites
- Python 3.12+ (tested on Python 3.12, 3.13, 3.14)
- Git
- [Trivy](https://trivy.dev/) CLI (required for running `vexreach scan` vulnerability discovery)

### Installation
```bash
# Clone the repository
git clone https://github.com/vexreach/vexreach.git
cd vexreach

# Create and activate virtual environment
python -m venv .venv

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate

# Install VEXReach in editable mode with development dependencies
pip install -e ".[dev]"
```

### Running the CLI
```bash
# Check version and environment status
vexreach version

# Validate system configuration and Trivy availability
vexreach check-config

# Run Discovery Engine against a local repository
vexreach scan ./sample-app --output ./out --format table

# Run Discovery Engine + OSV.dev Vulnerability Intelligence enrichment
vexreach scan ./sample-app --output ./out --enrich

# Inspect a stored assessment's intelligence report
vexreach intelligence ./out

# Run Python AST static call-graph reachability analysis standalone or with scan
vexreach analyze ./my-app --symbols ./symbols.json --output ./out
vexreach scan ./my-app --enrich --analyze --symbols ./symbols.json --output ./out

# Run AI/Patch Symbol Extraction, Attack Path Intelligence, and OpenVEX 0.2.0 emission
vexreach extract-symbols ./out --patch-dir ./patches --dependency-source ./vendor_src
vexreach attack-paths ./out --target ./my-app
vexreach vex ./out --format json > openvex.vex.json

# Full End-to-End Python MVP workflow in one command
vexreach scan ./my-app --enrich --extract-symbols --patch-dir ./patches --dependency-source ./vendor_src --analyze --attack-paths --emit-vex --output ./out
```

For detailed documentation, see:
- [Project Status](docs/development/PROJECT_STATUS.md)
- [Discovery Engine Guide](docs/development/DISCOVERY_ENGINE.md)
- [Vulnerability Intelligence Engine Guide](docs/development/VULNERABILITY_INTELLIGENCE.md)
- [AI Security Intelligence Guide](docs/development/AI_SECURITY_INTELLIGENCE.md)
- [Python Static Reachability Guide](docs/development/PYTHON_STATIC_REACHABILITY.md)
- [Attack Path Intelligence Guide](docs/development/ATTACK_PATH_INTELLIGENCE.md)
- [Evidence & OpenVEX Engine Guide](docs/development/OPENVEX_AND_POLICY_ENGINE.md)

---

## Development & Testing

```bash
# Run unit test suite
pytest

# Run tests with coverage
pytest --cov=packages --cov=apps

# Run linting and code formatting checks
ruff check .
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
