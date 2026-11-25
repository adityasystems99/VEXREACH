# ADR-001: Architectural Style - Modular Monolith First

## Status
Accepted

## Context
VEXReach consists of eight logical capabilities: Discovery, AI Security Intelligence, Hybrid Reachability, Attack Path Intelligence, Risk Intelligence, What-If Simulator, Continuous Evidence Intelligence, and Evidence/OpenVEX Generation.

In modern distributed systems engineering, there is a common temptation to prematurely decompose systems into microservices (e.g., separate microservices for SBOM ingestion, AI analysis, graph calculation, and VEX generation, communicating via gRPC or message queues).

However:
1. Microservices introduce substantial operational overhead: network latency, serialization costs, schema version drift, distributed tracing complexity, complex container orchestration, and difficult local developer onboarding.
2. The core workflow of VEXReach is an interactive or pipeline-based correlation pipeline where intermediate data structures (e.g., in-memory NetworkX call graphs, parsed ASTs) are memory-dense and expensive to serialize across network boundaries.
3. Users need to run VEXReach in multiple environments: as a local developer CLI tool (`vexreach scan .`), as an ephemeral CI/CD GitHub Action step, as a long-running Kubernetes Job, and as an asynchronous REST API service.

## Decision
We will build VEXReach as a **modular monolith** in Python:
- All core engines will reside within the same codebase under `packages/core/engines/`.
- Each engine will communicate with other engines strictly through typed Pydantic models and clean programmatic service interfaces.
- Engines will not directly access other engines' internal storage or private helper functions.
- The monolithic core will be packaged as a clean Python library that can be imported directly by both the CLI (`apps/cli`) and the API service (`apps/api`).

## Consequences

### Positive
- **Simplicity of Development**: A single virtual environment, straightforward pytest execution, and single-process debugging.
- **High Performance**: Zero network serialization overhead when passing large call graphs and ASTs between engines.
- **Portability**: The exact same engine can run in a developer's laptop shell, a Docker container, a GitHub Action, or a Kubernetes Pod without orchestrating a mesh of support services.
- **Refactoring Agility**: Public and private contracts can be adjusted cleanly with type checker validation (`mypy` / `pyright`).

### Negative / Trade-offs
- Scaling independent components (e.g., horizontally scaling AI LLM calls separately from AST parsing) requires intra-process concurrency or task workers (e.g., asyncio / background workers) rather than independent container scaling.
- If a future requirement demands independent microservices, we will extract well-defined engines along their existing Pydantic interface boundaries without requiring redesign of the business logic.
