# VEXReach Kubernetes Operator (Go Controller)

This module implements the `vexreach.security.io/v1alpha1` `VulnerabilityAssessment` Go schema ([`api/v1alpha1/vulnerabilityassessment_types.go`](./api/v1alpha1/vulnerabilityassessment_types.go)), worker Job reconciliation & conservative status evaluator ([`internal/controller/vulnerabilityassessment_controller.go`](./internal/controller/vulnerabilityassessment_controller.go)), and operator planning CLI ([`cmd/manager/main.go`](./cmd/manager/main.go)).

## Local Build & Test

```bash
cd operators/vexreach-operator
go vet ./...
go test -v ./...
go build ./cmd/manager
```

## Architecture Contract
- **Zero-Cluster Portability**: All Job synthesis, least-privilege Pod security constraints (`runAsNonRoot`, UID `10001`, `readOnlyRootFilesystem`, dropped capabilities, `automountServiceAccountToken: false`), and status reconciliation logic are verified offline without requiring an active Kubernetes control plane.
- **Standalone Mode Support**: Works alongside standalone CLI (`apps/cli/main.py`), containerized REST API (`apps/api/main.py`), and static manifests under [`deploy/kubernetes/`](../../deploy/kubernetes/).
