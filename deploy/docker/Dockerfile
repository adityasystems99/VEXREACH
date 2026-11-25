# VEXReach Backend Platform Image (API + CLI + Scanner Worker)
# Frontend UI is strictly excluded; consumes/exposes REST API v1 & OpenVEX 0.2.0 artifacts.

FROM golang:1.22-bookworm AS go-builder

WORKDIR /go-src
COPY packages/core/analysis/go_worker ./packages/core/analysis/go_worker
COPY operators/vexreach-operator ./operators/vexreach-operator

RUN cd /go-src/packages/core/analysis/go_worker \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vexreach-go-analyze ./cmd/vexreach-go-analyze \
    && cd /go-src/operators/vexreach-operator \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vexreach-operator-manager ./cmd/manager

FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml README.md ./
COPY packages ./packages
COPY apps ./apps

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir . uvicorn

FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="VEXReach Backend" \
      org.opencontainers.image.description="AI-Assisted, Kubernetes-Native Vulnerability Intelligence Backend Platform" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    VEXREACH_STORAGE_PATH="/var/lib/vexreach/vexreach.db" \
    VEXREACH_DEFAULT_OUTPUT_DIR="/var/lib/vexreach/assessments" \
    VEXREACH_GO_ANALYZER_BINARY_PATH="/usr/local/bin/vexreach-go-analyze"

# Least-privilege non-root user & writable runtime state directory
RUN groupadd --system --gid 10001 vexreach \
    && useradd --system --uid 10001 --gid vexreach --home-dir /nonexistent --shell /usr/sbin/nologin vexreach \
    && mkdir -p /app /var/lib/vexreach/assessments \
    && chown -R 10001:10001 /var/lib/vexreach

WORKDIR /app
COPY --from=go-builder /out/vexreach-go-analyze /usr/local/bin/vexreach-go-analyze
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 packages ./packages
COPY --chown=10001:10001 apps ./apps
COPY --chown=10001:10001 pyproject.toml ./

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

ENTRYPOINT ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
