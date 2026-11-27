# syntax=docker/dockerfile:1

FROM rust:1.93.1-slim-bookworm AS builder

WORKDIR /build

# 1. Dependency caching stage: copy manifests only and compile dummy targets first.
COPY Cargo.toml Cargo.lock ./
COPY crates/protocol/Cargo.toml crates/protocol/Cargo.toml
COPY crates/crypto/Cargo.toml crates/crypto/Cargo.toml
COPY crates/network/Cargo.toml crates/network/Cargo.toml
COPY crates/relay/Cargo.toml crates/relay/Cargo.toml
COPY crates/client/Cargo.toml crates/client/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml

RUN mkdir -p \
        crates/protocol/src \
        crates/crypto/src \
        crates/network/src \
        crates/relay/src \
        crates/client/src \
        crates/cli/src/bin && \
    for c in protocol crypto network relay client cli; do \
        echo "" > "crates/${c}/src/lib.rs"; \
    done && \
    for b in demo-dest relay-keygen relay-exit relay-middle relay-entry relay-client; do \
        echo "fn main() {}" > "crates/cli/src/bin/${b}.rs"; \
    done && \
    cargo build --release --locked --bins && \
    rm -rf crates

# 2. Real workspace release build.
COPY crates/ crates/
RUN find crates -name "*.rs" -exec touch {} + && \
    cargo build --release --locked --bins && \
    strip \
        target/release/demo-dest \
        target/release/relay-keygen \
        target/release/relay-exit \
        target/release/relay-middle \
        target/release/relay-entry \
        target/release/relay-client

# 3. Minimal non-root Debian slim runtime stage (zero Rust toolchains, compilers, or keys).
FROM debian:bookworm-slim AS runtime

RUN groupadd --gid 10001 relay && \
    useradd --uid 10001 --gid 10001 --shell /usr/sbin/nologin --no-create-home relay && \
    mkdir -p /app /cfg /cfg/entry /cfg/middle /cfg/exit /cfg/client && \
    chown -R 10001:10001 /app /cfg && \
    chmod 0750 /cfg /cfg/entry /cfg/middle /cfg/exit /cfg/client

COPY --from=builder --chmod=0555 /build/target/release/demo-dest /usr/local/bin/demo-dest
COPY --from=builder --chmod=0555 /build/target/release/relay-keygen /usr/local/bin/relay-keygen
COPY --from=builder --chmod=0555 /build/target/release/relay-exit /usr/local/bin/relay-exit
COPY --from=builder --chmod=0555 /build/target/release/relay-middle /usr/local/bin/relay-middle
COPY --from=builder --chmod=0555 /build/target/release/relay-entry /usr/local/bin/relay-entry
COPY --from=builder --chmod=0555 /build/target/release/relay-client /usr/local/bin/relay-client
COPY --chmod=0444 demo/configs/destination.docker.toml /app/destination.toml

USER 10001:10001
WORKDIR /app

ENTRYPOINT ["/usr/local/bin/relay-client", "--help"]
