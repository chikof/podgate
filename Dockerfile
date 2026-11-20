# syntax=docker/dockerfile:1
# Build:  docker build -t podgate .
# Run:    docker run --rm -p 8080:8080 podgate

FROM rust:1.99-slim AS build
WORKDIR /src
# Cache dependencies: build a stub first so source edits do not rebuild them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src
COPY src ./src
# Touch so cargo sees the real sources as newer than the stub build.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# distroless/cc has glibc and libgcc, which the default Rust target needs. No shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/podgate /usr/local/bin/podgate
# The service binds loopback by default; a container must listen on all interfaces.
ENV BIND_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json
EXPOSE 8080
USER nonroot
# No HEALTHCHECK: distroless has no shell, curl or wget to run one, and Docker's HEALTHCHECK
# needs one. Probe `GET /healthz` (liveness) and `GET /readyz` (readiness) from the orchestrator
# instead (Kubernetes httpGet probes, Nomad/Consul HTTP checks, a load balancer health check).
ENTRYPOINT ["/usr/local/bin/podgate"]
