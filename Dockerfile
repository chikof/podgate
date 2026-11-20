# syntax=docker/dockerfile:1
# Build:  docker build -t podgate .
# Run:    docker run --rm -p 8080:8080 -v podgate-admin:/run/podgate podgate

FROM rust:1.99-slim AS build
# Pingora's zlib-ng build needs cmake, make and a C++ compiler (the slim image has none).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Cache dependencies: build stubs first so source edits do not rebuild them. Every workspace member needs
# its manifest here (the `members = ["crates/*"]` glob must resolve) and a stub source.
COPY Cargo.toml Cargo.lock ./
COPY crates/podgate-model/Cargo.toml crates/podgate-model/Cargo.toml
RUN mkdir src crates/podgate-model/src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs crates/podgate-model/src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src crates/podgate-model/src
COPY src ./src
COPY crates ./crates
# Touch so cargo sees the real sources as newer than the stub build.
RUN touch src/main.rs src/lib.rs crates/podgate-model/src/lib.rs && cargo build --release --locked
# The runtime image has no shell, so the admin socket directory is made here and copied over.
RUN mkdir -p /out/run/podgate

# distroless/cc has glibc and libgcc, which the default Rust target needs. No shell, no package manager.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/podgate /usr/local/bin/podgate
COPY --from=build --chown=nonroot:nonroot /out/run/podgate /run/podgate
# The service binds loopback by default; a container must listen on all interfaces.
ENV PROXY_ADDR=0.0.0.0:8080 \
    ADMIN_SOCKET=/run/podgate/admin.sock \
    LOG_FORMAT=json
EXPOSE 8080
USER nonroot
# No HEALTHCHECK: distroless has no shell, curl or wget to run one. The admin API is a unix
# socket, so share /run/podgate as a volume with the PaaS agent, which calls `GET /healthz`
# (liveness) and `GET /readyz` (readiness) there.
ENTRYPOINT ["/usr/local/bin/podgate"]
