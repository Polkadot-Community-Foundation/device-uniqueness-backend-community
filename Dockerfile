# syntax=docker/dockerfile:1

# One build, one binary, ONE image.
#
# Every service and worker is a ROLE of the single `dub` binary
# (`dub --role device-attestation-api`; `dub --list-roles` prints the ten). There is one
# runtime stage, so there is one image: the deployment selects the role, the
# image does not. See docs/plans/active/one-image-one-binary.md.
#
# `ENTRYPOINT` with **no `CMD`** is deliberate. A container started with no
# arguments must fail loudly listing the accepted roles — never default into
# somebody else's service. That failure mode ("a mis-targeted build still
# starts, still passes /readyz, and serves the wrong thing") is what the old
# per-service image split existed to prevent, and it now lives in a values
# file instead of a build target: `scripts/verify_role_split.sh` asserts that
# every compose service and chart workload names a role the binary accepts, and
# that each role is named by exactly one of each.
#
# TLS is pure-Rust (ring + rustls), so no OpenSSL/system TLS libs are needed.
# Migrations are embedded at compile time (sqlx::migrate!), so the build needs
# the source tree but not a live database.

FROM rust:1.95-bookworm AS builder
# The People runtime this image targets: testnet or polkadot.
ARG DUB_NETWORK=testnet
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p dub \
    && mkdir -p /out \
    && cp target/release/dub /out/

# The bare binary, for the release workflow to export with
# `--target binaries --output type=local`. It reuses the builder layer the image
# is built from, so the released tarball and the released image hold the same
# bytes.
FROM scratch AS binaries
COPY --from=builder /out/ /

# --- the runtime image -------------------------------------------------------
#
# ca-certificates is NOT optional: the chain-facing roles dial a wss:// RPC, and
# without the trust store that fails at runtime rather than at build time.
#
# There is deliberately no `curl`: the compose healthcheck runs
# `dub --healthcheck`, which GETs this container's own /readyz on the
# BIND_ADDR port. That removed the `runtime-http` base layer whose only purpose
# was carrying curl for six of the ten stages — so the workers did not gain a
# network client when the images merged. Kubernetes uses httpGet probes and
# needs nothing in the image either way.
FROM debian:bookworm-slim AS dub
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Explicit GID, not `--user-group`: that picks the next free system GID (999
# here), so a manifest saying `runAsGroup: 10001` would be describing a group the
# image does not have — and an fsGroup-mounted secret would be unreadable.
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid 10001 appuser
COPY --from=builder /out/dub /usr/local/bin/
USER appuser
# 8080 is the HTTP roles' port; 9090 is the Prometheus exporter every role
# serves, reachable on the private metrics network and never published. EXPOSE
# is documentation — the four worker roles bind only the latter.
EXPOSE 8080 9090
ENTRYPOINT ["dub"]
