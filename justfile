default: check

# Fast offline gate — the same set check.yml's `offline` job runs, so a green
# `just check` means the same thing locally as in CI. (It drifted once: the
# deployment gates were added to CI only, and nothing here noticed.)
check: fmt-check lint test verify-config

# The deployment invariants: compose secret boundaries and one-service-one-image.
# Both offline.
verify-config:
    scripts/verify_compose_boundaries.sh
    scripts/verify_role_split.sh

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

# Canonical deterministic live gate: 11 suites / 24 ignored tests against two
# per-run scratch Postgres containers. CI invokes the same script directly.
test-live: test-live-db

test-live-db:
    scripts/run_live_suites.sh db cargo test

# Optional external smokes, deliberately outside the merge/release gate.
test-live-chain:
    scripts/run_live_suites.sh chain cargo test

test-live-providers:
    scripts/run_live_suites.sh providers cargo test

# Line coverage of the offline suite only (what `just check` runs). Needs
# cargo-llvm-cov (prebuilt releases: https://github.com/taiki-e/cargo-llvm-cov/releases)
# plus `rustup component add llvm-tools`.
coverage:
    cargo llvm-cov --workspace --summary-only

# Canonical deterministic coverage: offline + all DB-only live suites.
coverage-db: _coverage-offline
    scripts/run_live_suites.sh db cargo llvm-cov --no-report
    cargo llvm-cov report --summary-only

# Supplemental coverage including the mutable People Chain RPC suites. APNs / FCM
# smokes are never merged because they require operator credentials.
coverage-full: _coverage-offline
    scripts/run_live_suites.sh db cargo llvm-cov --no-report
    scripts/run_live_suites.sh chain cargo llvm-cov --no-report
    cargo llvm-cov report --summary-only

_coverage-offline:
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --workspace

# Dependency license/advisory audit (requires `cargo install cargo-deny`).
deny:
    cargo deny check

# Regenerate the committed edge config (the `(routes)` snippet in gateway/Caddyfile)
# from the ONE route table in crates/dub/src/routes/table.rs. The
# `committed_artifacts_are_in_sync` test in `just check` fails if it is stale, so
# run this after changing the table — and never hand-edit between the
# `generated:route-table` markers.
routes:
    cargo run -p routegen

# Regenerate the committed API reference (docs/api-reference/openapi.json + index.html)
# from the `#[utoipa::path]` annotations. The `committed_artifacts_are_in_sync` test
# in `just check` fails if these are stale, so run this after changing any route/DTO.
openapi:
    cargo run -p apidoc-gen

# Run the device-attestation-api service natively (needs Postgres reachable on localhost:
# `docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d postgres`).
run:
    cargo run -p dub -- --role device-attestation-api

# Run the device-attestation-chain-writer worker (drains the reservation outbox onto People
# Chain). Needs Postgres reachable on localhost — same prerequisite as `run`.
run-writer:
    cargo run -p dub -- --role device-attestation-chain-writer

# Run the notifications relay (stateless /api/v1/notify).
run-notify:
    cargo run -p dub -- --role notify-relay
