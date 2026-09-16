# AGENTS.md

Operating contract for coding agents in this repo. Keep this file lean and operational —
project narrative, architecture, and specs live in `docs/` and are linked below. Read the relevant
doc before non-trivial work.

## Orientation

Device Uniqueness Backend — a **Rust** backend that proves a device is a distinct physical device
and registers a username for it on Polkadot's People Chain, built as isolated services. It is a
reference implementation, not a hardened production build (see `README.md`). Context lives in docs,
not here:

- **Architecture, scope, service boundaries, naming, and data-flow invariants** → `docs/architecture.md`
- **Public API reference** → `docs/api-reference/`
- **Deploy / operations** → `docs/operations.md`

## Keeping docs current

The **code is the source of truth**; the docs must be kept in sync with it. When a change alters behavior, architecture, service boundaries, naming, or invariants, update the matching doc in the **same change**, not later:

- Architecture, scope, service boundaries, naming, or data-flow invariants → `docs/architecture.md`.
  It carries **no delivery status** (no "exists"/"pending"/"in flight", no dated demo notes) — it
  describes the system as designed, so only a design change touches it.
- Deploying it, running it, or diagnosing it → `docs/operations.md`.
- Commands, conventions, config, workspace layout, or gotchas → this file.
- **Public HTTP surface** (routes, request/response fields, status codes, examples) → the API reference is **generated from the code**, not hand-written. Annotate the handler with `#[utoipa::path(...)]` and its bodies with `#[derive(ToSchema)]`; register new handlers in the `paths(...)` list and new types in `components(schemas(...))` in `crates/<service>/src/openapi.rs`; then run `just openapi` and commit the regenerated `docs/api-reference/{openapi.json,index.html}` in the same change. Never hand-edit those two files (a test enforces this — see Gotchas). Edit the page **design** in `docs/api-reference/template.html` (the `<!--@NAV-->` / `<!--@ENDPOINTS-->` placeholders are filled by the generator).

If a change makes a doc wrong, fix the doc (or flag the drift) in the same change instead of leaving it stale.

## Workspace

Twelve crates today (plans may add more independently-deployable service crates):

- `dub` — **the single deployable binary**. Every service and worker is a *role* of this one
  process (`dub --role device-attestation-api`; `dub --list-roles` prints them — eight on a `testnet`
  build, six on `polkadot` — and `--list-merged-roles` the
  small topology's `all-in-one`). Process wiring only, no
  domain logic: each role module holds that service's former `main` body and enters the service
  crate through its library `routes()` / `run()`. Also serves `--healthcheck` (a GET on this
  container's own `/readyz`, so an image needs no `curl`). Adding a role means adding it to
  `ROLES` **and** to compose — `scripts/verify_role_split.sh` fails if those disagree. Also holds `src/routes.rs`, **the route table**: the ownership map that
  `gateway/Caddyfile` proxies, in Rust, which `--role all-in-one` serves so a consumer can run the
  whole API with no edge. `all-in-one` is accepted by `--role` but deliberately **absent from
  `--list-roles`** (it holds every secret in one process), so the gate rejects it in any manifest.
  **Two topologies**: standard (eight workloads, six on `polkadot`) and small (`all-in-one` + the
  three workers, two on `polkadot`). They
  are mutually exclusive and the compose file here runs the standard one —
  `docs/architecture.md` "Deployment topologies" has the threat model,
  `docs/operations.md` "Choosing a topology" the operator view.
- `chain-types` — generated People Chain type surface (subxt codegen), from the vendored
  `metadata/metadata.<network>.scale` that `DUB_NETWORK` selects. Its `build.rs` is **the** network
  switch: `invite-tickets`, `dub` and `apidoc-gen` name it as their own `build =` script, and it
  emits `cfg(dub_network = "…")` plus `cfg(invite_tickets)` (`testnet`, not `polkadot`). Two values,
  because two People runtimes — previewnet and paseo-next-v2 share one, so they share one build. Gate
  network-specific code on those cfgs; never read `DUB_NETWORK` at runtime.
- `chain-client` — reconnecting People Chain connection + the chain-writer signing key (`WriterSigner`); product-agnostic transport shared by the services.
- `jwt-verify` — the cross-service auth contract: JWKS parsing, Ed25519 signing and verification, claims. It holds **both** halves, but only `device-attestation` is given `JWT_ED25519_SECRET`, so it is the only process that can construct the issuer; every other service builds a verifier from public key material alone. (The crate name predates the issuer moving in.)
- `http-common` — shared axum primitives: the one JSON error envelope every service renders (`{error}`, plus a `fields` array of `{field, message}` on per-field validation failures), the JWT extractor, rate limiter, health, middleware stack, and fail-fast env helpers; consumed by invite-tickets. Also holds the two things **every** process installs: the metrics exporter (`metrics::spawn`) and the log subscriber (`telemetry::init`).
- `device-attestation` — the device attestation service (lib + the `voucher-mint` CLI; roles `device-attestation-api`, `device-attestation-chain-writer`, and the `registration-queue` advancer — with `QUEUE_ENABLED` on, its promotion is the only queue exit: down, claims park as `QUEUED` and the writer raises a stranded-queue warning).
- `username-indexer` — username indexer + search service.
- `invite-tickets` — synchronous invitation-credential claim service, the route the shipping apps call (lib; roles `invite-tickets-api` and `invite-tickets-pool`).
- `turn` — stateless TURN credential issuer (coturn REST-API HMAC construction over a relay-shared secret; lib; role `turn-api`). No DB; when proof issuance is enabled, each environment's process maintains a read-only root cache from its own People Chain.
- `notifications` — thin `/api/v1/notify` relay (verify-only Ed25519 JWT, stateless, DB-free, per-subject rate limited; role `notify-relay`) with optional iOS APNs + Android FCM providers.
- `apidoc-gen` — dev-only tool (not deployed) that renders the committed API reference from the service crates' `#[utoipa::path]` annotations. Run via `just openapi`.
- `routegen` — dev-only tool (not deployed) that renders the committed edge config from `dub`'s route table. Run via `just routes`.

Each service's boundary, persistence, endpoints, and data-flow invariants are in `docs/architecture.md`.

## Commands

- `just check` — the fast offline gate: fmt `--check` + `clippy -D warnings` + `cargo test --workspace`.
  It checks **one** network build (`DUB_NETWORK`, default `testnet`). CI runs it for both, so
  run `DUB_NETWORK=polkadot just check` too when touching anything invite-tickets or
  chain-types.
- `just test-live-db` (also `just test-live`) — the deterministic Postgres gate: 12 suites / 30 ignored tests against a per-run isolated Compose project. CI runs it after `just check`; run both before declaring done.
- `just test-live-chain` — optional Postgres + live People Chain suites; external RPC availability keeps it outside the merge/release gate.
- `just test-live-providers` — optional credentialed APNs/FCM smokes; runs only the providers configured in the environment and fails if neither is configured.
- `just coverage-db` — canonical deterministic coverage (offline + Postgres). `just coverage-full` additionally merges the optional live-chain suites.
- `just run` / `just run-writer` / `just run-notify` — run a role locally (`cargo run -p dub -- --role <name>`).
- Single test: `cargo test -p device-attestation <name>` (or `-p chain-types`, `-p username-indexer`).
- `just deny` — `cargo-deny` audit; **not** in `just check`, needs `cargo install cargo-deny`.
- `just routes` — regenerate the committed edge config (the `(routes)` snippet in `gateway/Caddyfile`) from `crates/dub/src/routes/table.rs`. The same table also emits Traefik rules via `table::chart_routes()` for anyone fronting the services with Traefik; that one is not a committed artifact.
- `just openapi` — regenerate the committed API reference (`docs/api-reference/openapi.json` + `index.html`) from the `#[utoipa::path]` annotations. Run after any change to a route, request/response type, status code, or example.
- Images: **ONE image, `$IMAGE_REPO:$IMAGE_TAG`** (`docker-bake.hcl`, one target).
  `docker buildx bake all` builds it from one `cargo build -p dub`. What makes a container a given
  service is its role — compose `command: ["--role", "<svc>"]` — never a different image. The image
  carries `ENTRYPOINT ["dub"]` and **no `CMD`**, so an argument-less container fails loudly instead
  of defaulting into somebody's service.
  `scripts/verify_role_split.sh` (in `check.yml`) fails if a compose service names a role
  `dub --list-roles` does not accept, if a role is claimed by more than one or by none, if a
  service name and its role disagree, if the services drift onto different image references, or if a
  `CMD` reappears in the Dockerfile.
- Config gates, both in `check.yml` and reachable as `just verify-config`:
  `verify_compose_boundaries.sh` (compose secret allowlists) and `verify_role_split.sh` (one image,
  every service's `--role`, plus the release exporter shape).
- Releasing: bump `[workspace.package] version` in `Cargo.toml`, add the matching `## [X.Y.Z]`
  section to `CHANGELOG.md`, merge, tag `vX.Y.Z`, then dispatch `release.yml` manually. The workflow
  refuses a tag that disagrees with either the manifest or the changelog.
  **Record the runtime versions in that changelog section** — one row per network
  (`testnet` → `next-people-paseo`, `polkadot` → `people-polkadot`, with each blob's
  `spec_version`) — because a release ships a build per network and the notes are generated from
  that section, so this is the only place they are written. The current values are the
  `KNOWN_RUNTIMES` / `VENDORED_VERSION` entries in `crates/chain-types/src/lib.rs`, which move when
  a metadata blob is refreshed.
- Local stack: `docker network create dub-edge` once, then `docker compose up`
  (Postgres + `device-attestation-api` + `device-attestation-chain-writer` + `username-indexer` + its own Postgres).
  All env vars in `.env.example`. Nothing publishes a host port: add
  `-f docker-compose.yml -f docker-compose.debug.yml` to republish them on `127.0.0.1`.
- Edge: its own project, so environment restarts never touch it. Locally:
  `GATEWAY_ADDRESS=http://localhost EDGE_HTTP_PORT=8000 EDGE_HTTPS_PORT=8443 docker compose -f gateway/docker-compose.yml -p edge up -d`,
  then curl `127.0.0.1:8000` with a `Host:` header.
- Metrics and logs: their own compose project. `docker network create dub-metrics` once, then
  `docker compose -f observability/docker-compose.yml -p observability up -d`
  (Prometheus + Loki + Alloy + Grafana). **Grafana on `127.0.0.1:3000` is the
  entry point** (dashboard `dub-overview`, anonymous read-only); Prometheus UI
  on `127.0.0.1:9091`, Alloy's on `127.0.0.1:12345`. Every process exports
  metrics on 9090 over that network only; scrape targets live in
  `observability/prometheus.yml`. Logs need no per-service wiring: Alloy
  discovers containers through a read-only Docker socket and labels them from
  Docker metadata, so a service only has to emit `LOG_FORMAT=json`.

## Conventions (beyond rustfmt/clippy defaults)

- Workspace lints: `unsafe_code = "forbid"`, clippy `uninlined_format_args = warn` → inline format args (`"{v:?}"`, not `"{}", v`).
- **Errors:** domain enums via `thiserror` (`ConfigError`, `JwtError`, `InsertError`, …); HTTP maps through `http::error::AppError` (`impl IntoResponse`). `anyhow` only in the bin `main`s, never in library public APIs.
- **sqlx is runtime-checked** — queries use `sqlx::query(...)` with bound `$n` params; there are **no** `query!`/`query_as!` macros and **no `.sqlx` cache**. Do not add compile-time SQL macros or `cargo sqlx prepare`; deterministic runtime database suites run separately in CI.
- **Migrations auto-run** via `sqlx::migrate!("./migrations")` in `db::connect` on every boot (advisory-locked, safe across replicas). Don't run them by hand; add schema as new `crates/<service>/migrations/*.sql`.
- **Config is fail-fast** (`Config::from_env`): required vars (e.g. `DEVICE_ATTESTATION_DATABASE_URL`, `JWT_ED25519_SECRET`, `ATTESTER_ACCOUNT`) have no defaults and abort startup if missing/malformed. Don't add fallbacks for them.
- **Per-service config keys are namespaced.** The database URLs are `DEVICE_ATTESTATION_` / `INDEXER_` / `INVITE_TICKETS_DATABASE_URL` and the rate limits `INVITE_TICKETS_` / `TURN_RATE_LIMIT[_WINDOW_SECS]` — a bare `DATABASE_URL` used to name several different Postgres instances, so `all-in-one` would have wired services to each other's databases. The names these keys used to have — the bare `DATABASE_URL` / `RATE_LIMIT[_WINDOW_SECS]`, and `IDENTITY_DATABASE_URL` for the service that used to be `identity-service` — were read for one release with a deprecation `WARN` and are no longer read at all: an environment setting only an old name fails fast at boot. `verify_compose_boundaries.sh` asserts each credential reaches only its own services and that nothing is left on a bare name. `BIND_ADDR` and `PEOPLE_RPC_URL` stay shared — one listener, one chain.
- Module layout: `foo.rs` + optional `foo/` children (no new `foo/mod.rs`); short `lib.rs` (docs + lints + `pub mod` + curated re-exports); doc every `pub` item.
- **Every role starts the same two lines**: `http_common::telemetry::init("<service>")` then `http_common::metrics::spawn("<service>")`, as the first two lines of its `run()`, with its OWN service name — both are process-global and `metrics::spawn` sets `service` as a global label, so hoisting either into `main` would relabel every scrape target. Don't build a subscriber in a role. Logs are aggregated, so prefer structured fields (`tracing::warn!(reservation_id, %error, "…")`) over interpolated message text — the field is queryable, the sentence is not. Don't add the service/environment name as a field: the log shipper labels those.

## Configuration

All vars + dev defaults are in `.env.example` (compose auto-loads `.env`).
Non-obvious: `AUTH_ENABLED=false` is the current **M0 mode** — platform attestation is a **no-op**
(a JWT is still issued and the sr25519 account proof still verified); `ENFORCE_AUTH` toggles soft
(log-only) vs hard rejection. `LOG_FORMAT` defaults to `text` in the binaries and `json` in
compose — containers ship to Loki, `just run` is read by a human.

## Gotchas / forbidden

- **Don't run migrations manually** — auto-applied on boot.
- **Don't scale `device-attestation-chain-writer`** past one instance (nonce lane). `registration-queue` is also single-instance (its lease guards promotion order and doubles as the queue's liveness signal).
- **Don't add `.sqlx` / `query!` compile-time SQL** — runtime-checked by design.
- **Don't hand-edit `docs/api-reference/openapi.json` or `index.html`** — both are generated by `just openapi`; the `apidoc-gen` `committed_artifacts_are_in_sync` test (part of `just check`) fails if they're stale. Change the annotations (content) or `template.html` (design), then regenerate.
- **Don't hand-edit the route table between the `generated:route-table` markers** in `gateway/Caddyfile`. That region is rendered by `just routes` from the ONE table in `crates/dub/src/routes/table.rs`, which is also what `--role all-in-one` serves; `routegen`'s `committed_artifacts_are_in_sync` test (part of `just check`) fails if it is stale. Change the table, run `just routes`, and commit both together.
- **Run `just check` and `just test-live-db` before declaring done** — CI runs both on push/PR. `cargo-deny` is separate (`just deny`).
- **Don't add `ports:` to `docker-compose.yml`** — the edge container is the only thing that
  publishes on the host (enforced by `scripts/verify_compose_boundaries.sh`). Local port access
  goes in `docker-compose.debug.yml`, loopback-only.
- **Don't widen the observability project's ports past `127.0.0.1`, and don't edit the Grafana
  dashboard in the UI** — Grafana/Prometheus/Alloy are tunnel-only (same script enforces it), and
  the dashboard is provisioned read-only from
  `observability/grafana/dashboards/dub-overview.json`. Change the file, restart Grafana.
- **Don't push, tag, or cut a release without explicit consent.** Operations live in `docs/operations.md`; releasing is a manual `workflow_dispatch`.
- **`device-attestation-api` blocks on the People Chain RPC at startup** — no reachable RPC, no boot.
