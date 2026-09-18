# Device Uniqueness Backend

> [!WARNING]
> The following is a proof-of-concept. This open source code is provided for
> research, experimentation, and developer education only. This code has not been
> audited, is actively experimental, and may contain bugs, vulnerabilities, or
> incomplete features. Use at your own risk.

Parity doesn’t deploy the code but may update it based on community feedback.

If you experience problems with any product or service that was built on or
deployed from this code, you should contact the third party who deployed the code
in its amended form, not Parity.

A Rust backend that proves a device is a distinct physical device, and registers
a username for it on Polkadot's People Chain — plus the sibling services a
consumer app tends to need around that. It is a **reference blueprint**: fork it,
point it at whichever network you want, deploy it under whatever name you want.

## What it does

Eight services on a `testnet` build (six on `polkadot`, which has no
invite-tickets — see [Choosing a network](docs/operations.md#choosing-a-network)),
each of which owns its Postgres database where it has one, and
each of which deploys independently behind a single-URL
[gateway](gateway/Caddyfile):

- **`device-attestation-api`** — the auth handshake (challenge → hardware
  attestation → JWT + refresh), username registration gated on device uniqueness
  (`POST /api/v1/usernames`, availability, queue status), the
  attester key, JWKS, health. Verifies Apple App Attest and Android Play
  Integrity / key attestation.
- **`device-attestation-chain-writer`** — a single-instance worker that drains
  the reservation outbox onto the chain.
- **`registration-queue`** — a single-instance queue advancer; while
  `QUEUE_ENABLED` is on, it is the only path out of the registration queue.
- **`username-indexer`** — a username projection with public prefix search,
  plus an optional proof-of-compute gate on that search. Finalized state is
  authoritative; the unfinalized window is indexed speculatively on top of it so
  a new registration is searchable a finality trail sooner.
- **`invite-tickets-api`** / **`invite-tickets-pool`** — synchronous
  invitation-ticket claim, and the keypair pool that keeps it stocked.
- **`turn-api`** — a stateless TURN credential issuer (coturn REST API).
- **`notify-relay`** — a stateless APNs / FCM push relay.

Plus **`voucher-mint`**, an operator CLI for minting registration vouchers
(deliberately not an HTTP surface).

Registration can additionally claim a **dotNS** label on Asset Hub, as a second
independent state machine alongside the People Chain registration.

## What it does not do

- **It is not audited, and it is not a hardened production build.** See
  [Security](#security).
- **It does not run a chain.** It is a client of one, and it needs an attester
  account on that chain with an allowance and a funded signing proxy —
  prerequisites it cannot create for itself.
- **It does not issue personhood.** Device uniqueness is not proof of a person;
  it is one signal among several.
- **It does not ship a Kubernetes chart or any deployment automation.** Docker
  Compose is the configuration contract; port it wherever you like.

## One binary, every role

Every service and worker is a `--role` of the single `dub` binary. What makes a
container a given service is its role, not a different image:

```
dub --list-roles                       # eight on testnet, six on polkadot
dub --role device-attestation-api
dub --help                             # which network this binary was built for
```

## Quickstart

You need Docker with Buildx, and about ten minutes for the first compile.

```bash
git clone https://github.com/paritytech/device-uniqueness-backend-community.git
cd device-uniqueness-backend-community
cp .env.example .env

docker network create dub-edge dub-metrics   # once per host

# bake reads the shell, NOT .env: export this or you get a testnet image.
export DUB_NETWORK=testnet                   # or polkadot
docker buildx bake all                       # one cargo build, one image
docker compose up -d                         # nothing is published — the edge does that
```

Nothing binds a host port by default. To reach a service directly, layer the
loopback-only debug overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d
#   device-attestation 127.0.0.1:8080 · indexer :8081
#   turn :8084 · notify :8085 · invite-tickets :8083 (testnet builds only)

curl -fsS http://127.0.0.1:8080/readyz
```

Or run a single role natively: `just run` / `just run-writer` / `just run-notify`,
with environment from `.env.example`.

### The network you are starting from

Out of the box `.env.example` points at **PreviewNet**
(`wss://previewnet.substrate.dev`), a public test network that is wiped and
re-spawned routinely, and uses the well-known development keys `//Alice` and
`//Bob`. That is enough for the stack to start and for the read paths to work.

For anything past that you need, on whichever network you target:

- an **attester account** with an attestation allowance,
- a **funded signing key** authorized as that account's `Any`/delay-0 proxy,
- for invites, an inviter account holding `AvailableInvites` quota.

The binary is **built for one People runtime**: `DUB_NETWORK` is `testnet` (the
default — previewnet and paseo-next-v2) or `polkadot` (polkadot-test). It picks
the vendored People metadata and, on `polkadot` — whose runtime has no `Game` /
`ProofOfInk` — leaves the invite-tickets services out. Set it in `.env` before
building, together with `COMPOSE_PROFILES` and the RPC endpoints; see
[Choosing a network](docs/operations.md#choosing-a-network).

Paseo's People Chain is
`wss://paseo-people-next-system-rpc.polkadot.io` — point `ASSET_HUB_RPC_URL` at
an Asset Hub on the same network running the `signed_at` `reserve_name`. The
dotNS lane is not optional; where the shape does not match, the writer parks the
lane rather than submitting.

[docs/operations.md](docs/operations.md) covers this from zero, including the
secret boundaries the compose file enforces and why they are worth keeping.

## Documentation

| | |
| --- | --- |
| Design, scope, service boundaries, data-flow invariants | [docs/architecture.md](docs/architecture.md) |
| Standing it up and running it | [docs/operations.md](docs/operations.md) |
| HTTP API reference (generated from the code) | [docs/api-reference/](docs/api-reference/) |
| Working notes: crate layout, conventions, gotchas | [AGENTS.md](AGENTS.md) |
| How to contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |

A live reference deployment of this code runs at
<https://identity.dotspark.app> ([API reference](https://identity.dotspark.app/docs)).
It exists so the API is explorable without deploying anything. It is a test
deployment operated by Parity on a test network — do not build against it, and do
not expect it to be there.

## Develop

```bash
just check                 # fmt + clippy + workspace tests + the config gates
just test-live-db          # deterministic Postgres suites; also required by CI
just test-live-chain       # optional Postgres + live People Chain smokes
just test-live-providers    # optional credentialed APNs / FCM smokes
just coverage-db           # canonical offline + Postgres coverage report
just deny                  # dependency licence and advisory audit
just openapi               # regenerate docs/api-reference after route/DTO changes
just routes                # regenerate the gateway route table
```

`just openapi` and `just routes` produce **committed generated artifacts** — a
test in `just check` fails if either is stale. Never hand-edit them.

## Releases

**This repository publishes binaries.** Releases are cut manually from a
`vX.Y.Z` tag via the [release workflow](.github/workflows/release.yml). Each one
attaches:

Every asset is built twice, once per People runtime — `testnet` (previewnet and
paseo-next-v2) and `polkadot` (polkadot-test) — because `DUB_NETWORK` is fixed
when the binary is built. Take the pair matching the chain you point at;
`dub --help` prints the network a binary was built for.

- `dub-<version>-<network>-<target>.tar.gz` — the single `dub` binary for
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` and
  `aarch64-apple-darwin`;
- `dub-compose-<version>-<network>.tar.gz` — `docker-compose.yml`,
  `.env.example` (already naming that network) and the gateway config, so the
  stack stands up on a host with no source tree;
- `SHA256SUMS`, covering every asset above.

**Verifying a tagged build.** Download `SHA256SUMS` alongside the assets and run
`sha256sum -c SHA256SUMS`. To satisfy yourself the binaries are this source,
build them yourself: `docker buildx bake all` compiles the very same
`Dockerfile` stage the release exports from.

### About the container image

There is a public image at `docker.io/paritytech/device-uniqueness-backend`, but
it is **not published from this repository** — Parity builds and pushes it from
its own working tree, and **its tags do not line up with this repository's
tags**. At the time of first publish it carries `v0.3.0`, built from source
older than this release. Treat it as a convenience, not as the artifact
corresponding to a tag here.

Because of that, the compose bundle does not blindly pin to it. The release
workflow checks whether an image exists at `<tag>-<network>` and is anonymously
pullable — one image per network, since an image carries a binary built for one
runtime; if it is, that network's bundle pins to it, and if it is not, the
bundle keeps its `build:` stanzas and the release notes say so. Either way the
bundle works — the second case just needs a source checkout beside it:

```bash
tar xzf dub-compose-<version>-<network>.tar.gz && cp .env.example .env
docker network create dub-edge dub-metrics

# only if the bundle was not pinned to an image. bake reads the shell, not
# .env, so name the same network the bundle is for:
export DUB_NETWORK=<network>
docker buildx bake all
docker compose up -d
```

Changes per release: [CHANGELOG.md](CHANGELOG.md). **Pre-1.0, breaking changes
bump the minor** — `0.4.x` → `0.5.0` can break you.

## Security

Before deploying it for real use cases, you are responsible for:

- Reviewing the code yourself — we publish a reference, not a hardened
  production build
- Checking that the dependencies are up to date and free of known
  vulnerabilities
- Securing your own fork or deployment environment (keys, secrets, network
  configuration)
- Tracking the latest tagged release and commits for security fixes; older
  releases are not backported (exceptions might apply)

This code has **not been audited**. The defaults in `.env.example` are
development defaults — well-known dev keys, a public test network, permissive
toggles — and every one of them must be replaced before a deployment anyone else
can reach.

For Parity's security disclosure process and Bug Bounty program:
<https://parity.io/bug-bounty>. Please do not report suspected vulnerabilities
through public GitHub issues.

## Licence

[GPL-3.0-only](LICENSE). Copyright (C) 2026 Parity Technologies (UK) Ltd.

Third-party dependencies and the licences they declare are inventoried in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); `cargo deny check licenses`
gates that set in CI.
