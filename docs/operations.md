# Operations

Standing this backend up on a server, and running it once it is up. For what the
system *is* and why it is shaped this way, read
[architecture.md](architecture.md) first.

Everything here is Docker Compose. There is no orchestrator-specific tooling in
this repository — if you deploy to Kubernetes or anything else, the compose file
is the configuration contract to port: the same image, the same `--role`
arguments (`dub --list-roles` prints them), the same environment allowlists.

**Two compose projects share a host.** The services live in an *environment*
project started from [`docker-compose.yml`](../docker-compose.yml); the public
edge is a separate project started from
[`gateway/docker-compose.yml`](../gateway/docker-compose.yml). They meet on a
shared external Docker network, `dub-edge`, that neither owns, where each
environment registers its services under `ENV_ID`-suffixed aliases
(`device-attestation-api-paseo-next-v2`, …). The edge resolves those aliases by
Docker DNS and is **the only container that publishes a host port** (80/443).
Nothing else is reachable from outside the machine, and a second environment on
the same host collides with nothing.

**Every command below needs its project**, or it acts on the wrong stack — or on
none.

---

## Before you start

- A Linux server with sudo and outbound internet — the services dial a People
  Chain RPC at startup and will not become ready without one.
- A DNS A record pointing your domain at the server, direct rather than proxied.
- Ports 80/443 open.
- **An attester account on the People Chain**, with an attestation allowance, and
  a funded signing key authorized as that account's `Any`/delay-0 proxy. This is
  the one prerequisite the software cannot create for you; see
  [Chain prerequisites](#chain-prerequisites).

### Secret boundaries

Worth understanding before you write a `.env`, because the compose file enforces
it and a "simplification" here is a real downgrade:

- The JWT **signing** seed lives only in `device-attestation-api`. `turn-api`,
  `notify-relay`, `username-indexer` (for the proof-of-compute bypass) and
  `invite-tickets-api` where it runs get the **public** key (or JWKS) only.
- Each chain-submitting worker holds only its own signing secret: the invite
  inviter SURI lives only in `invite-tickets-pool`.

> The `invite-tickets` services exist only on a `testnet` build — see
> [Choosing a network](#choosing-a-network). On `polkadot`, ignore every mention
> of them here; that image has no such roles.
- `turn-api` additionally holds `TURN_SECRET`, the HMAC key shared with the TURN
  relay (coturn `--use-auth-secret`). Relay and issuer rotate together, and no
  other service sees it.
- Push credentials (`APNS_*` / `FCM_*`) live only in `notify-relay`.

Compose uses the root `.env` for interpolation only, and gives every application
container an explicit environment allowlist, so no service can read another's
key. `scripts/verify_compose_boundaries.sh` asserts this, and runs in CI.

### Nonce lanes

`device-attestation-chain-writer` submits as the attester authority, and on a
`testnet` build `invite-tickets-pool` also submits, as "an inviter". **No two
submitters may sign as the same account** — two independent submitters on one
account race nonces. Give each its own account; separate proxy delegates of one
cold primary works well. (On `polkadot` there is one submitter, so this is one
account.)

---

## 1. Install Docker and create the shared networks

Caddy is not installed on the host — it runs as the edge container.

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 ca-certificates curl gnupg
sudo systemctl enable --now docker

# Owned by no project: both the environment and the edge attach to it.
sudo docker network create dub-edge

# Same idea for metrics: the environment and the observability project meet
# here, and nothing else does (Prometheus is never reachable from the edge).
sudo docker network create dub-metrics
```

## 2. Code and config

```bash
git clone https://github.com/paritytech/device-uniqueness-backend-community.git ~/dub
cd ~/dub
```

`ENV_ID` names this environment and is what the network aliases are suffixed
with. It defaults to `paseo-next-v2`; a second environment on the same host sets
its own. It is unrelated to `PEOPLE_NETWORK`, which is the wire literal the
clients parse.

Copy the template and edit it — `.env.example` documents every variable, its
default, and what breaks if it is wrong:

```bash
cp .env.example .env && chmod 600 .env
```

The values you must decide, at minimum:

| Variable | What it is |
| --- | --- |
| `DUB_NETWORK` | Which People runtime this build targets — `testnet` or `polkadot`. **Read when the image is built, not when it runs**; see [Choosing a network](#choosing-a-network) directly below. |
| `COMPOSE_PROFILES` | `invite-tickets` on `testnet`; **empty** on `polkadot`, whose image has no such roles. |
| `ENV_ID` | This environment's name; suffixes every network alias. |
| `PEOPLE_RPC_URL` | People Chain RPC. Must be a **full** node serving the legacy `state_queryStorageAt` — see the availability failure mode below. |
| `ASSET_HUB_RPC_URL` | Asset Hub RPC. **Required.** Same `state_queryStorageAt` requirement. **Must name the same network as `PEOPLE_RPC_URL`** — a split pair claims labels on the wrong chain, unrecoverably. |
| `ATTESTER_ACCOUNT` | The on-chain attester authority (SS58). |
| `CHAIN_WRITER_SIGNER_SURI` | The writer's signing key; must be an authorized attester or its proxy, and funded. |
| `JWT_ED25519_SECRET` | 32 bytes. `device-attestation-api` only. |
| `JWT_ED25519_PUBLIC_KEY` or `JWT_JWKS_JSON` | The verify-only half, for the other services. |
| `INVITE_INVITER_SIGNER_SURI` | `testnet` only: the invite pool's own account — **not** the writer's. Unused on `polkadot`. |
| `TURN_SECRET` | Shared with your coturn relay; must match it exactly. |

The defaults in `.env.example` point at a public test network
(`wss://previewnet.substrate.dev`) and use well-known dev keys (`//Alice`,
`//Bob`). They exist so `docker compose up` works on a laptop. **Replace every
one of them before a deployment anyone else can reach.**

### Choosing a network

**Decide this before you build.** One source tree builds for two People
runtimes, selected by `DUB_NETWORK`. It is a *build* input, not runtime
configuration: an image or binary is built for one runtime and stays that
runtime, and changing it means rebuilding.

| `DUB_NETWORK` | People runtime | Deployments | Vendored metadata | invite-tickets |
| --- | --- | --- | --- | --- |
| `testnet` (default) | `next-people-paseo` | previewnet, paseo-next-v2 | `metadata.testnet.scale` | yes |
| `polkadot` | `people-polkadot` | polkadot-test | `metadata.polkadot.scale` | no — the runtime has no `Game` / `ProofOfInk` |

previewnet and paseo-next-v2 are **one** build: same runtime, same metadata.
What separates them is `ENV_ID` and their endpoints. Split the flag again only
if their runtimes diverge.

- **Build — the one trap worth reading twice.** `docker compose build` reads
  `DUB_NETWORK` from `.env` and is correct with nothing else set. **`docker
  buildx bake` does not read `.env`**: it takes the shell environment and
  otherwise falls back to `testnet`, so building with bake after editing only
  `.env` gives you a `testnet` image whatever the file says. Export it, and keep
  it across `sudo`:

  ```bash
  export DUB_NETWORK=polkadot          # or testnet
  sudo -E docker buildx bake all       # -E preserves the variable
  ```

  Tag images for different networks differently — the default tag is `local` for
  both. `dub --help` prints the network a binary was built for, which is how you
  check an image you did not build yourself.
- **Run**: keep `COMPOSE_PROFILES=invite-tickets` on `testnet` to start the
  three invite-tickets services. Leave it empty on `polkadot`: that image
  rejects both roles, and those containers would crash-loop.
- **Endpoints go with the network.** `PEOPLE_RPC_URL` / `ASSET_HUB_RPC_URL` must
  name the same network the image was built for; `.env.example` lists each
  network's pair. A mismatch shows up at boot as `live runtime and the vendored
  metadata disagree`, with `network` and `vendored_metadata` fields.
- **Edge**: the route table is the same everywhere. An environment with no
  `invite-tickets-api` points `INVITE_TICKETS_UPSTREAM` at its own
  `device-attestation-api`, so the claim path answers a JSON 404 instead of a 502.
- **Building from source yourself**: `DUB_NETWORK=<network> just check` gates
  that network's build, and CI runs the offline gate once per network. `just
  openapi` needs a `testnet` build, because the committed API reference
  documents every surface.

## 3. Run

```bash
# the service image — one cargo build, one runtime stage (several minutes the
# first time). `bake` is the only builder: compose's `build.target` keys exist
# so `docker compose build` works too, but bake shares the compile.
#
# bake does NOT read .env, so the network comes from the shell here — without
# these two lines you get a testnet image whatever .env says. See
# "Choosing a network" above.
export DUB_NETWORK=testnet           # or polkadot; must match .env
sudo -E docker buildx bake all

# the environment (migrations run on boot, advisory-locked)
sudo docker compose up -d --no-build

# the public edge — acquires its certificate on first start
sudo docker compose -f gateway/docker-compose.yml -p edge up -d

# monitoring — its own project, so an environment restart never stops it
sudo docker compose -f observability/docker-compose.yml -p observability up -d
```

To run a tagged release instead of building, use that release's compose bundle
for your network (`dub-compose-<version>-<network>.tar.gz`, one per People
runtime) rather than pinning the image by hand. Its bundled `.env.example`
already carries the right `DUB_NETWORK` and `COMPOSE_PROFILES`. The release
workflow pins the bundle to `<repo>:<tag>-<network>` only when an image is
anonymously pullable at that tag; when none is, it ships the compose file
with its `build:` stanzas, and the release notes say so — that case needs a
source checkout beside the bundle.

Do **not** point `IMAGE_REPO` / `IMAGE_TAG` at
`docker.io/paritytech/device-uniqueness-backend` yourself. That image is not
published from this repository and its tags do not correspond to this
repository's tags — see "About the container image" in the
[README](../README.md).

Recreate the **whole project**, never a single service — `up -d <service>` on its
own leaves the rest on the previous image, and a stack split across two builds
fails in ways neither build does (an old writer reading config the new compose no
longer passes).

Migrations run automatically on boot. Never run them by hand.

## Running the released binaries, without Docker

Everything above is Compose. The release also publishes the bare `dub` binary,
and systemd is a fine way to run it — but Compose was doing three things for you
that now become your job: it supplied Postgres, it gave every role its own
network namespace, and it handed each process only the variables that role is
allowed to see. Re-read [Secret boundaries](#secret-boundaries) first: **nothing
below enforces them**, so a flat environment shared by every unit puts
`JWT_ED25519_SECRET` in the same process as public search.

**1. Take the tarball for your network.** Assets are
`dub-<version>-<network>-<target>.tar.gz` — the network is in the name because
the two binaries differ (see [Choosing a network](#choosing-a-network)).

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar xzf dub-<version>-testnet-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  dub-<version>-testnet-x86_64-unknown-linux-gnu/dub /usr/local/bin/dub

dub --help          # the network this binary was built for — check it matches your RPC
dub --list-roles    # eight roles on testnet, six on polkadot
```

**2. Provide Postgres yourself.** Each database belongs to one service: create
the roles and databases named in the `*_DATABASE_URL` defaults in
`.env.example` — `device_attestation` and `username_indexer`, plus
`invite_tickets` on a `testnet` build. Migrations still run automatically on
first boot, advisory-locked; never run them by hand.

**3. Load the environment — `dub` does not read `.env`.** This is the one that
bites: Compose reads that file, the binary does not. It reads real environment
variables only, and a required one that is missing aborts startup. So either
source it into the shell, or let systemd do it:

```bash
sudo install -d -m 0750 /etc/dub
sudo install -m 0640 .env.example /etc/dub/env    # then edit it as step 2 describes
```

**4. Give every role its own ports.** Under Compose each container had its own
namespace, so all of them could use `0.0.0.0:8080` and `0.0.0.0:9090`. On one
host the second process to start simply fails to bind. Assign a pair per role —
this scheme matches the debug overlay, so the doc's other `curl` examples still
apply:

| Role | `BIND_ADDR` | `METRICS_ADDR` |
| --- | --- | --- |
| `device-attestation-api` | `127.0.0.1:8080` | `127.0.0.1:9090` |
| `username-indexer` | `127.0.0.1:8081` | `127.0.0.1:9091` |
| `invite-tickets-api` (`testnet`) | `127.0.0.1:8083` | `127.0.0.1:9093` |
| `turn-api` | `127.0.0.1:8084` | `127.0.0.1:9094` |
| `notify-relay` | `127.0.0.1:8085` | `127.0.0.1:9095` |
| `device-attestation-chain-writer` | — (no HTTP) | `127.0.0.1:9096` |
| `registration-queue` | — | `127.0.0.1:9097` |
| `invite-tickets-pool` (`testnet`) | — | `127.0.0.1:9098` |

Bind to loopback and let a reverse proxy publish, exactly as the Compose
deployment does — nothing but the edge should hold a public port.

**5. One unit per role.** A single template unit takes the role as its instance
name, so adding a role is `systemctl enable dub@<role>`:

```ini
# /etc/systemd/system/dub@.service
[Unit]
Description=Device Uniqueness Backend — %i
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/dub --role %i
EnvironmentFile=/etc/dub/env
EnvironmentFile=-/etc/dub/%i.env      # per-role overrides: ports, and the
                                      # secrets only this role may see
User=dub
Restart=always
RestartSec=5s
# LOG_FORMAT defaults to text in the binary; set json here if you ship logs.
Environment=LOG_FORMAT=json

[Install]
WantedBy=multi-user.target
```

The per-role file is where the secret boundaries are rebuilt by hand: keep
`JWT_ED25519_SECRET` in `device-attestation-api.env` and nowhere else, the
writer's SURI in `device-attestation-chain-writer.env`, `TURN_SECRET` in
`turn-api.env`, and give every other role the verify-only
`JWT_ED25519_PUBLIC_KEY` instead. The `environment:` block of each service in
[`docker-compose.yml`](../docker-compose.yml) is the authoritative list of what
that role should receive.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dub@device-attestation-api dub@username-indexer \
  dub@turn-api dub@notify-relay \
  dub@device-attestation-chain-writer dub@registration-queue
```

**The singleton rules still apply, and nothing enforces them here.** Exactly one
`device-attestation-chain-writer` and one `registration-queue` across the whole
deployment (one `invite-tickets-pool` too, on `testnet`) — the Postgres lease is
a deploy-overlap guard, not a licence to run two.

**6. Front it yourself.** No edge comes with the binaries. Run Caddy against the
committed [`gateway/Caddyfile`](../gateway/Caddyfile) — the route table is
generated and stays correct — or map the same ownership into whatever proxy you
already run. `https://<domain>/docs` is served from `docs/api-reference/` in a
checkout; without one, drop that route or serve the directory from the release.

Health probes work the same as in a container: `dub --healthcheck` GETs this
process's own `/readyz` on its `BIND_ADDR` port, and `--url` points it anywhere.

```bash
dub --healthcheck --url http://127.0.0.1:8081/readyz
```

## 4. Verify

```bash
curl -fsS https://<domain>/readyz                                    # {"chain":"up","db":"up",…}
curl -fsS https://<domain>/api/v1/attester
curl -fsS 'https://<domain>/api/v1/usernames/search?prefix=alice'    # routed to the indexer
curl -fsS https://<domain>/docs/ -o /dev/null                        # the API reference
sudo docker compose logs device-attestation-chain-writer | tail -5
#   healthy startup: "connected signer=0x…" then "acquired writer lease"
```

Confirm the host exposes nothing else:

```bash
sudo docker ps --format '{{.Names}}\t{{.Ports}}'   # only the edge maps 80/443
ss -ltn                                            # no 8080–8085, no 5432–5435
```

Per-service `/readyz` needs the debug overlay, which republishes the ports on
loopback only. Layer it on, poke, then drop back:

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d
curl -fsS http://127.0.0.1:8081/readyz     # index freshness + Postgres + People Chain RPC
sudo docker compose up -d --remove-orphans   # back to no published ports
```

Failure isolation is worth checking once: stop `notify-relay` and confirm auth,
registration and search stay healthy, then bring it back.

## Chain prerequisites

The backend registers usernames on someone else's chain, so several things must
be true on-chain before it can do anything. After a chain wipe or a fresh
network, re-check all of them:

- `ATTESTER_ACCOUNT` is a recognised attester authority.
- The writer's signing key is an `Any`/delay-0 **proxy** of that account.
- The authority holds an **attestation allowance** (`dub_attester_allowance`).
- The writer's signing account is **funded** on both chains it submits to
  (`dub_account_free_balance_planck{role="signer",chain=…}`).
- **`testnet` builds only:** the invite inviter account holds `AvailableInvites`
  quota, or claims return `422 Pool exhausted`.

None of these are things the software can provision. On a permissioned test
network they are an ask of whoever operates it.

## Choosing a topology

The backend deploys in one of two shapes. They serve an **identical** public API;
they differ in how many processes hold how many secrets. The reasoning and the
full threat model are in
[architecture.md](architecture.md#deployment-topologies) — read that before
choosing, not after.

| | standard | small |
|---|---|---|
| workloads | 8, or 6 on `polkadot` | 4, or 3 on `polkadot` |
| HTTP tier | one service per surface | one `all-in-one` process |
| workers | three singletons (two on `polkadot`) | the same ones |
| `JWT_ED25519_SECRET` reaches | `device-attestation-api` only | the process that also serves public search |
| `/readyz` on a dead dependency | that service leaves rotation | reports `degraded`, stays in rotation |

**The standard topology is the default**, and it is what the compose file here
runs. Choosing the small one is a security decision, not a configuration change:
one process ends up holding `JWT_ED25519_SECRET` (mint a token for any subject),
`POC_HMAC_SECRET`, `TURN_SECRET` and all three database URLs, in the same address
space that serves the unauthenticated public
`GET /api/v1/usernames/search`. `all-in-one` is deliberately absent from
`dub --list-roles` for that reason.

Moving between them is a **full redeploy, not a scale operation** — different
workloads, different secret distribution, a different ingress target. The
databases and chain accounts are unchanged; both shapes run the same code.

---

# Day-2 operations

## Observability

Every process serves Prometheus metrics on port 9090 (`METRICS_ADDR`), published
to no host port and routed by no edge rule: reachable only from the
`dub-metrics` network, under the same `<service>-$ENV_ID` alias Prometheus
scrapes in [`observability/prometheus.yml`](../observability/prometheus.yml),
which holds one job per environment labelled `env_id`. Adding an environment
means copying that job with the other `ENV_ID` suffix, listing **only the
services that environment deploys** (an undeployed target is a permanent
`down`), and keeping the `env_id` label — it is what the dashboard filters on, so
a job without it merges two environments into one line.

The same project runs the logs half: **Loki** stores them (14-day retention),
**Alloy** ships them by discovering this host's containers through a read-only
Docker socket, and **Grafana** is the single UI over both, with the committed
`Device Uniqueness Backend — overview` dashboard. Nothing is configured per
service: `LOG_FORMAT=json` is all a process contributes, and the labels
(`project`, `service`, `container`, `level`) come from Docker metadata.

Prometheus (`127.0.0.1:9091`) and Grafana (`127.0.0.1:3000`) are **loopback-only**
— reach them over an SSH tunnel. Set `GRAFANA_ADMIN_PASSWORD` before exposing
that port anywhere else, and set `METRICS_ENABLED=false` to turn an
environment's exporters off entirely.

```bash
ssh -N -L 3000:127.0.0.1:3000 <server>
open http://127.0.0.1:3000/d/dub-overview     # anonymous read-only
```

**Check the `environment` selector before reading anything** — every panel,
metrics and logs alike, is scoped to it. The dashboard is provisioned read-only:
edit `observability/grafana/dashboards/dub-overview.json` in the repo and restart
Grafana rather than clicking, and **increment its `version` once per change** —
Grafana skips re-importing a provisioned dashboard whose version has not risen,
so an edit otherwise silently does nothing.

Ad-hoc questions go to Explore:

```logql
{env_id="paseo-next-v2"}                            # one environment, everything
{service="device-attestation-chain-writer"}         # one service, every environment
```

## Registration outbox

`username_reservations` is the source of truth
(`RESERVED → SUBMITTING → ASSIGNED | RETRY_AFTER | FAILED_TERMINAL`); the chain
is reconciled to it.

```bash
sudo docker compose exec -T postgres psql -U device_attestation -d device_attestation \
  -c "select id, full_username, status, attempt, tx_hash, left(last_error,120) as err
      from username_reservations order by id desc limit 10;"
```

- `RETRY_AFTER` retries automatically, up to 8 attempts.
- `FAILED_TERMINAL` never retries — inspect `last_error`.
- **Not every failure spends one of those 8.** A refusal that belongs to the
  *signer* rather than the row — its next nonce still held by an earlier
  transaction of ours waiting in the node's pool, or a submission the writer
  stopped watching when `CHAIN_WRITER_FINALIZE_SECS` ran out — holds the row in
  `RETRY_AFTER` at an unchanged `attempt` and logs `submission deferred without
  spending an attempt`. One writer signs from one account and the chain serves
  that account strictly in nonce order, so while one transaction is stuck every
  row behind it gets the identical refusal; billing that to whoever is standing
  in the queue would fail valid registrations for someone else's traffic jam.
  Deferrals count on `dub_chain_submit_total{outcome="deferred"}` — a burst
  while `outcome="ok"` stays flat is one slow inclusion holding the lane, and it
  clears itself; a sustained one is a pool or RPC problem worth looking at.
- Independent check: query `Resources.UsernameOwnerOf("<base>.<NN>")` on the
  People Chain.
- A pass submits its whole claimed set as **one** `Utility.force_batch`, so rows
  share a `tx_hash` and a `nonce`. Many rows on one hash is normal, not a
  duplicate submission.

### Batch size is adaptive

`CHAIN_WRITER_BATCH_SIZE` (default 25) is the *maximum*.
`dub_chain_batch_size{lane="people"|"dotns"}` is the size actually in use: it
halves on every whole-batch failure (floor 1) and climbs back one per successful
submission, but never back into the smallest size it has seen fail — that one is
retried only after 20 consecutive successful submissions. A chain that rejects
*every* batch of two or more (a proxy whose `ProxyType` allows the inner call but
not `Utility.force_batch` is the case to check first) therefore settles at a size
of 1 rather than alternating 1 → 2 → fail and paying a fee on every other pass.

- Size sitting well below the max, or pinned at 1 → the chain is rejecting whole
  batches. Look for `registration batch failed as a whole` in the logs; the line
  carries the reason and the next size. The usual cause is the block's weight
  budget (each `attest` verifies two sr25519 signatures and writes storage),
  which the halving search resolves on its own within a few passes. If it settles
  much lower than 25, lower `CHAIN_WRITER_BATCH_SIZE` to near it so a fresh
  writer does not re-run the search on every restart.
- A whole-batch failure does **not** advance any row toward `FAILED_TERMINAL`:
  `attempt` is unchanged and the set is deferred on one shared backoff. Rows
  piling up in `RETRY_AFTER` with a low `attempt` is the batch failing, not the
  rows.
- `dub_chain_batch_failed_total{lane}` counts whole-batch failures;
  `dub_chain_batch_item_failed_total{lane}` counts individual rejected calls. The
  first climbing with the second flat means the chain, not the claims. A batch
  that *submitted* but had to be resolved from chain state is neither: it counts
  on `dub_chain_batch_reconciled_total{lane}`, leaving the lane's size and
  failure counter untouched.
- `dub_registration_latency_seconds` is end-to-end intake→on-chain, measured per
  row from its own `created_at`. Only assignments this writer's own submission
  produced are recorded; a row the chain already showed as owned (an idempotent
  replay, or one carried over from a previous writer at startup) is assigned
  without touching the histogram, so its age does not skew the number.
- **A count-guard error is serious.** `force_batch reported a different number of
  items than calls submitted` at ERROR means the positional mapping was discarded
  and chain state decided instead. Nothing is mis-assigned — that is what the
  guard is for — but a repeat means the runtime's batch event shape changed and
  the fan-out needs revisiting.

## dotNS gateway lane (Asset Hub)

A second, independent state machine on the same row. `status` is the People
registration; `dotns_status` is the Asset Hub reservation. **A dotNS failure
never changes `status`.** `ASSIGNED` + `DOTNS_FAILED_TERMINAL` means the username
works and the dotNS name does not.

```bash
sudo docker compose exec -T postgres psql -U device_attestation -d device_attestation \
  -c "select id, full_username, status, dotns_status, dotns_attempt, dotns_tx_hash,
             left(dotns_last_error,120) as err
      from username_reservations where dotns_status is not null
      order by id desc limit 10;"
```

- `NULL` — the request carried no `dotns` block, or the row predates the lane.
  There is no backfill; those are never submitted.
- `EXPIRED` — **not a bug to retry.** `reserve_name` enforces a 3-day window on
  the client's `signedAt`, and the backend cannot re-sign: only the client holds
  the candidate key. It means the row sat unsubmitted for days — writer down, or
  parked in `QUEUED`. The client must re-register.
- `FAILED_TERMINAL` — inspect `dotns_last_error`. Common causes: `dotns signature
  does not verify` (the client bound it to a different attester than
  `GET /api/v1/attester` returns), `lite label reserved by another account`, or a
  contract revert.
- `ABANDONED` — the People half reached `FAILED_TERMINAL`, so this half was never
  attempted. Nothing is wrong with the reservation; there is no username to
  attach a name to. Diagnose the People `last_error`.
- `RETRY_AFTER` with a **future-dated** signature error is not a failure: the
  client's `signedAt` is further ahead of the chain's clock than
  `MaxFutureSkewSeconds` allows. It clears itself once `dotns_not_before` passes
  and costs no attempt. A steady stream means client clock skew.

Watch `dub_dotns_lane_connected` (`1` up, `0` parked, absent = disabled),
`dub_dotns_outbox_depth{status}`, `dub_dotns_attester_allowance`, and
`dub_account_free_balance_planck{role="signer",chain="asset-hub"}`. A parked lane
with rising `PENDING` depth is the expected shape while Asset Hub is down; a
*connected* lane with rising `PENDING` depth is not. The Asset Hub allowance is a
**second budget**, separate from People's — either hitting zero stops
registration in its own half.

`dub_account_free_balance_planck` carries `chain` on **every** series, People
included. A selector written as `{role="signer"}` alone matches both chains —
always pin `chain="people"` or `chain="asset-hub"` in alerts and dashboards.

## Writer rules

- **Exactly one instance.** A nonce lane is (signing account, chain). Never
  `--scale device-attestation-chain-writer`. It holds two lanes on one account,
  People and Asset Hub; that is safe because nonces are per chain, and both sit
  behind the same single lease. The `writer_lease` table is a best-effort
  deploy-overlap guard only — the chain nonce plus outbox reconciliation is the
  real serializer.
- Restart-safe: reconciles `SUBMITTING` rows on both chains against chain state
  rather than resubmitting.
- **One dotNS condition refuses to start:** a missing `ASSET_HUB_RPC_URL`. The
  dotNS lane is not optional, so a writer without an endpoint would accept
  blocks nothing submits. Not restart-fixable; correct the `.env`.
- **Everything else dotNS parks the lane, not the writer.** Asset Hub is dialled
  on the first pass rather than at boot, and re-dialled every 30s while down, so
  an unreachable endpoint leaves rows in `PENDING` and keeps People registrations
  flowing. The parking warning names the cause and is logged once per distinct
  cause, not once per pass — read the first occurrence, not the latest.
- `sudo docker compose restart device-attestation-chain-writer` reuses the
  existing container, so it never changes the image. A version change is a
  project-wide `up -d`.

## Config and secret rotation

Everything is in the checkout's `.env` (mode 600); apply changes with
`sudo docker compose up -d`.

| Rotating | Consequence |
| --- | --- |
| `JWT_ED25519_SECRET` | Invalidates outstanding JWTs; clients re-authenticate. Update the verify-only half everywhere in the same change. |
| the writer key | Must be an authorized attester or proxy, and funded, **before** the switch. |
| `TURN_SECRET` | Invalidates outstanding TURN credentials (up to `TURN_TTL_SECS` old). Update the coturn relay and every `turn-api` together, then recreate each service. |
| `POC_HMAC_SECRET` | Invalidates outstanding puzzles (≤90s old); in-flight solvers get a `402` and request a new one. Safe to rotate any time. |

## After a chain wipe

Test networks get re-spawned. Two databases hold state derived from the chain
that just disappeared, and they need opposite treatment.

**`username-indexer` heals itself.** `sync_state.genesis_hash` records which
chain the checkpoint belongs to. On boot, a mismatch against the connected
chain's genesis makes the indexer discard the projection and the checkpoint and
run a full bootstrap. Expect one long first boot, a
`connected chain is not the one this projection was built from` WARN, then
`finalized username bootstrap complete` with `trigger=ChainChanged`. Nothing to
do.

**The device-attestation database needs a decision, so it is a script.** Its
outbox is not derivable from anything: `username_reservations` rows name
usernames no chain will confirm, and each one keeps occupying a discriminator
regardless of status, because availability unions the whole table with no status
filter — a base with 100 historical rows reports `EXHAUSTED` against an empty
chain. But the same database also holds `app_attest_keys` (per-install device
keys; clearing them makes every tester reinstall) and `registration_vouchers`.

```bash
# report only; deletes nothing, stops nothing
scripts/reset_env_state.sh --project <compose-project> --confirm <compose-project> --dry-run

# stop the writers, clear the outbox + lease, restart
scripts/reset_env_state.sh --project <compose-project> --confirm <compose-project>
```

`--confirm` must repeat `--project`: when two environments run from the same
compose file on one host, naming the target twice is what stops a reset landing
on the wrong stack. Add `--include-indexer` to force the projection rebuild by
hand rather than letting the boot guard do it.

Then re-check the [chain prerequisites](#chain-prerequisites) the wipe also
cleared.

## Backups

There are no automatic backups. Before anything risky:

```bash
sudo docker compose exec -T postgres pg_dump -U device_attestation device_attestation \
  | gzip > ~/device-attestation-$(date +%Y%m%d-%H%M%S).sql.gz

# restore into an empty DB:
gunzip -c ~/device-attestation-<timestamp>.sql.gz \
  | sudo docker compose exec -T postgres psql -U device_attestation -d device_attestation
```

The edge's `edge_caddy_data` volume holds the TLS certificates and the ACME
account key. Losing it is not fatal — Caddy re-issues — but repeated loss burns
Let's Encrypt duplicate-certificate allowance, so include it:

```bash
sudo docker run --rm -v edge_caddy_data:/data -v ~:/backup alpine \
  tar czf /backup/caddy-data-$(date +%Y%m%d).tgz -C /data .
```

## The edge: routes, TLS, docs

The route table is the **committed**
[`gateway/Caddyfile`](../gateway/Caddyfile), mounted read-only into the edge
container. It is a **generated artifact** — the region between the
`generated:route-table` markers comes from the one ownership map in
`crates/dub/src/routes/table.rs` via `just routes`, and a test fails if it is
stale. Never hand-edit inside the markers.

Never edit a running copy either. Change the repo file, pull, then validate and
reload in place — the mount means the new file is already inside the container,
so this drops no connection. Recreating the edge would interrupt **every**
environment, since it is the only container on 80/443:

```bash
sudo docker run --rm -v "$PWD/gateway/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile
sudo docker compose -f gateway/docker-compose.yml -p edge \
  exec -T caddy caddy reload --config /etc/caddy/Caddyfile
```

A reload only re-reads the file. Changing the container's *environment* or ports
— a new `{$VAR}` placeholder, which must also join the `environment:`
pass-through list in `gateway/docker-compose.yml` — needs `up -d`, and accepts
that brief interruption.

For a different domain, set `GATEWAY_ADDRESS` in the edge project's environment
rather than editing the file. Certificates live in `edge_caddy_data` and renew
automatically. `https://<domain>/docs` serves `docs/api-reference/` mounted from
the checkout; a pull updates the files, but recreate the edge project if the
mount looks stale.

## Proof-of-compute gate on public search

Off by default. When on, `GET /api/v1/usernames/search` needs **either** a valid
device-attestation JWT **or** a solved puzzle from `POST /api/v1/poc/issue`, so
only anonymous callers have to mine. An unverifiable bearer is treated as
anonymous — this route never returns 401.

```bash
# in the environment's .env — username-indexer only
POC_ENABLED=true
POC_HMAC_SECRET=<random, >=32 chars>   # required when enabled; boot fails without it
sudo docker compose up -d username-indexer
```

The service also needs verify-only JWT material (`JWT_JWKS_JSON` or
`JWT_ED25519_PUBLIC_KEY`) or it refuses to boot — without it every caller would
be anonymous and authenticated clients would be forced to mine anyway.

```bash
curl -sX POST https://<domain>/api/v1/poc/issue                       # 201 + puzzle
curl -so /dev/null -w '%{http_code}\n' 'https://<domain>/api/v1/usernames/search?prefix=a'  # 402
```

`POC_DIFFICULTY_BITS` (1–32, default 16) is the number of leading zero bits, so
each extra bit doubles the expected work. 16 bits is roughly 0.1s of native
single-threaded mining; raise it only with a measurement from the slowest client
you expect.

---

## Failure modes

| Symptom | Action |
|---|---|
| `readyz`: `chain: down` | People Chain RPC unreachable or changed — check `PEOPLE_RPC_URL`. |
| Writer: `registration parked without spending an attempt` / `dotns reservation parked …` | The signer cannot pay fees on that chain. Rows are held in `RETRY_AFTER` at an unchanged `attempt` and resume by themselves once funded — nothing is lost and no restart is needed. Fund the signer named in the accompanying `chain-writer signer balance below floor` warning (`ATTESTER_SIGNER_BALANCE_FLOOR_PLANCK` is the threshold, and the two chains hold **separate** balances for the same account). A park that persists past a top-up is not a funding problem: read the `reason` field. |
| Writer: `submission deferred without spending an attempt` | The signer's next nonce is held by an earlier transaction of ours still in the node's pool (`priority of the transaction is too low`, `Transaction Already Imported`) or a submit passed `CHAIN_WRITER_FINALIZE_SECS` without being seen finalized. Rows wait 30s at an unchanged `attempt` and resume by themselves; nothing is lost and no restart is needed. Expect a short burst behind one slow inclusion — that is the mechanism working. Persisting for many minutes means the incumbent transaction is not being included: check finality lag and the RPC endpoint, and confirm the signer can pay fees (an unfunded signer parks instead, see the row above). Do **not** restart the writer to clear it — a restart re-reads the nonce and hits the same pool. |
| Writer: `submission deferred …; the signer's nonce was already consumed on chain` | The node refused the signed nonce as `Transaction is outdated`: it is below the signer's current nonce. The writer reads its nonce with `system_accountNextIndex` (best block plus our pool transactions), so an occasional one after a reconnect or finalize timeout is expected; rows wait 6s at an unchanged `attempt` and re-read. A steady stream means **something else is signing from the writer's account** on that chain (another deployment or a manual script) — find and stop it; the writer cannot out-race it. |
| Writer: `rejected deterministically, not retried` in `last_error` | Another submission would buy the same answer, so the row fails on the first pass instead of paying `CHAIN_WRITER_MAX_ATTEMPTS` fees. All three causes are the row's `reserved_username` (the personhood name) leg, which `attest` checks **before** it writes the lite username: `Resources::UsernameReservationTaken` (that name is owned by someone else), `Resources::QueueFull` (its reservation queue is at `MaxReservationQueueLength`, 10 on next-people-paseo), `Resources::AlreadyHasReservation` (the candidate already reserved another name). Intake refuses these claims with a `409` before a row exists, so a row that reaches here raced that check — a queue that filled in between. The writer **cannot** resubmit without the reservation: the consumer signature covers `reserved_username`, so only the client can re-sign. The client must re-register for another `dotns.reservedUsername` — dropping the reservation leg is not an option any client implements. Note `QueueFull` is not immutable in principle — entries expire and `remove_expired_username_reservation` is permissionless — but nothing drains within the seconds the backoff spans. The lite username is unaffected only if `status` is `ASSIGNED`; if it is `FAILED_TERMINAL` the discriminator that row holds stays consumed until the row is deleted. |
| Availability checks failing while `readyz` is green | The endpoint does not serve the legacy `state_queryStorageAt` method (a trimmed or `chainHead`-only RPC or proxy). Availability reads all 100 `{base}.{NN}` keys in one such request, and the writer resolves `UsernameOwnerOf` (People) and `LiteLabelOwner` (Asset Hub) for a whole claimed set the same way, so writer passes fail wholesale too — but `readyz` only probes it on People, so readiness can stay green. Repoint `PEOPLE_RPC_URL` (and `ASSET_HUB_RPC_URL`) at a full node. A response that is incomplete, doubled, or for another block also fails closed by design — never as "available". |
| Claims returning `422 Pool exhausted` (`testnet` builds only) | The ticket pool drained. Check `invite-tickets-pool` logs: `ticket batch finalized … registered=0` means the inviter is out of `AvailableInvites` quota or unauthorized; `pool tick failed` means RPC or signer trouble. Pool size is logged each tick — treat sustained `available < ~10% of POOL_TARGET_SIZE` as the alert threshold. |
| `invite-tickets-pool`: `another maintainer instance holds the pool lock` (`testnet` builds only) | A second replica or a stuck deploy overlap. Scale back to exactly one. |
| `unknown role: invite-tickets-api` / `-pool` at startup | A `polkadot` image was started with `COMPOSE_PROFILES=invite-tickets`. That runtime has no `Game` / `ProofOfInk`, so the build has no such roles. Clear `COMPOSE_PROFILES` in `.env`, or rebuild with `DUB_NETWORK=testnet` if you meant the other network. |
| Writer: `queue advancer is down with claims queued; holding the throttle` | The registration queue is enabled but `registration-queue` is dead, so free-lane claims park as `QUEUED` and nothing drains. This is deliberate: the queue is the free lane's throughput control and a dead queue never falls back to unthrottled registration. Restart it. To retire the queue instead, set `QUEUE_ENABLED=false` for **both** `device-attestation-api` and the writer (writer last). Treat a warning that survives one restart as a page. |
| `QUEUED` rows draining with the advancer down, or stranded-queue warnings while intake goes direct | `QUEUE_ENABLED` is split between api and writer. Writer off + api on = the janitor silently drains a queue the api is still filling, and the throttle is gone. Writer on + api off = warnings about leftovers no new claim joins. The values must match; `scripts/verify_compose_boundaries.sh` pins both. |
| Rows stuck in `RETRY_AFTER` with wasm-trap errors | Invalid payload for `PeopleLite.attest`, or attester/proxy authorization missing on-chain. |
| At boot: `live runtime and the vendored metadata disagree` | The chain was upgraded under the vendored blob. Harmless on its own — most upgrades change nothing this workspace signs — but it is the early warning for the row below, which is the same drift seen minutes to days later as a failed write or a silent invite-ticket pool. Every connection also logs `connected to the chain` with the live `spec_version` / `transaction_version`, on People and Asset Hub alike. |
| `The extrinsic payload is not compatible with the live chain` | The runtime changed shape under the vendored metadata. Refresh `crates/chain-types/metadata/metadata.<network>.scale` (the one this build's `DUB_NETWORK` names — the boot warning logs it as `vendored_metadata`) with the `subxt metadata` command in the `chain-types` crate docs, `subxt diff` the blobs to see what moved, then rebuild. |
| Every extrinsic failing with `Transaction has a bad signature`, nonce back at 0 | The chain was reset: the process still holds the old genesis hash, captured when its client connected. **Restart the service** — reconnecting alone does not re-read it. Then re-check the [chain prerequisites](#chain-prerequisites). |
| Writer exits at boot | Bad `CHAIN_WRITER_SIGNER_SURI`, or Postgres unreachable. |
| `device-attestation-api` never healthy | It blocks on the People Chain RPC at startup. Check connectivity to `PEOPLE_RPC_URL`. |
| `username-indexer` never healthy | Check its Postgres, its RPC, and its bootstrap logs. |
| Search fails while device-attestation routes work | Check the indexer's logs and its edge route; for a direct `readyz`, layer the debug overlay and curl `127.0.0.1:8081`. |
| A just-registered username is not in search results | With `SPECULATIVE_INDEXING_ENABLED` on (the default) the expected gap is about one block after the registration is *authored*, not after it is finalized. Check `dub_indexer_checkpoint_lag_blocks` first: a climbing lag means the projection is genuinely behind (a restart backlog is replayed block by block). A **flat, near-zero lag** means the indexer is caught up and the row is being withheld downstream — search hides accounts whose `identifier_key` predates chat-spec RFC-0004, so a client that sets that key in a later transaction than the one registering the username is invisible until it lands. |
| `best block subscription dropped; resubscribing` repeating, or `dub_indexer_subscribed` flapping | The RPC endpoint accepts the subscription and closes it. Retries back off exponentially to 60s, and the `SYNC_INTERVAL_SECS` fallback still forces a pass, so the projection keeps advancing — but at poll speed, not block speed. Check the endpoint's subscription limits, or repoint `PEOPLE_RPC_URL`. |
| A username appeared in search and then vanished | Expected, and rare: a speculative row whose block was discarded at the tip. `dub_indexer_speculative_retracted_total` counts them. It re-appears once the registration lands on the canonical chain — usually, but not always: the registration is re-submitted against a chain where the name may since have been taken, and a name is owned by one account forever. If the rate is high, the endpoint's fork rate is high — check `dub_chain_finality_trail_blocks`, or set `SPECULATIVE_INDEXING_ENABLED=false` to serve finalized state only. `dub_indexer_speculative_failed_total` climbing instead means the window could not be read at all; the finalized projection is unaffected, but nothing is being admitted early. |
| `unfinalized window too wide; admitting nothing new` | The best head has run more than `MAX_SPECULATIVE_WINDOW` (64) blocks ahead of finality, so the chain's finality is stalled rather than merely trailing. The indexer stops admitting new speculative rows and search goes back to finalized-only latency for anything new — but rows already held are still re-checked against the best head every pass, so nothing gets stranded for the length of the stall. Investigate finality on the chain, not the indexer. `dub_indexer_speculative_stood_down_total` counts it. |
| `turn-api` exits: `TURN_PROOF_PRODUCTS: must list at least one product id` | The proof route is enabled with no accepted product. Every proof is made under a product-scoped context, so the list is required — set it, or turn the feature off. |
| TURN 201s minted but the relay rejects the credentials | `TURN_SECRET` / `TURN_AUTH_ALGORITHM` drifted from the relay's coturn config. They must match exactly; rotate together. `turn-api` is stateless, so `readyz` never gates on this. |
| Public search suddenly returning `402` | The proof-of-compute gate is on. Expected for anonymous callers; if *authenticated* clients see it, the indexer's verify-only JWT material is wrong — compare it against `device-attestation-api`'s `/.well-known/jwks.json`. |
| `402 puzzle has already been used` on a first attempt | The client is reusing a puzzle (one solve = one request), or a proxy is retrying. Each request needs a fresh `POST /api/v1/poc/issue`. |
| `spent_puzzles` growing without bound | The pruner is failing (`pruning expired spent puzzles failed`). Rows are harmless but unbounded until it recovers. |
| Every device-attestation role fails at boot: `payment_requests is not empty; export it before dropping` | Migration `0010` drops the retired paid lane's table and refuses while it holds rows, which would mean a quote was issued somewhere. Nothing is applied and every process that connects to the database stops at startup. Export the rows (`CONFIRMED` and `FAILED_CONFLICT` ones record money received) and settle them with support, then `DELETE FROM payment_requests` and restart. |
| An image older than migration `0010` fails at boot after the upgrade | sqlx refuses to start against a database holding a migration the binary does not know, and `0010` does not restore `payment_requests`. Roll forward instead; returning to an older image means restoring a backup taken before the upgrade. |
| `migration N was previously applied but has been modified` | The volume holds an older schema. Back up first, then `docker compose down && docker volume rm <project>_pgdata && docker compose up -d`. **This destroys database state.** |
| No TLS certificate | DNS not propagated, 80/443 blocked, or another process holding the ports. `dig +short <domain>`, `sudo ss -ltnp '( sport = :443 )'`, and the edge project's logs. |
| Edge answers 502 | The upstream alias does not resolve: the environment project is down, or its `ENV_ID` does not match the Caddyfile's upstream suffix. `sudo docker network inspect dub-edge`. |
| `network dub-edge not found` | Created out of band, once per host: `sudo docker network create dub-edge`. |
| `/docs` returns 404 | The edge mounts `../docs/api-reference` from the checkout. Confirm the path exists, and recreate the edge project after a pull. |
| Down after a reboot | Should not happen (`restart: unless-stopped`). If it does, bring up both projects. |
