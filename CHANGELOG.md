# Changelog

Notable changes to the published binaries. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning:
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, a breaking change bumps the **minor**. Pin an exact `vX.Y.Z`.

## [Unreleased]

## [0.7.0] - 2026-09-16

### Added

- **The container image is published from this repository.** Until now
  `docker.io/paritytech/device-uniqueness-backend` was pushed from Parity's
  private tree and its tags did not correspond to tags here. One image
  workflow now publishes it from this repository, from the same `Dockerfile`
  stage the release tarballs are exported from:
  - **Release images**, `<tag>-<network>` (e.g. `v0.7.0-testnet`,
    `v0.7.0-polkadot`), multi-arch (`linux/amd64` + `linux/arm64`), built when
    the `vX.Y.Z` tag is pushed; the release workflow, dispatched after that,
    pins the compose bundle to them. No bare `<tag>`, `stable` or `latest`: an
    image carries a binary built for one runtime, so a tag must name its
    network, and pinning an exact version is the only supported mode.
  - **Commit images**, `YYYYMMDD-HHMMSS-<shortsha>` (`linux/amd64` + `linux/arm64`, `testnet`),
    one per push to `main`. Pull requests build the image without pushing.
  - A manual run of the image workflow builds any ref for either network under
    a tag of the operator's choosing; the commit-image shape is refused there,
    since it is the key the internal deployment promotes on.

### Changed

- **`turn-api` gains a credential provider, and defaults to Cloudflare Realtime
  TURN.** The relay this service was built against is decommissioned, and
  Cloudflare does not do shared-secret HMAC credentials: it mints both halves
  itself and returns the ICE server list with them. `TURN_PROVIDER` now selects
  the source — `cloudflare` (the new default) fetches one credential per request
  from `generate-ice-servers`, and `coturn` keeps the previous behaviour of
  computing the credential locally from a secret shared with a relay you run.
  Only the selected provider's variables are read, so a deployment holds one
  provider's secret and not the other's.

  **Operators on a self-hosted relay: set `TURN_PROVIDER=coturn` and nothing else
  changes.** `TURN_SECRET`, `TURN_AUTH_ALGORITHM`, `TURN_REALM` and `ICE_SERVERS`
  keep their meanings under that provider. Leaving `TURN_SECRET` set without
  naming the provider is refused at boot with a message saying what to set, so
  the upgrade cannot silently land on Cloudflare and fail at request time.
  Operators moving to Cloudflare set `TURN_KEY_ID` and `TURN_API_TOKEN`, which
  are required by that provider and have no defaults.

  **Clients need no release**, but the 201 body's `username` and `password`
  should be treated as opaque: on `cloudflare` they are unstructured Cloudflare
  values, so anything parsing `username` as `{unixExpiry}:{hexId}` must stop.
  `ttl` is now the life remaining on the credential rather than the configured
  TTL (identical on `coturn`, which mints to order; lower on `cloudflare` only
  when a cached credential is served). Both routes can answer `503` on
  `cloudflare` when it is unreachable and nothing is cached — unreachable on
  `coturn`, which computes locally.

  On `cloudflare`, each request getting its own credential is what keeps callers
  mutually unlinkable; the last good response is cached and served during an
  outage, and after three consecutive failures the client serves that cache
  directly for 30s rather than making every caller wait out a timeout. The proof
  route's alias-derived credential id remains on `coturn`, where the HMAC keying
  it still exists; on `cloudflare` the alias is purely an in-memory throttle key,
  since nothing derived from the prover reaches a Cloudflare-minted credential.

- **The dotNS lane has its own batch-size ceiling, `CHAIN_WRITER_DOTNS_BATCH_SIZE`
  (default 3).** Both writer lanes used to climb back to `CHAIN_WRITER_BATCH_SIZE`
  (25), but `reserve_name` dispatches through the DotNS contract on
  `pallet_revive` and declares enough weight that Asset Hub refuses a
  `force_batch` of four or more at submission (`Transaction would exhaust the
  block limits`). The lane already recovered — it re-queued the set without
  spending an attempt and halved its way down — but it paid a few minutes of
  delay for that search after every restart and on every burst. It now starts at
  the size that fits. `CHAIN_WRITER_BATCH_SIZE` no longer caps the dotNS lane.

- **PreviewNet is gone; `testnet` means paseo-next-v2.** The default endpoints
  are now `wss://paseo-people-next-system-rpc.polkadot.io` and
  `wss://paseo-asset-hub-next-rpc.polkadot.io` in `.env.example`, compose and
  the built-in fallbacks. `DUB_NETWORK=testnet` still selects the same
  `next-people-paseo` metadata — the runtime did not change, only the deployment
  it names — so no rebuild is required, but an environment relying on the old
  `wss://previewnet.substrate.dev` defaults must now set `PEOPLE_RPC_URL` and
  `ASSET_HUB_RPC_URL` explicitly. The previewnet Prometheus job, the Alloy
  `dub-previewnet` log label, the `identity-previewnet.dotspark.app` gateway
  site block and its `PREVIEW_GATEWAY_ADDRESS` variable are removed, as are the
  two previewnet-only entries in `KNOWN_RUNTIMES` (the signing extension tuples
  are unchanged — they were already the union).

### Fixed

- **The quickstart stack boots again.** `.env.example` and compose selected the
  `cloudflare` provider with no credentials to go with it — no placeholder can
  stand in for a real Cloudflare account — so `cp .env.example .env && docker
  compose up` crash-looped `turn-api` at boot, and so did `--role all-in-one`.
  Both now default to `coturn`, which computes credentials locally and needs
  nothing off the machine, with the documented dev-only secret and a loopback
  `ICE_SERVERS`. The code default is unchanged: `TURN_PROVIDER` unset is still
  `cloudflare`, which is what a deployment wants.

- **`ICE_SERVERS` is required under `TURN_PROVIDER=coturn`.** It was optional
  and defaulted to empty, so a relay deployment that forgot it booted clean and
  answered every request `201 {"servers": []}` — a credential with no relay to
  use it against, failing at the client rather than at boot.

- **A Cloudflare 4xx is no longer served out of the outage cache.** Every
  non-2xx was classified retryable, so a revoked, wrong or mis-scoped
  `TURN_API_TOKEN` was indistinguishable from an outage: the stale credential
  went to every caller at `warn` level for up to `TURN_TTL_SECS` while the
  breaker suppressed the calls that would have surfaced it. 4xx other than 408
  and 429 now fail immediately with `cloudflare rejected TURN issuance`.

- **A short `TURN_TTL_SECS` no longer empties the Cloudflare outage cache.** The
  floor on a cached credential's remaining life was a fixed 60s, so any TTL at
  or under a minute rejected each credential the instant it was stored and every
  Cloudflare blip became a 503. The floor is now derived from the TTL.

- **An upstream 503 no longer spends the caller's rate-limit slot.** Both TURN
  routes admit against the limit before issuing; the slot is now handed back if
  issuance then fails upstream. It mattered most on `/turn/issue-with-proof`,
  where the budget is per person and per product and a ring-VRF proof for a
  given second is one fixed value, so a caller could not cheaply retry until the
  window rolled.

- **`verify_compose_boundaries.sh` enforces the TURN secret boundary it
  documents.** `TURN_API_TOKEN` and `TURN_SECRET` were forbidden only on a
  named handful of services, so `device-attestation-*` or `invite-tickets-*`
  could have gained a billable Cloudflare minting credential with the gate
  still passing. Both are now forbidden on every service but `turn-api`.

- **Compose now passes device-attestation-api its attestation settings.** The
  service's environment allowlist was missing the Play Integrity
  (`PLAY_INTEGRITY_*`, `GOOGLE_CREDENTIALS`), DeviceCheck (`DEVICE_CHECK_*`,
  `APPLE_TEAM_ID`), Widevine dedup (`WIDEVINE_DEDUP_*`) and
  `REGISTRATION_VOUCHERS_ENABLED` variables. Values set in `.env` never reached
  the container, so these features stayed off under Docker. The Android CRL
  variables stay out on purpose. `verify_compose_boundaries.sh` now requires the
  verification keys on the api and forbids them on every other service.

## [0.6.0] - 2026-09-16

### Added

- **One tree for every network: `DUB_NETWORK`.** The `fork` line and `main`
  are merged. The People runtime is chosen at build time — `testnet` (default,
  covering previewnet and paseo-next-v2) or `polkadot` — and selects the
  vendored metadata (`crates/chain-types/metadata/metadata.<network>.scale`,
  replacing `people.scale`) and whether invite-tickets is built. On `polkadot`
  (no `Game` / `ProofOfInk`) `dub --list-roles` lists six roles and the claim
  path answers the catch-all 404; on `testnet` nothing changes. Compose passes
  it as a build arg and keeps the invite-tickets services behind the
  `invite-tickets` profile (`COMPOSE_PROFILES`). CI checks both builds, and a
  release ships every asset for both networks under one tag: binaries are
  `dub-<version>-<network>-<target>.tar.gz`, with a compose bundle per network
  whose `.env.example` already names it.

  Runtime versions this release targets:

  | build      | People runtime         | spec_version |
  | ---------- | ---------------------- | ------------ |
  | `testnet`  | `next-people-paseo-v2` | 3000000      |
  | `polkadot` | `people-polkadot`      | 2005000      |

- **Widevine device dedup for Android username claims.**
  `POST /api/v1/usernames` accepts three optional evidence fields,
  `attestationChain`, `deviceChallenge` and `deviceId`, sent together or not at
  all. The leaf key of the chain must attest
  `SHA-256(domain ‖ deviceChallenge ‖ accountKey ‖ deviceId)`. The raw device id
  never leaves the device, and the server stores only an HMAC of the hashed id
  (migration `0009`, `widevine_devices`), so a database dump cannot be tested
  against candidate ids. One free registration per physical device: the device
  record is reserved in the same transaction as the username, consumed when the
  registration lands on chain and deleted on terminal failure so the device can
  claim again. Off by default. `WIDEVINE_DEDUP_ENABLED=true` verifies and logs
  the would-be outcome without changing routing (soft mode), and requires
  `WIDEVINE_DEDUP_HMAC_KEY` (32 bytes, hex or base64). Adding
  `WIDEVINE_DEDUP_ENFORCE=true` gates the claim: a seen device or an Android
  claim without evidence gets the ineligible outcome, malformed evidence a `400
  DEVICE_EVIDENCE_MALFORMED`, evidence that fails verification a `403
  DEVICE_EVIDENCE_INVALID`, and an unreachable attestation revocation list a
  retryable `503 DEVICE_EVIDENCE_UNAVAILABLE`. Enforcing without `AUTH_ENABLED`
  and `ENFORCE_AUTH` logs a warning at boot, because the gate is then advisory.

### Removed

- **`DOTNS_GATEWAY_ENABLED` is gone; the dotNS lane is always on.**
  `device-attestation-api` always accepts the `dotns` block, and
  `device-attestation-chain-writer` requires `ASSET_HUB_RPC_URL`, refusing to
  start without it. The variable is no longer read, so an environment that set
  it to `false` now claims labels: before upgrading, make sure
  `ASSET_HUB_RPC_URL` names the Asset Hub of the same network as
  `PEOPLE_RPC_URL`. An Asset Hub whose `reserve_name` this backend does not
  encode (Paseo next's) parks the lane rather than stopping the writer.

- **The paid registration lane is retired.** It never quoted in any
  deployment. A claim the device gate turns away (a DeviceCheck slot already
  used, a Widevine device already recorded or an enforced Android claim without
  evidence, a lost device race) gets the terminal
  `200 {"registrationOutcome":"PAYMENT_REQUIRED"}` with nothing stored, as it
  already did with the lane's default `PAYMENT_LANE_ENABLED=false`; the wire
  value is kept because shipped Android clients match on it. Removed:
  `GET /api/v1/usernames/payment-status`, the chain writer's deposit watcher,
  the non-store-install routing (FR-005) that only ran with the lane on, the
  `payment_requests` table (migration `0010`, which refuses to drop a non-empty
  table), and the `PAYMENT_LANE_ENABLED`, `PAYMENT_MASTER_ACCOUNT`,
  `PAYMENT_AMOUNT_PLANCK`, `PAYMENT_REQUEST_TTL_SECS` and
  `PAYMENT_POLL_INTERVAL_SECS` settings, which are no longer read. The edge
  now routes only `/api/v1/usernames/search` to `username-indexer` (the
  GET-reads carve-out existed for `payment-status`); every other path under
  `/api/v1/usernames` reaches `device-attestation-api`, whose 404 body is the
  same shared envelope. Regenerate or redeploy `gateway/Caddyfile`. DeviceCheck,
  Widevine dedup, the registration queue and vouchers are unchanged.

### Fixed

- **The writer's transactions decode on runtimes that declare several
  transaction-extension versions.** subxt 0.50 signs a v4 extrinsic with the
  extensions of the *highest* version the metadata declares, but the runtime
  decodes v4 with version 0 only. Both polkadot-test chains declare two, so
  every registration and `reserve_name` failed with `wasm trap: wasm
  'unreachable' instruction executed`. Both lanes now sign through
  `chain_client::create_signed_v4`. On a single-version runtime (PreviewNet's
  Asset Hub) version 0 is that version, so the encoding is unchanged.
- **Signing covers the polkadot-test runtimes' extensions.** People gains
  `CheckMetadataHash`; Asset Hub gains `VerifyMultiSignature` (as `Disabled`)
  and `PrevalidateAttests`. The Paseo gates stay, so every network signs from
  one tuple.
- **A full-name reservation that would sink the claim is refused at intake.**
  `attest` checks the `dotns.reservedUsername` leg *before* it writes the lite
  username, and the consumer signature covers it, so a reserved name that is
  already owned or whose reservation queue is full used to cost the whole
  registration, with no retry able to drop the leg. Intake now reads that
  name's reservation state (not the base's, as the two need not match) and
  answers `409` before a row or a fee exists. Availability reports `EXHAUSTED`
  for a base whose bare name is owned or queue-full, read in the same batched
  request as the discriminators. The writer treats
  `Resources::UsernameReservationTaken`, `QueueFull` and
  `AlreadyHasReservation` as deterministic rejections, so a claim that races
  the check costs one fee instead of `CHAIN_WRITER_MAX_ATTEMPTS`.
- **`turn-api`'s proof-root refresher no longer leaks connections.** It dialled
  a fresh People Chain client every time a refresh failed and never closed the
  old one. It now holds one connection for the life of the process.

- **A contested signer nonce no longer fails registrations terminally.** One
  writer signs from one account and the chain serves that account strictly in
  nonce order, so while one of our transactions waits in a node's pool it owns
  that nonce: a replacement may only displace it by bidding strictly higher
  priority, and the writer attaches no tip, so every copy ties and every copy is
  refused. The single-row submit path charged each of those refusals to the row
  that happened to be next, which burned all 8 attempts in about three minutes —
  far less than a transaction may legitimately sit in a pool — and sent valid
  registrations to `FAILED_TERMINAL` against a healthy chain. A submit the
  writer stops watching at `CHAIN_WRITER_FINALIZE_SECS` did the same, and could
  additionally mark a row failed that was included moments later. Both are now
  recognised as signer-wide conditions and deferred on a fixed 30s backoff at an
  unchanged `attempt`, matching what the whole-batch path already did: a row
  waits out the jam and is re-read against chain state on its next pass. They
  count on `dub_chain_submit_total{outcome="deferred"}` and log `submission
  deferred without spending an attempt`. Genuine row-level rejections are
  unaffected and still spend their budget.
- **The writer reads its signer nonce the way the node validates it.** Both
  lanes used subxt's `account_nonce`, which reads at the *finalized* block, so
  any transaction of ours in a best block but not yet finalized left the read one
  behind and the next submission was refused as `Transaction is outdated`. That
  refusal was then logged as a pool jam and held for 30s, then re-read from the
  same lagging state. The nonce now comes from `system_accountNextIndex` (best
  block plus our own pool transactions). An `outdated` refusal that still occurs
  is logged as its own case (`the signer's nonce was already consumed on chain`)
  and deferred for 6s instead of 30s, still without spending an attempt.

### Changed

- **Vendored People metadata refreshed to `next-people-paseo` 3004000, and both
  signing tuples gained the gates that runtime added.** Pulled from Paseo Next
  v2 (`wss://paseo-people-next-system-rpc.polkadot.io`), which PreviewNet is now
  byte-identical to. Unlike the 3003000 refresh this one changes how we sign:
  `transactionVersion` moved 5 → 6, the runtime publishes a versioned extension
  set, and the encoding set now declares **`CheckMetadataHash`** — which had no
  slot in `PeopleTransactionExtensions`, so signing against the upgraded chain
  would have failed. It is subxt's real extension, not a `Noop`: its value is
  one byte but its implicit is `Option<[u8; 32]>`, and encoding nothing there is
  a signer-payload mismatch. The individuality Asset Hubs moved to 3004000 too
  and now declare **`VerifyMultiSignature`** (the same `pallet_verify_signature`
  gate People has always had) and **`PrevalidateAttests`**;
  `AssetHubTransactionExtensions` gained both, so the dotNS gateway write lane
  keeps signing. Every earlier runtime stays in the known-runtime list, so a
  binary pointed at a node that has not upgraded yet still signs. In the trimmed
  pallet surface, `Game` gained a `product_name` constant, `Members` a
  `RetiredIdentifiers` storage entry, and `System::Events` plus the
  call-wrapping extrinsics (`Utility::batch`/`force_batch`, `Proxy::proxy`,
  `People::under_alias`, `PeopleLite::dispatch_as_signer`) re-shaped around the
  new calls; nothing this workspace constructs changed name or arity.

- **subxt 0.50.3 → 0.51.1, which is required for the runtime above.** subxt
  0.50 builds a **v4** extrinsic whenever the chain advertises version 4, but
  encodes the transaction extensions from the runtime's **highest** extension
  version. Those were the same thing until `next-people-paseo` /
  `next-asset-hub-paseo` 3004000 split them into version 0 (the short legacy
  list) and version 1 (the full one). A v4 extrinsic carries no
  extension-version byte and is defined to use version 0, so one holding
  version 1's bytes does not decode at all: the node traps inside
  `validate_transaction` before it ever checks the signature. **Every write to
  an upgraded chain would have failed**, whatever the metadata said. 0.51
  resolves a versionless extrinsic to version 0 and fixes it; no workspace code
  changed to adopt it. Verified against all four live runtimes by handing each
  node's own `TaggedTransactionQueue_validate_transaction` a transaction built
  by the unchanged writer path: `Valid` on People and Asset Hub, paseo-next-v2
  and previewnet alike, where the same calls on 0.50.3 did not decode on any of
  them. Two `chain-types` tests pin the behaviour — one that a versionless
  extrinsic resolves to extension version 0, one that the tuple satisfies every
  name that version declares — so a bump that regressed it fails in CI rather
  than on chain. The runbook gains a row for the trap, which looks nothing like
  a bad signature.

- **`username-indexer` indexes the unfinalized window speculatively.** The sync
  loop now subscribes to **best** block headers rather than finalized ones, and
  each pass reconciles the finalized range first (unchanged, authoritative) and
  then the unfinalized window `(finalized, best]` against the best head. A new
  registration therefore reaches search about a block after it is *authored*
  instead of after it is finalized — a gap measured at 2-5 blocks on the People
  chain. New `SPECULATIVE_INDEXING_ENABLED` (default `true`) turns it off.

  Speculative rows carry `assigned_usernames.speculative_from_block` and obey one
  rule: **speculation may add rows and retract rows it added, and may never
  modify or delete finalized state.** That rule sets the scope: a *new*
  registration is admitted early, while a change to an account that already holds
  a finalized row — a personhood upgrade, an identifier key rotation — still
  becomes visible only at finality.

  The window is re-derived from the finalized head on every pass rather than
  checkpointed, so a block discarded at the tip — on PreviewNet's People chain,
  structurally about one height in eight — is retracted on the next pass instead
  of stranding a row the finalized pass would never revisit. Because
  `Resources::Consumers` is append-only on chain, that re-check is the only thing
  that ever retracts a row, so it runs on every pass: when a wake carries no
  header the best head is read over RPC instead, and when the window is too wide
  to scan the loop stops admitting but keeps re-checking what it already holds.
  Failure there is contained — the finalized pass is never failed or backed off
  by it. The checkpoint, `/readyz` freshness and the lag gauges keep their
  existing finalized-only meaning. Startup drops any speculative rows a previous
  run left behind, under the projection lock so a booting replica cannot clear
  rows a live one is serving. New metrics: `dub_chain_best_head_block`,
  `dub_chain_finality_trail_blocks`, `dub_indexer_speculative_window_blocks`,
  `dub_indexer_speculative_admitted_total`,
  `dub_indexer_speculative_retracted_total`,
  `dub_indexer_speculative_stood_down_total`,
  `dub_indexer_speculative_failed_total`.

- **`username-indexer` syncs on block headers instead of a timer.** The
  resync loop now subscribes to the People Chain's block stream and indexes on
  each header, so a newly registered username reaches
  `GET /api/v1/usernames/search` about a block after it is authored rather than
  up to `SYNC_INTERVAL_SECS` (default 30s) later. Headers are only a signal —
  every pass still re-reads the checkpoint and indexes up to the head — so a
  dropped or coalesced header costs nothing, and a burst is drained into one
  pass. `SYNC_INTERVAL_SECS` keeps its name and default but is now the fallback:
  the longest the loop sits without a header before forcing a pass anyway.
  Nothing to change in an environment. Two new metrics: `dub_indexer_subscribed`
  (1 while the best-header subscription is live) and
  `dub_indexer_resubscribes_total`.

- **Rate limits refill continuously instead of resetting per window.** Every
  limiter (`device-attestation-api` auth routes, username search,
  invite-tickets, `turn-api`, `notify-relay`) keeps its existing
  limit-per-window settings, now read as a burst that refills at
  `limit / window`. A client can no longer spend a full window at its end and
  another at the start of the next. Per-IP keys now come from the **rightmost**
  `X-Forwarded-For` entry (then `CF-Connecting-IP`, then `True-Client-IP`)
  instead of the leftmost, which the client controls. Idle keys are evicted
  after an hour, and at most 8192 are held. invite-tickets' `Retry-After` is
  now the actual wait rather than the whole window.

## [0.5.0] - 2026-09-02

### Fixed

- **The invite-ticket pool mints again after People Chain 3000000.** The
  vendored metadata is refreshed from `next-people-paseo` 3000000, which
  paseo-next-v2 and previewnet both run (their metadata is identical). The
  upgrade did not touch `Game`/`ProofOfInk::set_invite_ticket` at all — what
  moved was `RuntimeCall`, which `PeopleLite` grew `register_with_fee` and
  `create_lite_people_collection` into. The pool never signs a bare
  `set_invite_ticket`; it signs the `Utility.force_batch` and `Proxy.proxy`
  wrappers around it, and those carry `RuntimeCall`, so every tick failed
  validation with `The extrinsic payload is not compatible with the live
  chain` and no ticket was minted. `/api/v1/invitation-ticket/claim` kept
  serving the pool it already had, so the first symptom an operator would
  have seen is `422 Pool exhausted` once it drained. Nothing about the wire format changed: pallet and call indices
  are identical on both sides of the upgrade, and username registration
  (`PeopleLite::attest`, `Resources::register_lite_person`) was never
  affected.
- **The dotNS lane can sign against Asset Hub 3000000.** That runtime dropped
  the `AsRingAlias` transaction extension and declares `AsScarcity` in its
  place. `AssetHubTransactionExtensions` had no member for it, and subxt
  resolves a runtime's extensions by name, so every Asset Hub submission
  would have failed to encode. The tuple now carries both gates: as with the
  People tuple, it is the union across every runtime in `KNOWN_RUNTIMES`, not
  a snapshot of the newest, so a binary pointed at a node that has not
  upgraded yet still signs.
- **An unfundable signer no longer fails registrations terminally.** A
  transaction rejected with `Inability to pay some fees`
  (`InvalidTransaction::Payment`) never enters a block, spends nothing and says
  nothing about the row, so it now **parks** the row — re-queued at an
  *unchanged* `attempt` behind a 5-minute `not_before` — instead of spending one
  of `CHAIN_WRITER_MAX_ATTEMPTS`. Previously a drained signer walked a row
  through its whole budget in about three minutes (`2^attempt` backoff, clamped
  at 6) and wrote `FAILED_TERMINAL`. On the dotNS lane that was unrecoverable:
  the client's reservation stays valid for `MaxValiditySeconds` (three days) and
  only the client holds the key that can re-sign it, so a funding gap an
  operator had not noticed yet destroyed claims that had days of validity left.
  Parked rows resume on their own once the signer is topped up; the existing
  `chain-writer signer balance below floor` warning and
  `dub_account_free_balance_planck` gauge remain how the outage is seen, now
  joined by `dub_chain_submit_total{outcome="parked"}`.
- **A rejection that cannot change is no longer retried.** A dispatch error
  named in `DETERMINISTIC_REJECTIONS` — currently
  `Resources::UsernameReservationTaken` — is terminal on the first pass. Such a
  call reached a block and paid its fee, and is byte-identical on every retry,
  so the previous behaviour paid the same fee eight times to be told the same
  thing, draining the very signer whose exhaustion then parks the lane.
  `last_error` now distinguishes the two terminal routes: `rejected
  deterministically, not retried: …` versus `max attempts reached: …`.

### Changed

- **`device-attestation-chain-writer` submits a whole pass as one extrinsic.** A
  claimed set now becomes one `Utility.force_batch` of `PeopleLite.attest` calls
  (wrapped as a whole in `Proxy.proxy` when the signer is a delegate) instead of
  one extrinsic per row, so N registrations cost one finalization rather than N.
  The dotNS gateway lane batches `DotnsGateway.reserve_name` the same way on
  Asset Hub. A single-row set still submits a bare call, unwrapped. Each row's
  outcome comes from its own `Utility.ItemCompleted` / `ItemFailed`
  positionally — and only when the item count matches the calls submitted;
  otherwise the positional mapping is discarded and chain state decides, so
  `ASSIGNED` can never be inferred from a mapping that does not line up.
  Failures split: a whole-batch fault (nonce, signing, transport, a proxy
  rejection of the batch) re-queues the set at an **unchanged** `attempt` on one
  shared backoff, while a per-item failure spends that row's own budget as
  before, carrying its dispatch error into `last_error` resolved to
  `Pallet::Variant`.
- **`CHAIN_WRITER_BATCH_SIZE` is now a maximum rather than a fixed claim size.**
  Each lane holds an adaptive size — halved on a whole-batch failure (floor 1),
  grown by one per successful submission, capped at the configured value — so
  the writer finds the chain's real per-batch ceiling instead of being
  configured with a guess. A lane also remembers the smallest size it has seen
  fail and stops one below it, re-probing that size only after 20 consecutive
  successful submissions: without that memory a chain that rejects *every* batch
  of two or more would make the lane alternate 1 → 2 → fail forever, paying a
  fee and a nonce on every other pass. The People and Asset Hub lanes size
  independently. The variable name and default (25) are unchanged; only its
  meaning is — a configured value that does not fit a `u16` falls back to the
  default rather than claiming the whole outbox at once.
- **The writer's owner reads are batched.** A drain pass resolves
  `Resources::UsernameOwnerOf` for its whole claimed set in one
  `state_queryStorageAt`, as does the startup `SUBMITTING` reconcile and the
  dotNS lane's `LiteLabelOwner` read — one round trip per pass instead of one
  per row. Unchanged semantics: a partial or unexpected answer is an error, never
  "unowned". Because one read now decides a whole set, a failed read is treated
  as a whole-batch fault: the set is re-queued at an **unchanged** `attempt` on
  one shared backoff, so a flapping RPC cannot walk an entire claimed set to
  `FAILED_TERMINAL`. The startup reconcile reads in chunks and keeps the rows it
  did resolve, rather than abandoning all of them on one bad response.

### Added

- **Metadata drift is visible at boot.** Every chain connection now logs the
  live `spec_version` and `transaction_version` once, and the People Chain
  connections compare it against the `spec_version` the vendored blob was
  generated from — read out of the blob's own `System::Version`, so the two
  cannot be edited apart. A mismatch is a `WARN` naming the file to refresh.
  Previously a runtime upgrade under a stale blob announced itself only as a
  throttled pool tick or a failed write, minutes to days later. The check is
  diagnostic and never fatal: most upgrades change nothing this workspace
  signs, and a chain that cannot be read has already failed the connect.
- **Batch observability.** `dub_chain_batch_size{lane}` (the adaptive size in
  use), `dub_chain_batch_items{lane}` (rows per submission),
  `dub_chain_batch_failed_total{lane}` (whole-batch failures),
  `dub_chain_batch_item_failed_total{lane}` (individual rejected calls),
  `dub_chain_batch_reconciled_total{lane}` (rows from a batch that submitted but
  had to be resolved from chain state — kept off the whole-batch failure counter
  so that one keeps meaning "the chain is rejecting batches"), and
  `dub_registration_latency_seconds` (end-to-end intake→on-chain, per row, and
  only for assignments the writer's own submission produced).
- **Chain failures are named the same way on both lanes.** `ProxyExecuted` and
  `Utility.ItemFailed` are now decoded through subxt's own `DispatchError`,
  against the metadata of the block the extrinsic landed in, by one
  implementation shared by People and Asset Hub. The dotNS lane previously
  recorded an undecoded value in `dotns_last_error`, having no vendored Asset Hub
  metadata to resolve names against; it now records `Pallet::Variant` like the
  People lane. People's names come from the runtime that actually executed the
  call rather than from the vendored metadata blob. The one error name the
  writer treats as success is now matched pallet-qualified
  (`PeopleLite::AlreadyRegistered`), so a gateway error that happens to be
  spelled the same way is retried rather than recorded as a reservation that
  landed.
- **`subxt` pinned to 0.50.3** (from 0.50.1), which picks up `frame-decode`
  0.18.1: V5 signer payloads now include the transaction extension version and
  call data as an immutable base implication, and unknown `Option<T>`
  transaction extensions encode as `None` instead of failing. Both are on the
  path this release's batched submission takes.

### Fixed

- **A proxied dotNS reservation rejected by the gateway is no longer recorded as
  reserved.** `Proxy.proxy` emits `ExtrinsicSuccess` even when the inner call
  fails, and the Asset Hub lane was reading that as success — the People lane has
  checked `ProxyExecuted` since the earlier silent-failure fix, but its Asset
  Hub twin never did. The check fails closed: a result field that is not a
  `Result<(), DispatchError>` is an error rather than a pass.

## [0.4.0] - 2026-08-25

Initial public release. Development up to this point happened in a private
repository, so this entry describes the state of the project at first publish
rather than a delta from a public predecessor.

The version starts at 0.4.0 rather than 0.1.0 so that it does not collide with
the internally-tagged 0.1–0.3 series, whose `docker.io/paritytech/device-uniqueness-backend`
images are public and were built from earlier source than this. A `v0.3.0`
here would name binaries that disagree with the `v0.3.0` image already
published under that name.

### Added

- **Device attestation and username registration for Polkadot's People Chain**,
  as eight services that are all `--role`s of one `dub` binary:
  `device-attestation-api` (auth handshake, username registration with free and
  paid lanes, JWKS), `device-attestation-chain-writer` (drains the reservation
  outbox onto the chain), `registration-queue` (queue advancer),
  `username-indexer` (finalized-chain username projection, prefix search, and
  the optional proof-of-compute gate), `invite-tickets-api` and
  `invite-tickets-pool`, `turn-api` (coturn REST credential issuer) and
  `notify-relay` (APNs / FCM push relay). Plus `voucher-mint`, an operator CLI.
- **A dotNS gateway lane** that claims Asset Hub labels alongside the People
  Chain username, as an independent state machine on the same row.
- **A single-URL Caddy gateway** whose route table is generated from one
  in-code ownership map (`crates/dub/src/routes/table.rs`), with a Traefik
  emitter for deployments that front the services differently.
- **A generated OpenAPI reference** under `docs/api-reference/`, kept in sync
  with the handlers by a test.
- **A Docker Compose stack** covering every service, its Postgres databases,
  the gateway, and an optional Prometheus / Loki / Grafana project.

### Changed since the 0.3.0 image

For anyone comparing against the published `v0.3.0` container image, the
source here is ahead of it. The **public HTTP surface is unchanged** — the
generated OpenAPI document is byte-identical — but the binaries are not the
same build:

- **JWT issuance and verification were consolidated into the `jwt-verify`
  crate.** `device_attestation::jwt` is gone and `Jwt` is re-exported from
  `jwt-verify`, which now carries the issuer, the verifier and the JWKS
  document. Issuing still requires the signing key that only
  `device-attestation` is given, so the sole-issuer property is unchanged.
  This pulls in `jsonwebtoken`, `sha2` and `hex` as new dependencies.
- **Both target Asset Hubs now take the `signed_at` `reserve_name` shape.** The
  boot-time shape guard remains and still refuses to return a client on a
  mismatch; it now guards against future runtime drift rather than
  distinguishing two live runtimes.

### Fixed relative to the pre-publish source

- **`cargo deny check licenses` passes.** `CC0-1.0` and `CDLA-Permissive-2.0`
  were missing from the allow list, so the audit failed on four transitive
  crates.
- **Three security advisories cleared** by updating the lockfile: `h2`
  0.4.15 → 0.4.19 (RUSTSEC-2026-0258), plus the yanked `num-bigint` and `spin`.
  Four advisories with no available fix are ignored with per-entry reasons in
  [`deny.toml`](deny.toml).
- **`jsonwebtoken` is pinned to `9`** rather than `*`. A wildcard version can
  resolve across a semver-major on any `cargo update`.
- **`.env.example` ships a working dev `TURN_SECRET`.** It previously carried
  the literal placeholder `<base64-secret>`, and `turn-api` refuses to boot on
  invalid base64 — so the documented quickstart crash-looped one service.

[Unreleased]: https://github.com/paritytech/device-uniqueness-backend-community/compare/v0.7.0...HEAD

[0.7.0]: https://github.com/paritytech/device-uniqueness-backend-community/releases/tag/v0.7.0

[0.6.0]: https://github.com/paritytech/device-uniqueness-backend-community/releases/tag/v0.6.0

[0.5.0]: https://github.com/paritytech/device-uniqueness-backend-community/releases/tag/v0.5.0

[0.4.0]: https://github.com/paritytech/device-uniqueness-backend-community/releases/tag/v0.4.0
