# Shrinking the attester to what only it can do


Sources:
- device-uniqueness-backend-community @ `ea175e8`
- dotns @ `3c8a9e96`
- individuality-community @ `4b606a3`
- polkadot-sdk @ `c208ccc5d3d`

Unmerged branches taken into account (see
[Pending upstream changes](#pending-upstream-changes)):
- individuality-community `zebedeusz/removing-usernames-from-pallet-resources` @ `063e2f0`
- dotns `fix/root-origin-gates` @ `3d2e767d`

Decentralization process started with the retirement of the `paid_lane`,
which means that the only way to attain a `lite-username` if devicehood checks
fail is via `peopleLite.registerWithFee`. This is not considered for R1 and is not
implemented on any client so far.

Summary:

- **Forced by upstream:** Asset Hub becomes the source of truth for usernames
  once they leave People's `Resources` pallet.
- **In scope to change:** the dotNS contracts and the `dotns-gateway` pallet, not
  just the backend. See [What we can change in dotNS](#what-we-can-change-in-dotns).
- **Can move on-chain, with changes:** dotNS claims, digit allocation (after the
  `Resources` branch), vouchers, and Game invites.
- **Rejected:** recording the device on-chain, and replacing the queue with an
  on-chain rate limit. Each fails on inspection (a privacy leak, and a mechanism
  that can't work); see [Moves dropped](#moves-dropped).
- **Stays off-chain:** proving that a device is genuine.

## Pending upstream changes

Neither repo has new commits on its main branch since the hashes above. Two
open branches change what this plan rests on.

### Usernames leave People (individuality-community)

`zebedeusz/removing-usernames-from-pallet-resources` removes usernames from
`pallet-resources`, leaving `dotns-gateway` on Asset Hub as the only username
store.

- **Removed from `Resources`:** `UsernameOwnerOf`, `UsernameReservationQueue`,
  `UsernameReservationDuration`, `ReservationOf`, `MinUsernameLength`,
  `MaxReservationQueueLength`, and the username fields in `Consumers`. A stepped
  migration, `MigrateV0ToV1`, clears them.
- **`people-lite` consumer registration no longer carries a username.**
  `LiteConsumerRegistrationParams` drops `username` and `reserved_username`, and
  the signing payload becomes `(account, verifier, identifier_key)`.
- **`support` drops the `Username` type**, and `ConsumerRegistrar::register_lite_consumer`
  takes only `(account, identifier_key)`.
- **`scripts/check-username-sync.sh`** lists the names users see on People today
  and would lose once the app reads from Asset Hub. It exists to size that gap
  before the release, which matches the ~32% dotNS coverage seen earlier.

**Backend work this forces, independent of any move below.** When this lands,
the backend breaks in these places:

- Availability and registration read `Resources::UsernameOwnerOf`,
  `UsernameReservationQueue` and `MaxReservationQueueLength`
  (`crates/device-attestation/src/chain/people.rs`,
  `usernames/available.rs`, `usernames/register.rs`).
- The writer encodes `username` and `reserved_username` into `attest`'s consumer
  params (`chain/writer/tx.rs`), and clients sign the old five-field payload, so
  `consumer_registration_signature` fails verification.
- `username-indexer` projects `Resources::Consumers` and the
  `Resources.LitePersonRegistered` / `PersonRegistered` events
  (`crates/username-indexer/src/incremental.rs`, `projection.rs`).
- The People lane of the outbox stops registering a name at all; the dotNS lane
  becomes the registration.

### Root gate moves to a gateway contract (dotns)

`fix/root-origin-gates` replaces `SystemUtils.originIsRoot()` on the governance
surfaces (`DotnsPopController`, `PopRules`, `DotnsRegistrarController`,
`DotnsNameWhitelist`) with `GovernanceAuth.isGovernance(registry, msg.sender)`.
The only accepted caller is a new, non-upgradeable `DotnsRootGateway`, which
checks `callerIsRoot` in its own frame and forwards through
`execute(targets[], payloads[])`.

- The trust model is unchanged: only Root reaches the controller.
- `dotns-gateway` ABI-encodes `reserveLiteName` / `reserveBaseName` /
  `registerBaseName` directly (`dotns-gateway/src/types.rs:284-286`) and calls
  the contract at `DispatcherAddress` (`dotns-gateway/src/lib.rs:213`).
  `DotnsRootGateway` only accepts `execute(targets[], payloads[])`, so the pallet
  has to wrap its calldata, and `DispatcherAddress` has to point at the new
  gateway, before the dotns branch is deployed.

## What we can change in dotNS

Both the dotNS contracts and the `dotns-gateway` pallet are ours to change, so
several gaps that looked permanent from the backend's side can be closed where
the names live. Facts they rest on:

- **Only the gateway issues lite labels.** A lite label is a subname `stem` under
  a numeric container `NN.dot`, and the controller must own that container
  (`SubnodeUtils.sol:121`). The public registrar controller only takes single
  labels (`DotnsRegistrarController.sol:351`), so `stem.NN` can't be registered
  any other way.
- **Gateway-issued names don't move.** Full names minted by the PoP controller
  are soulbound (`DotnsRegistrar.sol:153-154`), and lite subnames can only be
  reassigned by the controller that owns their container.
- **Only the controller can set a chat key.** `DotnsPopResolver.setChatKey` is
  gated to the PoP controller.
- **The contract returns nothing to the pallet.** The pallet only learns whether
  the call succeeded (`dotns-gateway/src/lib.rs:579-600`), and with
  `fix/root-origin-gates` every call goes through
  `DotnsRootGateway.execute(targets[], payloads[])`, which has no return value.
  Anything the pallet has to record must be decided in the pallet.

| Change | Where | What it unlocks |
| --- | --- | --- |
| Allocate the `.NN` suffix on-chain | `dotns-gateway` | Removes the backend's digit choice and the unsigned-digits gap; see [Digit allocation in the gateway](#digit-allocation-in-the-gateway-sound-after-the-resources-branch) |
| One lite name per account | `DotnsPopController` | A per-person limit enforced by the source of truth, for attester and ring paths alike |
| One lite name per alias | `dotns-gateway` | The same limit for ring-proof claims, where the contract never sees the alias |
| Chat-key update by the name's owner | `dotns-gateway` + `DotnsPopController` | Makes the resolver's chat key authoritative, so People's `identifier_key` no longer has to match |
| Governance-only reserve and revoke | `dotns-gateway` + `DotnsPopController` | Backfills existing People names without fresh user signatures, and settles suffix mismatches |
| Lite-ring-authorized reserve | `dotns-gateway` extension | Registration without the attester's Asset Hub allowance |
| Per-attester window on `reserve_name` | `dotns-gateway` | An on-chain throttle for the attester lane, which `origin-restriction` can't provide |
| Promote `AccountNames` to authoritative for gateway names | `dotns-gateway` | The indexer and app can read one map instead of re-checking the contracts |

## Changing Asset Hub as the source of truth for usernames

Once the `Resources` branch lands, People holds no usernames and Asset Hub
(`dotns-gateway` plus the dotNS contracts) is the only place they exist. This
move is forced by that release, not optional, and has to ship with it.

### Where the truth lives today

- **People is the effective source of truth.** The iOS app treats
  `GET /api/v1/usernames/search` only as a prefix-to-account lookup. It then reads
  username and chat key from People `Resources::Consumers` itself
  (`polkadot-app-ios-v2/Packages/Individuality/Sources/Resources/ResourcesPallet+StoragePath.swift`).
  It reads nothing from `DotnsGateway`.
- **The indexer projects People.** It reads `Resources::Consumers` and the
  `Resources.LitePersonRegistered` / `PersonRegistered` events
  (`crates/username-indexer/src/incremental.rs:525-531`).
- **dotNS is a second, best-effort lane.** A row can rest at `ASSIGNED` on
  People with its dotNS half `DOTNS_FAILED_TERMINAL`, and there is no backfill.

### The gap to close

Measured on PreviewNet on 7 Sep 2026. The counts drift; the ratios are what
matter.

- `Resources::Consumers` had 364 records; `DotnsGateway::AccountNames` had 115
  (~32%). Counting only RFC-0004 rows (chat key starting `0x00`, the only ones
  search shows, `search.rs:148`), it was 36 against 279 (~13%).
- Asset Hub was a strict subset of People, but **30 of the 115 accounts had a
  different number suffix on each chain**, for example `brevityios.48` on People
  and `brevityios.44` on Asset Hub. The two lanes pick digits independently.

### What has to change

1. **Registration writes to Asset Hub first.**
   - Availability reads Asset Hub (`LiteLabelOwner`, or the contract views
     `isPopIssued` / registry `recordExists`) instead of `UsernameOwnerOf`.
   - The digit is allocated by `dotns-gateway`, not the backend (see
     [Digit allocation in the gateway](#digit-allocation-in-the-gateway-sound-after-the-resources-branch)).
     Until that ships, the backend picks against `LiteLabelOwner`.
   - A row isn't done until the dotNS reservation lands. `ASSIGNED` with a
     failed dotNS half stops being an acceptable resting state.
   - `attest` carries only `(account, identifier_key)`, and clients sign the
     three-field consumer payload.
2. **One digit per name, chosen once.** Until the release, both lanes must use
   the same allocated suffix, so the 26% divergence stops growing. Find out
   whether the dotNS lane records the requested suffix while People records the
   allocated one.
3. **Reconcile existing names.**
   - `scripts/check-username-sync.sh` on the `Resources` branch lists every name
     users see on People today and would lose once reads move to Asset Hub. Run
     it against each network to size the gap.
   - Decide, per mismatched suffix, which name the user keeps. Recommended: keep
     the People name, since that's what users have seen and shared.
   - The attester can't simply replay `reserve_name` for old users: the candidate
     signature must be fresh (`MaxValiditySeconds`,
     `dotns-gateway/src/lib.rs:136-138`). Add a governance-only
     `force_reserve_name` to `dotns-gateway` that skips the candidate signature,
     and a governance-only lite-name revoke on `DotnsPopController` to release
     the Asset Hub suffix that loses. Feed both from the sync script's output and
     remove them after the release.
4. **The indexer moves to Asset Hub.** Its source becomes the `dotns-gateway`
   `NameReserved` / `NameRegistered` events plus `AccountNames`. The `0x00`
   chat-key filter carries over unchanged: chat keys are the same 65 bytes as
   People's `identifier_key`.
   - `AccountNames` is documented as not the source of truth, because it misses
     contract-side changes. Gateway-issued names can't change contract-side
     (see [What we can change in dotNS](#what-we-can-change-in-dotns)), so
     `dotns-gateway` can promote it to authoritative for them, once `reserve_name`
     stops overwriting `lite` and every chat-key change goes through the pallet.
   - Names registered through the public controller or the whitelist never
     appear in `AccountNames`. They aren't lite usernames, so search can ignore
     them.
5. **The app reads Asset Hub in the same release.** Its username and chat-key
   lookup has to move from `Resources::Consumers` to Asset Hub (`AccountNames`,
   `DotnsPopLens`, or the resolver's chat key). Moving the indexer without the
   app only shrinks search results, since accounts the app can't resolve are
   silently dropped.

## What the chain trusts the DUB for

The attester key, or its proxy, can register any lite person up to its
`AttestationAllowance`. Each row the chain can't check is trust placed in the
backend.

| The chain trusts that… | Enforced today in | Proposed |
| --- | --- | --- |
| The app and device are genuine | App Attest, Key Attestation and Play Integrity verifiers | Stays off-chain |
| The free lane is used once per device | DeviceCheck bits, `widevine_devices` | Stays off-chain |
| The voucher is valid | `registration_vouchers`, `voucher-mint` | Pallet change |
| The queue order is fair | `registration-queue` balance groups | Stays off-chain; optional throttle in `dotns-gateway` |
| The digit choice is fine | 100-key `UsernameOwnerOf` read plus the outbox (this read goes away with the `Resources` branch) | `dotns-gateway` change, after the `Resources` branch |
| The dotNS label matches the People username | Writer ordering only; the pallet never reads People state | Pallet change; moot once usernames leave `Resources` |
| Invite tickets reach legitimate users | Ticket private keys in `invite_tickets` | Game only, and only for existing lite people, not required for R1 |

## Moves that stand

### dotNS claimed with a lite-ring proof: sound with changes

- **Today:**
  - `DotnsGateway.reserve_name` needs an attester signature and a second
    allowance on Asset Hub.
  - The pallet never reads People state (`reserve_name`,
    `dotns-gateway/src/lib.rs:342`). The only link is that the writer waits for
    `ASSIGNED`.
- **Proposed:** add a transaction-extension path authorized by lite-ring
  membership, like `AsDotnsGateway::RegisterFullName` does for full people.
  - Lite ring roots already reach Asset Hub: the notifier whitelist includes
    `PEOPLE_LITE_IDENTIFIER` (`people.rs:1752`).
- **Removes:** the dotNS lane in the writer, the `dotns_*` outbox columns, and the
  Asset Hub attester allowance.
- **Required changes:**
  - **Land after the `Resources` branch.** While `Resources` still stores
    usernames, a user could hold `alice.42` on People and `bob.17` on dotNS once
    the backend stops sequencing. The extension can't prevent that: Asset Hub
    can't read People's `UsernameOwnerOf`, and the ring-root relay doesn't carry
    it. Once usernames live only in `dotns-gateway`, the dotNS label *is* the
    username and there is nothing to diverge from.
  - **One lite name per person, enforced twice.** The contract only rejects an
    identical node (`DotnsPopController.sol:607`), and `reserve_name` overwrites
    `AccountNames.lite` on every reservation, so one account can collect several
    lite names today. After the `Resources` branch lands this is the *only*
    per-person limit on names, since `attest` no longer registers one.
    - In `DotnsPopController`: record each user's lite name and reject a second
      one. This covers every path, including the attester's, in the source of
      truth.
    - In `dotns-gateway`: a record keyed by alias, because the contract only sees
      the account and one alias could otherwise claim for several accounts.
    - Existing accounts with several lite names need a governance cleanup that
      keeps one.
  - **Make the resolver's chat key authoritative.** `reserve_name` takes a
    `chat_key` that `dotns-gateway` never compares with the `identifier_key` in
    `Resources::Consumers`; today only the backend passes the same value to both.
    Asset Hub can't read People's `Consumers`, so the two can't be checked
    against each other. Instead, make `DotnsPopResolver.chatKey` the one clients
    read, and add an update path for the name's owner: a `dotns-gateway` call,
    signed by the account or authorized by its lite alias, that reaches
    `setChatKey` through the controller. Without that path a user who rotates
    keys is stuck, since only the controller can write it.
  - **Route the claim through `DotnsPopController`**, so the controller gate from
    dotns #305 is satisfied. With `fix/root-origin-gates`, that means going
    through `DotnsRootGateway`.
  - **Backfill `AliasRegistration`** for people who already got a label through
    the attester, or they can claim a second one. The existing v1 migration only
    backfills `AccountNames`, which is keyed by account rather than alias, so it
    doesn't help.
  - **Expect a delay.** A new lite person can't prove membership until three
    things have happened: onboarding (size 3, `people.rs:161`), ring building,
    and the relay to Asset Hub.

### Digit allocation in the gateway: sound after the `Resources` branch

- **Today:** the backend picks the `.NN` suffix from `01..99` after reading 100
  `UsernameOwnerOf` keys, and races its own outbox. The candidate signs only the
  stem; the digits "ride along as an unsigned extrinsic argument"
  (`dotns-gateway/src/lib.rs:323-330`), so whoever submits chooses them.
- **Proposed:** `reserve_name` takes the stem, and `dotns-gateway` allocates the
  suffix against `LiteLabelOwner`, which covers every lite label because only
  the gateway issues them.
  - **Start digit:** `(H(candidate ‖ stem) mod 99) + 1`, then probe upward with
    wrap-around to the first free suffix. No block randomness, so collators
    can't steer it, and there is no shared "lowest free" slot to front-run.
  - **Preferred digit:** optional, honoured if free, so the existing
    `preferredDigits` UX survives.
  - **Cap:** exactly two digits. When all 99 are taken, revert with a stem-exhausted
    error. This also closes the "3+ digits allowed" gap
    (`support/src/labels.rs:27`) for gateway names.
  - **Allocate in the pallet, not the contract.** The contract can't return the
    allocated label (see [What we can change in dotNS](#what-we-can-change-in-dotns)),
    and the pallet needs it for `LiteLabelOwner` and `AccountNames`. The
    contract's `LiteNameAlreadyIssued` stays as a backstop.
  - The allocated label goes out in `NameReserved`.
- **Removes:** digit selection in `usernames.rs` and `register.rs`, the
  availability read, the outbox race, and the unsigned-digits gap.
- **Requires the `Resources` branch.** Before it lands, People allocates its own
  digit in `UsernameOwnerOf` and Asset Hub can't read that, so the two would
  diverge again.
- **Residual risk:** someone can deliberately take the digit a victim's
  start point lands on. The victim just gets the next free one. Denying a whole
  stem takes 99 names, and with one lite name per person that means 99 lite
  personhoods.

### Invite tickets → lite-person self-invite, Game only: sound with changes

- **Today:** ticket claims need a JWT and an address
  (`invite-tickets/src/http.rs:211-242`), so they reach users who aren't lite
  people yet. Ticket private keys live in Postgres.
- **On-chain:** `Game.sign_up_with_account_lite_invite`
  (`game/src/lib.rs:1035`). It requires a lite-alias origin in the score context
  and allows one account per alias, ever (`game/src/lib.rs:1047`).
- **Removes:** Game tickets for users who are already lite people. The pool
  stays for everyone else, and for ProofOfInk, whose tickets feed
  `apply_with_invitation` (`proof-of-ink/src/lib.rs:1198`) toward full
  personhood.
- **Required changes:** retire the pool only if onboarding requires lite
  personhood before Game. Otherwise, add an on-chain invite that an issuer grants
  to new users.

### Vouchers as a recognition method: sound with changes

- **Today:** `voucher-mint` writes sha256 hashes into `registration_vouchers`.
  Redeeming a voucher requires an authenticated session and skips the device
  gate.
- **Proposed:** a new `Voucher(IssuerId)` recognition method, with expiry and
  single use enforced on-chain.
  - An issuer origin registers the hashes of voucher public keys.
  - Redeeming is a signature over the candidate.
- **Removes:** `voucher-mint`, `registration_vouchers`, and the INSTANT lane.
- **Required changes:**
  - The commented-out `Voucher(PersonalId)` at `people-lite/src/types.rs:41`
    means vouching by a full person, not issuer keys. This is a different variant.
  - Accept that vouchers become bearer tokens.

## Moves dropped

### Queue → attester rate limit via `origin-restriction`: unsound

`origin-restriction` can't throttle the attester:

- It gives back all consumed usage for `Pays::No` calls
  (`origin-restriction/src/lib.rs:37, 381`), and `attest` returns `Pays::No`
  (`people-lite/src/lib.rs:427`).
- It only tracks custom origins. A signed attester maps to `None`
  (`next-people-paseo/src/lib.rs:850-866`).
- The move to relay-chain block numbers (#58) changes neither of these.

A rate limit also wouldn't do the queue's job:

- It doesn't order claims by balance group.
- Rejected claims still need a durable buffer, and that buffer is the outbox.

Keep the queue. If throttling on-chain matters, add a per-attester
`(count, window)` check inside `attest` on People, or the same check on
`reserve_name` in `dotns-gateway`. Once usernames live only on Asset Hub, the
gateway check alone throttles name issuance.

### On-chain device nullifier in `attest`: unsound

- **It would publish a device-to-account link.**
  - Today `widevine_devices` deliberately clears `reservation_id` once a claim is
    consumed, so "a permanent row carries no device->username link"
    (`migrations/0009_widevine_devices.sql:5-7`).
  - Putting the nullifier in `attest` would place HMAC(device) next to the
    account in public history for good. Anyone holding the key and a device ID
    could link them.
- **Key rotation breaks it.** Rotating the key silently breaks uniqueness.
- **It only covers Android.** iOS uniqueness is DeviceCheck bits on Apple's
  servers.

## What stays off-chain

- **Device attestation.** None of the checks can run on-chain today:
  - The runtime has no P-256 host function and no CBOR, X.509 or RSA code. The
    only P-256 verifier is revive's precompile at `0x100`.
  - Android needs RSA and P-384 roots plus a live revocation list.
  - Play Integrity tokens are encrypted with keys that can't be published.
- **One-per-device dedup and the registration queue.** See the dropped moves.
- **Session JWTs and challenges.**
- **`turn-api`.** It already checks ring proofs against on-chain roots.
- **`notify-relay`.** It holds APNs and FCM credentials.
- **`username-indexer`.** Names live under hashed map keys, so prefix search
  can't run on-chain. Once the `Resources` branch lands, its only source is
  Asset Hub: `dotns-gateway` events and `AccountNames`, re-verified against the
  contracts until `AccountNames` is made authoritative. Until then it needs both.

## Moving without breaking what's in flight

Each move follows the pattern #45 used for the paid lane:

1. Stop taking new claims.
2. Drain what's in progress.
3. Drop the table, behind a migration that refuses to drop a non-empty table.

| In flight | Drain |
| --- | --- |
| Outbox rows with `dotns_*` not yet reserved | Let the writer finish them before the lane is removed; backfill `AliasRegistration` for holders. |
| Unredeemed vouchers | Honour until expiry, or re-issue on-chain. |
| Deployed clients on `/api/v1/usernames` and the ticket claim endpoint | Keep wire values clients match on, as #45 kept `PAYMENT_REQUIRED`; keep the old endpoints until clients migrate. |

## Where the backend ends up

**Roles**

- `device-attestation-api`
- `device-attestation-chain-writer` (People lane only)
- `registration-queue`
- `username-indexer`
- `turn-api`
- `notify-relay`
- `invite-tickets-api` / `invite-tickets-pool`, with narrower scope
- ~~`voucher-mint`~~

**Tables and columns**

- `auth_challenges`
- `refresh_tokens`
- `app_attest_keys`
- `username_reservations`
- `widevine_devices`
- `writer_lease`
- `invite_tickets`, with narrower scope
- ~~`payment_requests`~~ (dropped, #45)
- ~~`registration_vouchers`~~
- ~~`username_reservations.dotns_*`~~

Attester allowance on both chains is still the real throughput limit, because
every free registration spends it.

## Suggested order

1. **Track the two upstream branches.** When `removing-usernames-from-pallet-resources`
   lands, the backend has forced work regardless of this plan: availability, the
   consumer payload, and the indexer's source (see
   [Pending upstream changes](#pending-upstream-changes)). All pallet work lands in
   `individuality-community`.
2. **Change Asset Hub as the source of truth for usernames**, shipped with the
   `Resources` release: registration, suffix alignment, reconciliation, indexer
   and app together (see
   [Changing Asset Hub as the source of truth](#changing-asset-hub-as-the-source-of-truth-for-usernames)).
   Stop the suffix divergence right away; the rest waits for the release.
   dotNS work in the same release:
   - `DotnsPopController`: one lite name per account, and a governance-only
     lite-name revoke.
   - `dotns-gateway`: governance-only `force_reserve_name` for the backfill.
3. **Digit allocation in `dotns-gateway`, after step 2.** Stem-only
   `reserve_name`, deterministic start digit, two-digit cap. The backend drops
   its digit selection.
4. **dotNS claimed with a lite-ring proof, after step 2.** One lite name per
   alias, the owner chat-key update path, and the `AliasRegistration` backfill.
   Runtime change on Asset Hub, routed through `DotnsRootGateway` if the dotns
   branch has landed. Promote `AccountNames` to authoritative for gateway names
   here too.
5. **Vouchers** as `Voucher(IssuerId)`. This is a runtime change on People.
6. **Game self-invite** for users who are already lite people. Narrow the ticket
   pool.
7. **A paid path, if product wants one.** Point ineligible clients at
   `register_with_fee`. After step 4 this needs no backend at all.
