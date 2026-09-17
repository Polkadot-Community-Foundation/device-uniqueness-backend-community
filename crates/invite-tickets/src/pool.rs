// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use anyhow::Context as _;
use chain_client::WriterSigner;
use sqlx::PgPool;
use subxt::utils::AccountId32;

use crate::chain::PeopleChain;
use crate::sign::{self, TicketKeypair};
use crate::tickets::{self, Dim, Network};

/// Advisory lock key for the tick guard (stable, service-specific).
/// Public but hidden: the live-Postgres suite (`tests/pool_live_pg.rs`) probes
/// the same key from a second connection; not part of the crate's API.
#[doc(hidden)]
pub const POOL_LOCK_KEY: i64 = 0x1417_1CE7_0001;

/// Pool maintainer tunables (legacy defaults; all env-overridable).
#[derive(Debug, Clone)]
pub struct PoolTuning {
    /// Sleep between ticks.
    pub interval: Duration,
    /// Target `available` count per pool.
    pub target: i64,
    /// Max tickets per submitted batch.
    pub batch_max: u16,
    /// Budget for one batch's submission + finalization.
    pub finalize_timeout: Duration,
}

impl Default for PoolTuning {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(6),
            target: 10_000,
            batch_max: 100,
            finalize_timeout: Duration::from_secs(60),
        }
    }
}

pub use chain_client::settle_batch_size;

/// How many tickets one tick should submit: the shortfall against `target`,
/// capped by the current AIMD `batch_size`. Returns 0 when the pool is already
/// at (or above) target — the tick submits nothing.
pub fn plan_refill(available: i64, target: i64, batch_size: u16) -> u16 {
    let needed = target.saturating_sub(available);
    if needed <= 0 {
        return 0;
    }
    u16::try_from(needed).unwrap_or(u16::MAX).min(batch_size)
}

/// Whether the generated keypair at `index` was accepted on chain — the
/// positional `force_batch` contract: `items[i]` reports the i-th call, and a
/// missing entry means not accepted (only accepted tickets may be inserted).
pub fn item_accepted(items: &[bool], index: usize) -> bool {
    items.get(index).copied() == Some(true)
}

/// The signing identity the maintainer submits with.
pub struct InviterIdentity {
    /// Transaction signer (the inviter itself, or its proxy delegate).
    pub signer: WriterSigner,
    /// The inviter account whose quota funds tickets — stamped into rows, and
    /// the account the chain must see as the caller.
    pub inviter: AccountId32,
    /// The inviter SS58 string as configured (stamped into rows verbatim).
    pub inviter_ss58: String,
}

/// One maintenance pass over one pool. Returns the number of tickets added.
///
/// Chain finalization can take minutes; no DB transaction is held across it —
/// the only DB writes are the post-finalization inserts.
pub async fn tick_pool(
    pool: &PgPool,
    chain: &PeopleChain,
    identity: &InviterIdentity,
    dim: Dim,
    network: Network,
    tuning: &PoolTuning,
    batch_size: u16,
) -> anyhow::Result<(u16, u16)> {
    let available = tickets::count_available(pool, dim, network)
        .await
        .context("counting available tickets")?;
    metrics::gauge!("dub_invite_pool_depth", "dim" => dim.as_str()).set(available as f64);
    // Read before the early return that skips a full pool: that is exactly when
    // nobody is watching and the quota drains unnoticed.
    match chain.available_invites(dim, &identity.inviter).await {
        Ok(invites) => {
            metrics::gauge!("dub_inviter_available_invites", "dim" => dim.as_str())
                .set(invites as f64);
        }
        Err(error) => {
            tracing::warn!(dim = dim.as_str(), %error, "reading available invites failed");
        }
    }
    tracing::debug!(
        dim = dim.as_str(),
        network = network.as_str(),
        available,
        target = tuning.target,
        "pool status"
    );
    let size = plan_refill(available, tuning.target, batch_size);
    if size == 0 {
        return Ok((0, batch_size));
    }

    let generated: Vec<(TicketKeypair, [u8; 32])> = (0..size)
        .map(|_| {
            let seed = sign::generate_seed();
            let keypair = TicketKeypair::from_stored_secret(&seed).expect("fresh seed is valid");
            (keypair, seed)
        })
        .collect();
    let accounts: Vec<AccountId32> = generated
        .iter()
        .map(|(keypair, _)| AccountId32(keypair.public_bytes()))
        .collect();

    let proxy_for = identity.signer.proxy_for(identity.inviter);
    let finalized = tokio::time::timeout(
        tuning.finalize_timeout,
        chain.submit_ticket_batch(&accounts, dim, &identity.signer, proxy_for.as_ref()),
    )
    .await
    .context("batch finalization timed out")??;

    // Insert exactly the accepted items; everything else is discarded with
    // its keypair (the seeds drop with `generated`).
    let mut inserted = 0u16;
    for (index, (keypair, seed)) in generated.iter().enumerate() {
        if !item_accepted(&finalized.items, index) {
            continue;
        }
        tickets::insert_available(
            pool,
            &keypair.public_bytes(),
            seed,
            dim,
            network,
            &identity.inviter_ss58,
        )
        .await
        .context("inserting registered ticket")?;
        inserted += 1;
    }
    let failed = size - inserted;
    record_submit_outcome("ok", inserted);
    // Per-item failures are terminal: `Utility.force_batch` already executed
    // the batch, and the rejected items' keypairs are discarded unrecoverably.
    record_submit_outcome("terminal", failed);
    tracing::info!(
        dim = dim.as_str(),
        network = network.as_str(),
        block = %finalized.block_hash,
        submitted = size,
        registered = inserted,
        failed,
        "ticket batch finalized"
    );
    // A batch where every item failed did not make progress — throttle it
    // like a whole-batch failure instead of growing.
    Ok((
        inserted,
        settle_batch_size(batch_size, tuning.batch_max, inserted > 0),
    ))
}

/// Run the maintainer loop forever: each tick serves every configured pool
/// sequentially (one nonce lane — never two submissions in flight), guarded
/// by the advisory lock.
pub async fn run_loop(
    pool: PgPool,
    chain: PeopleChain,
    identity: InviterIdentity,
    dims: Vec<Dim>,
    network: Network,
    tuning: PoolTuning,
) -> anyhow::Result<()> {
    let mut batch_sizes: Vec<(Dim, u16)> =
        dims.iter().map(|dim| (*dim, tuning.batch_max)).collect();
    loop {
        match acquire_tick_lock(&pool).await {
            Ok(Some(guard)) => {
                for (dim, batch_size) in &mut batch_sizes {
                    match tick_pool(
                        &pool,
                        &chain,
                        &identity,
                        *dim,
                        network,
                        &tuning,
                        *batch_size,
                    )
                    .await
                    {
                        Ok((_, next_size)) => *batch_size = next_size,
                        Err(err) => {
                            let throttled = settle_batch_size(*batch_size, tuning.batch_max, false);
                            // Nothing was registered and the next tick tries
                            // again: a retry, not a terminal outcome.
                            record_submit_outcome("retry", 1);
                            tracing::warn!(
                                dim = dim.as_str(),
                                error = ?err,
                                batch_from = *batch_size,
                                batch_to = throttled,
                                "pool tick failed; keypairs discarded, batch throttled"
                            );
                            *batch_size = throttled;
                        }
                    }
                }
                drop(guard);
            }
            Ok(None) => {
                tracing::warn!("another maintainer instance holds the pool lock; skipping tick");
            }
            Err(err) => {
                tracing::warn!(error = ?err, "could not acquire pool lock; skipping tick");
            }
        }
        record_inviter_balance(&chain, &identity).await;
        tokio::time::sleep(tuning.interval).await;
    }
}

/// Outcomes [`record_submit_outcome`] can emit, for the zero-init below.
const SUBMIT_OUTCOMES: [&str; 3] = ["ok", "retry", "terminal"];

/// Count ticket-registration outcomes on the shared `dub_chain_submit_total`
/// family, under this service's own lane. `count` is per item for a finalized
/// batch and `1` for a failed tick, so it is bounded by the batch size.
fn record_submit_outcome(outcome: &'static str, count: u16) {
    if count == 0 {
        return;
    }
    metrics::counter!("dub_chain_submit_total", "lane" => "invite", "outcome" => outcome)
        .increment(u64::from(count));
}

/// Register the counters at zero, so a healthy pool reads as flat zeros rather
/// than as an absent series indistinguishable from a dead process.
fn zero_init_submit_outcomes() {
    for outcome in SUBMIT_OUTCOMES {
        metrics::counter!("dub_chain_submit_total", "lane" => "invite", "outcome" => outcome)
            .absolute(0);
    }
}

/// Sample the fee-paying account's balance once per tick, on the family the
/// device-attestation writer also reports to — `role` is what separates the budgets.
/// Best-effort: a failed read must not stop the pool.
async fn record_inviter_balance(chain: &PeopleChain, identity: &InviterIdentity) {
    let account = AccountId32(identity.signer.public_bytes());
    match chain.free_balance(&account).await {
        Ok(balance) => {
            metrics::gauge!(
                "dub_account_free_balance_planck",
                "role" => "inviter",
                "chain" => "people"
            )
            .set(balance as f64);
        }
        Err(error) => {
            tracing::warn!(%error, "reading the inviter signer balance failed");
        }
    }
}

/// A held advisory lock: released when the connection drops back to the pool.
struct TickLock {
    conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
}

impl TickLock {
    async fn release(mut self) {
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(POOL_LOCK_KEY)
            .execute(&mut *self.conn)
            .await;
    }
}

/// Try to take the tick lock on a dedicated connection; `None` = held elsewhere.
/// Public but hidden: exercised by `tests/pool_live_pg.rs`; not crate API.
#[doc(hidden)]
pub async fn acquire_tick_lock(pool: &PgPool) -> anyhow::Result<Option<TickGuard>> {
    let mut conn = pool.acquire().await.context("acquiring lock connection")?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(POOL_LOCK_KEY)
        .fetch_one(&mut *conn)
        .await
        .context("taking advisory lock")?;
    if locked {
        Ok(Some(TickGuard {
            lock: Some(TickLock { conn }),
        }))
    } else {
        Ok(None)
    }
}

/// Drop-guard that releases the advisory lock without blocking `Drop`.
/// Public but hidden: returned by [`acquire_tick_lock`] for the live-PG suite.
#[doc(hidden)]
pub struct TickGuard {
    lock: Option<TickLock>,
}

impl Drop for TickGuard {
    fn drop(&mut self) {
        if let Some(lock) = self.lock.take() {
            tokio::spawn(lock.release());
        }
    }
}

/// Maintainer configuration, loaded from the environment (independent of the
/// api bin's [`crate::Config`] — the maintainer holds the inviter secret and
/// no JWT material; the api holds JWT material and no secret).
#[derive(Clone)]
pub struct MaintainerConfig {
    /// Postgres connection string (invite-tickets' own DB).
    pub database_url: String,
    pub people_rpc_url: String,
    pub network: Network,
    /// Inviter whose quota funds tickets; stamped into rows.
    pub inviter_address: String,
    /// Secret of the hot inviter signing key (SURI or raw 64-byte hex). A key
    /// whose account is not `inviter_address` proxies for it — see
    /// [`chain_client::WriterSigner::proxy_for`].
    pub signer_secret: String,
    pub dims: Vec<Dim>,
    pub tuning: PoolTuning,
}

/// The inviter signing secret (and the DB password inside `database_url`) must
/// never reach logs, spans, or error output — a `{:?}` of the config anywhere
/// would otherwise leak them, so `Debug` is implemented by hand.
impl std::fmt::Debug for MaintainerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaintainerConfig")
            .field("database_url", &"<redacted>")
            .field("people_rpc_url", &self.people_rpc_url)
            .field("network", &self.network)
            .field("inviter_address", &self.inviter_address)
            .field("signer_secret", &"<redacted>")
            .field("dims", &self.dims)
            .field("tuning", &self.tuning)
            .finish()
    }
}

impl MaintainerConfig {
    /// Read and validate maintainer configuration from the environment.
    ///
    /// Fails (rather than defaulting) for `DATABASE_URL`, `PEOPLE_RPC_URL`,
    /// `PEOPLE_NETWORK`, `INVITER_ADDRESS`, and `INVITER_SIGNER_SURI`.
    pub fn from_env() -> anyhow::Result<Self> {
        use std::str::FromStr as _;

        // Namespaced: this worker shares its sibling API's database, and a bare
        // DATABASE_URL would mean three different instances across the workspace.
        let database_url = http_common::config::required_var("INVITE_TICKETS_DATABASE_URL")?;
        let people_rpc_url = required_env("PEOPLE_RPC_URL")?;
        let network_raw = required_env("PEOPLE_NETWORK")?;
        let network = Network::from_str(&network_raw)
            .map_err(|()| anyhow::anyhow!("PEOPLE_NETWORK must be westend2|paseo|polkadot"))?;

        let inviter_address = required_env("INVITER_ADDRESS")?;
        AccountId32::from_str(&inviter_address)
            .map_err(|e| anyhow::anyhow!("INVITER_ADDRESS is not valid SS58: {e}"))?;
        let signer_secret = required_env("INVITER_SIGNER_SURI")?;

        let dims_raw = std::env::var("POOL_DIMS").unwrap_or_else(|_| "Game,ProofOfInk".to_string());
        let dims = parse_pool_dims(&dims_raw)?;

        let interval_secs = env_bounded_u64("POOL_INTERVAL_SECS", 6, 1, 86_400)?;
        let target = env_bounded_u64("POOL_TARGET_SIZE", 10_000, 1, 10_000_000)?;
        let batch_max = env_bounded_u64("POOL_BATCH_MAX", 100, 1, 1_000)?;
        let finalize_secs = env_bounded_u64("POOL_FINALIZE_SECS", 60, 1, 86_400)?;

        Ok(Self {
            database_url,
            people_rpc_url,
            network,
            inviter_address,
            signer_secret,
            dims,
            tuning: PoolTuning {
                interval: Duration::from_secs(interval_secs),
                target: i64::try_from(target).context("POOL_TARGET_SIZE is too large")?,
                batch_max: u16::try_from(batch_max).context("POOL_BATCH_MAX is too large")?,
                finalize_timeout: Duration::from_secs(finalize_secs),
            },
        })
    }
}

/// The maintainer's dependency probe, published as readiness gauges. Wider than
/// `invite-tickets-api`'s: registering ticket keys needs the People Chain too.
async fn readiness(pool: PgPool, chain: PeopleChain) -> http_common::health::Readiness {
    if let Err(error) = sqlx::query("SELECT 1").execute(&pool).await {
        tracing::warn!(error = ?error, "readiness check failed: database unavailable");
        return Err("db");
    }
    if let Err(error) = chain.health().await {
        tracing::warn!(error = ?error, "readiness check failed: People Chain unavailable");
        return Err("chain");
    }
    Ok(&["db", "chain"])
}

/// Connect and run the maintainer until fatal error (the process is expected
/// to be supervised and restarted).
pub async fn run(config: MaintainerConfig) -> anyhow::Result<()> {
    use std::str::FromStr as _;

    let signer = WriterSigner::from_secret(&config.signer_secret)?;
    let configured_inviter = AccountId32::from_str(&config.inviter_address)
        .context("parsing validated INVITER_ADDRESS")?;
    let mode = if signer.proxy_for(configured_inviter).is_some() {
        "proxy"
    } else {
        "direct"
    };

    let pool = crate::db::connect(&config.database_url).await?;
    let chain = PeopleChain::connect(&config.people_rpc_url).await?;
    tracing::info!(
        people_rpc = %config.people_rpc_url,
        network = config.network.as_str(),
        inviter = %config.inviter_address,
        signer = %hex::encode(signer.public_bytes()),
        mode,
        dims = ?config.dims,
        target = config.tuning.target,
        "invite-tickets-pool starting"
    );
    http_common::metrics::spawn_readiness_probe(
        "invite-tickets-pool",
        (pool.clone(), chain.clone()),
        |(p, c)| readiness(p, c),
    );

    let identity = InviterIdentity {
        signer,
        inviter: configured_inviter,
        inviter_ss58: config.inviter_address.clone(),
    };
    zero_init_submit_outcomes();
    run_loop(
        pool,
        chain,
        identity,
        config.dims.clone(),
        config.network,
        config.tuning.clone(),
    )
    .await
}

/// Parse the `POOL_DIMS` value: comma-separated DIM names, whitespace-tolerant,
/// empty entries skipped. Errors on an unknown DIM or when nothing remains.
fn parse_pool_dims(raw: &str) -> anyhow::Result<Vec<Dim>> {
    use std::str::FromStr as _;

    let dims: Vec<Dim> = raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            Dim::from_str(part)
                .map_err(|()| anyhow::anyhow!("POOL_DIMS entries must be Game|ProofOfInk"))
        })
        .collect::<anyhow::Result<_>>()?;
    if dims.is_empty() {
        anyhow::bail!("POOL_DIMS must name at least one DIM");
    }
    Ok(dims)
}

fn required_env(key: &'static str) -> anyhow::Result<String> {
    let raw =
        std::env::var(key).map_err(|_| anyhow::anyhow!("required env var {key} is not set"))?;
    let value = raw.trim();
    if value.is_empty() {
        anyhow::bail!("env var {key} must not be empty");
    }
    Ok(value.to_string())
}

fn env_bounded_u64(key: &'static str, default: u64, min: u64, max: u64) -> anyhow::Result<u64> {
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    let value: u64 = raw
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("env var {key} is not a number: {e}"))?;
    if !(min..=max).contains(&value) {
        anyhow::bail!("env var {key} must be within {min}..={max}, got {value}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{item_accepted, parse_pool_dims, plan_refill, settle_batch_size};
    use crate::tickets::Dim;

    #[test]
    fn grows_by_one_on_success_up_to_max() {
        assert_eq!(settle_batch_size(50, 100, true), 51);
        assert_eq!(settle_batch_size(100, 100, true), 100);
        assert_eq!(settle_batch_size(99, 100, true), 100);
    }

    #[test]
    fn halves_on_failure_with_floor_one() {
        assert_eq!(settle_batch_size(100, 100, false), 50);
        assert_eq!(settle_batch_size(3, 100, false), 1);
        assert_eq!(settle_batch_size(1, 100, false), 1);
    }

    #[test]
    fn plan_refill_caps_shortfall_by_batch_size() {
        assert_eq!(plan_refill(9_950, 10_000, 100), 50);
        assert_eq!(plan_refill(0, 10_000, 100), 100);
        assert_eq!(plan_refill(9_999, 10_000, 100), 1);
    }

    #[test]
    fn plan_refill_full_or_overfull_pool_needs_nothing() {
        assert_eq!(plan_refill(10_000, 10_000, 100), 0);
        assert_eq!(plan_refill(15_000, 10_000, 100), 0);
        assert_eq!(plan_refill(i64::MAX, 10_000, 100), 0);
    }

    #[test]
    fn plan_refill_saturates_on_extreme_shortfall() {
        assert_eq!(plan_refill(i64::MIN, i64::MAX, 100), 100);
        assert_eq!(plan_refill(0, i64::MAX, u16::MAX), u16::MAX);
    }

    #[test]
    fn item_accepted_reads_the_positional_outcome() {
        let items = [true, false, true];
        assert!(item_accepted(&items, 0));
        assert!(!item_accepted(&items, 1));
        assert!(item_accepted(&items, 2));
    }

    #[test]
    fn item_accepted_missing_entry_means_not_accepted() {
        assert!(!item_accepted(&[true], 1));
        assert!(!item_accepted(&[], 0));
    }

    #[test]
    fn parse_pool_dims_accepts_single_and_multi() {
        assert_eq!(
            parse_pool_dims("Game").expect("single dim"),
            vec![Dim::Game]
        );
        assert_eq!(
            parse_pool_dims("Game,ProofOfInk").expect("both dims"),
            vec![Dim::Game, Dim::ProofOfInk]
        );
    }

    #[test]
    fn parse_pool_dims_tolerates_whitespace_and_empty_entries() {
        assert_eq!(
            parse_pool_dims(" Game , ProofOfInk ").expect("trimmed"),
            vec![Dim::Game, Dim::ProofOfInk]
        );
        assert_eq!(
            parse_pool_dims("Game,,ProofOfInk,").expect("empty entries skipped"),
            vec![Dim::Game, Dim::ProofOfInk]
        );
    }

    #[test]
    fn parse_pool_dims_empty_input_is_an_error() {
        for raw in ["", "  ", ",,"] {
            let err = parse_pool_dims(raw).expect_err("no dims");
            assert!(err.to_string().contains("POOL_DIMS"), "got: {err}");
        }
    }

    #[test]
    fn parse_pool_dims_unknown_dim_is_an_error() {
        let err = parse_pool_dims("Game,Bogus").expect_err("unknown dim");
        assert!(err.to_string().contains("POOL_DIMS"), "got: {err}");
    }

    #[test]
    fn debug_output_redacts_signer_secret_and_db_password() {
        let config = super::MaintainerConfig {
            database_url: "postgres://invite:s3cret-db-pw@localhost/invite".to_string(),
            people_rpc_url: "wss://rpc.example".to_string(),
            network: crate::tickets::Network::Paseo,
            inviter_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            signer_secret: "s3cret-inviter-suri".to_string(),
            dims: vec![Dim::Game],
            tuning: super::PoolTuning::default(),
        };
        let dump = format!("{config:?}");
        assert!(!dump.contains("s3cret-inviter-suri"));
        assert!(!dump.contains("s3cret-db-pw"));
        assert!(dump.contains("<redacted>"));
        assert!(dump.contains("wss://rpc.example"));
    }
}
