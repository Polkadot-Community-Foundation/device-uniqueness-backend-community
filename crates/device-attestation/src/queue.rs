// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::VecDeque;
use std::time::Duration;

use axum::extract::State;
use axum::Json;
use http_common::AuthSubject;
use serde::Serialize;
use sqlx::{PgPool, Row as _};
use utoipa::ToSchema;

use crate::chain::{lease, PeopleChain};
use crate::http::state::AppState;
use crate::usernames::error::{UsernamesError, UsernamesResult};

/// Queue promotions per advancer iteration (the spec's four slots).
pub const SLOTS_PER_ITERATION: usize = 4;

/// Planck per DOT (10-decimal token, shared by Polkadot and Paseo).
const PLANCK_PER_DOT: u128 = 10_000_000_000;

/// The priority group for a free balance in planck: `<10` DOT → 1 (lowest),
/// `≥10` → 2, `≥100` → 3, `≥1000` → 4 (highest).
pub fn group_for_balance(planck: u128) -> u8 {
    match planck {
        p if p >= 1000 * PLANCK_PER_DOT => 4,
        p if p >= 100 * PLANCK_PER_DOT => 3,
        p if p >= 10 * PLANCK_PER_DOT => 2,
        _ => 1,
    }
}

/// Budget for the intake-path balance read: a hung RPC must not hold the
/// claim request open, so past this the claim proceeds as group 1.
const INTAKE_BALANCE_TIMEOUT: Duration = Duration::from_secs(5);

/// The initial group for a claim: the subject's on-chain balance, mapped
/// through [`group_for_balance`]. Fails open to group 1 — a chain hiccup,
/// timeout, or malformed subject must never block intake, only deprioritise
/// it (the next advancer refresh corrects the group).
pub async fn intake_group(chain: &PeopleChain, subject: &str) -> u8 {
    let Some(account) = parse_subject(subject) else {
        tracing::warn!(subject, "queue intake: unparseable subject; using group 1");
        return 1;
    };
    match tokio::time::timeout(INTAKE_BALANCE_TIMEOUT, chain.free_balance(account)).await {
        Ok(Ok(balance)) => group_for_balance(balance),
        Ok(Err(error)) => {
            tracing::warn!(subject, error = %error, "queue intake: balance read failed; using group 1");
            1
        }
        Err(_) => {
            tracing::warn!(
                subject,
                "queue intake: balance read timed out; using group 1"
            );
            1
        }
    }
}

/// The JWT subject as stored (`0x` + 64 hex) decoded to a 32-byte account id.
fn parse_subject(subject: &str) -> Option<[u8; 32]> {
    let hex = subject.strip_prefix("0x")?;
    hex::decode(hex).ok()?.try_into().ok()
}

/// One row of the FIFO queue snapshot (ordered by `(created_at, id)`).
#[derive(Debug, Clone)]
pub struct QueuedEntry {
    pub id: i64,
    /// Queue owner — the stored JWT subject.
    pub account_id: String,
    /// Priority group `1..=4`.
    pub group: u8,
}

/// The current `QUEUED` rows in FIFO order (the drain-simulation input).
pub async fn queued_snapshot(pool: &PgPool) -> Result<Vec<QueuedEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, account_id, queue_group FROM username_reservations \
         WHERE status = 'QUEUED' ORDER BY created_at ASC, id ASC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(QueuedEntry {
                id: row.try_get("id")?,
                account_id: row.try_get("account_id")?,
                group: (row.try_get::<i32, _>("queue_group")?).clamp(1, 4) as u8,
            })
        })
        .collect()
}

/// Where a queued claim lands when the current snapshot drains under the slot
/// rules: its overall pick order and the iteration that picks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainEstimate {
    /// 1-based pick order across the whole drain.
    pub position: u32,
    /// 1-based advancer iteration in which the claim is promoted.
    pub iterations: u32,
}

/// Simulate draining `entries` (FIFO-ordered) and locate `target_id`.
///
/// Exact w.r.t. the spec's slot algebra for the snapshot taken — later
/// arrivals and group changes shift it, hence "estimate". `None` when
/// `target_id` is not in `entries`.
pub fn drain_estimate(entries: &[QueuedEntry], target_id: i64) -> Option<DrainEstimate> {
    let mut by_group: [VecDeque<usize>; 4] = Default::default();
    for (index, entry) in entries.iter().enumerate() {
        by_group[usize::from(entry.group) - 1].push_back(index);
    }

    let mut position = 0u32;
    for iteration in 1..=entries.len() as u32 {
        for slot in 1..=SLOTS_PER_ITERATION {
            let min_group = 5 - slot;
            // Earliest-enqueued among the eligible groups' heads: entries is
            // FIFO-ordered, so the smallest index wins.
            let pick = (min_group..=4)
                .filter_map(|group| by_group[group - 1].front().map(|&index| (index, group)))
                .min_by_key(|&(index, _)| index);
            let Some((index, group)) = pick else { continue };
            by_group[group - 1].pop_front();
            position += 1;
            if entries[index].id == target_id {
                return Some(DrainEstimate {
                    position,
                    iterations: iteration,
                });
            }
        }
    }
    None
}

/// Concurrent in-flight balance reads during a group refresh (bounds one
/// iteration's wall clock to roughly `accounts / 16 × RPC latency`).
const BALANCE_READ_CONCURRENCY: usize = 16;

/// Refresh every queued claim's priority group from its subject's on-chain
/// balance, [`BALANCE_READ_CONCURRENCY`]-wide.
///
/// A failed balance read **keeps the current group**: unlike intake there is a
/// known-good value, and failing open to 1 would demote the whole queue.
pub async fn refresh_groups(pool: &PgPool, chain: &PeopleChain) -> Result<(), sqlx::Error> {
    use futures::StreamExt as _;

    let rows = sqlx::query(
        "SELECT DISTINCT account_id FROM username_reservations WHERE status = 'QUEUED'",
    )
    .fetch_all(pool)
    .await?;
    let accounts: Vec<String> = rows
        .into_iter()
        .map(|row| row.try_get("account_id"))
        .collect::<Result<_, _>>()?;

    let groups: Vec<(String, Option<u8>)> =
        futures::stream::iter(accounts.into_iter().map(|account_id| {
            let chain = chain.clone();
            async move {
                let group = match parse_subject(&account_id) {
                    // Deterministically malformed subjects are group 1 for good.
                    None => Some(1),
                    Some(account) => match chain.free_balance(account).await {
                        Ok(balance) => Some(group_for_balance(balance)),
                        Err(error) => {
                            tracing::warn!(
                                account_id,
                                error = %error,
                                "queue refresh: balance read failed; keeping current group"
                            );
                            None
                        }
                    },
                };
                (account_id, group)
            }
        }))
        .buffer_unordered(BALANCE_READ_CONCURRENCY)
        .collect()
        .await;

    for (account_id, group) in groups {
        let Some(group) = group else { continue };
        sqlx::query(
            "UPDATE username_reservations SET queue_group = $2, updated_at = now() \
             WHERE status = 'QUEUED' AND account_id = $1 AND queue_group <> $2",
        )
        .bind(&account_id)
        .bind(i32::from(group))
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// A claim promoted out of the queue this iteration.
#[derive(Debug)]
pub struct Promoted {
    pub id: i64,
    /// `base.digits` — for logging.
    pub full_username: String,
    /// The winning slot (1..=4).
    pub slot: usize,
}

/// Run one advancer iteration: up to [`SLOTS_PER_ITERATION`] promotions,
/// slot `k` eligible to groups `>= 5 - k`, earliest-enqueued first, each pick
/// removed from the pool before the next slot (the promotion itself removes
/// it: the row leaves `QUEUED`). `FOR UPDATE SKIP LOCKED` keeps promotion
/// exactly-once even if a second advancer ever runs concurrently.
pub async fn advance_iteration(pool: &PgPool) -> Result<Vec<Promoted>, sqlx::Error> {
    let mut promoted = Vec::new();
    for slot in 1..=SLOTS_PER_ITERATION {
        let min_group = (5 - slot) as i32;
        let row = sqlx::query(
            "UPDATE username_reservations SET status = 'RESERVED', updated_at = now() \
             WHERE id = (SELECT id FROM username_reservations \
                         WHERE status = 'QUEUED' AND queue_group >= $1 \
                         ORDER BY created_at ASC, id ASC \
                         LIMIT 1 \
                         FOR UPDATE SKIP LOCKED) \
             RETURNING id, full_username",
        )
        .bind(min_group)
        .fetch_optional(pool)
        .await?;
        if let Some(row) = row {
            promoted.push(Promoted {
                id: row.try_get("id")?,
                full_username: row.try_get("full_username")?,
                slot,
            });
        }
    }
    Ok(promoted)
}

/// The advancer's lease row name. The lease is both the single-instance guard
/// for the `registration-queue` service and its **liveness signal**: the
/// chain-writer reads its freshness to decide between the stranded-queue
/// warning (queue enabled) and the janitor drain (queue disabled).
pub const ADVANCER_LEASE_NAME: &str = "registration-queue-advancer";

/// `registration-queue` service configuration, loaded from the environment.
#[derive(Debug, Clone)]
pub struct AdvancerConfig {
    /// Postgres connection string (shared schema with device-attestation-api).
    pub database_url: String,
    /// People Chain RPC endpoint (balance reads for group refresh).
    pub people_rpc_url: String,
    /// Iteration interval (the spec's "every N seconds").
    pub interval: Duration,
    /// Lease TTL; must comfortably exceed `interval` so a live advancer's
    /// lease never looks expired between iterations.
    pub lease_ttl: Duration,
    pub holder_id: String,
}

impl AdvancerConfig {
    /// Read and validate advancer configuration from the environment
    /// (fail-fast: a malformed value aborts startup, never a silent default).
    pub fn from_env() -> anyhow::Result<Self> {
        // Namespaced: this worker shares its sibling API's database, and a bare
        // DATABASE_URL would mean three different instances across the workspace.
        let database_url = http_common::config::required_var("DEVICE_ATTESTATION_DATABASE_URL")?;
        let interval = Duration::from_secs(env_u64_strict("QUEUE_ADVANCE_INTERVAL_SECS", 6)?);
        let lease_ttl = Duration::from_secs(env_u64_strict("QUEUE_LEASE_TTL_SECS", 30)?);
        validate_cadence(interval, lease_ttl)?;
        Ok(Self {
            database_url,
            people_rpc_url: std::env::var("PEOPLE_RPC_URL")
                .unwrap_or_else(|_| "wss://previewnet.substrate.dev/people".to_string()),
            interval,
            lease_ttl,
            // Unique per boot: in a container the PID is always 1, and equal
            // holder ids would let overlapping instances steal each other's
            // live lease through the "already ours" arm.
            holder_id: match std::env::var("QUEUE_HOLDER_ID") {
                Ok(value) if !value.trim().is_empty() => value,
                _ => format!("queue-{}-{:08x}", std::process::id(), rand::random::<u32>()),
            },
        })
    }
}

/// Validate the advancer's cadence: the longest un-renewed gap is
/// `interval + lease_ttl/3` (the sleep between iterations plus up to one
/// renewal-ticker period since the last in-work renew), so the TTL must
/// exceed *that*, not merely the interval — otherwise a healthy advancer's
/// lease flaps every iteration and the writer's stranded-queue warning (or,
/// queue-disabled, its janitor drain) fires against a live service. A zero
/// interval is rejected too (it would hot-loop against Postgres and the RPC).
fn validate_cadence(interval: Duration, lease_ttl: Duration) -> anyhow::Result<()> {
    anyhow::ensure!(
        interval >= Duration::from_secs(1),
        "QUEUE_ADVANCE_INTERVAL_SECS must be at least 1"
    );
    anyhow::ensure!(
        lease_ttl > interval + lease_ttl / 3,
        "QUEUE_LEASE_TTL_SECS ({ttl}) must exceed QUEUE_ADVANCE_INTERVAL_SECS ({interval}) \
         by more than one renewal period (ttl/3 = {renewal}s): the un-renewed gap between \
         iterations can reach interval + ttl/3, and a lease that expires there makes a \
         healthy advancer look dead every iteration",
        ttl = lease_ttl.as_secs(),
        interval = interval.as_secs(),
        renewal = (lease_ttl / 3).as_secs(),
    );
    Ok(())
}

/// Parse an optional `u64` env var. Unset uses `default`; a set-but-garbage
/// value is a startup error (the fail-fast config rule — a typo like `30s`
/// must stop the process loudly, not silently run on the default).
pub(crate) fn env_u64_strict(key: &'static str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("{key} is invalid ({raw:?}): {e}")),
    }
}

/// Whether the `registration-queue` service is live (its lease is held and
/// unexpired). Purely observational — intake queues on the flag alone; this
/// feeds the writer's stranded-queue warning and tests.
pub async fn advancer_alive(pool: &PgPool) -> Result<bool, sqlx::Error> {
    lease::alive(pool, ADVANCER_LEASE_NAME).await
}

/// Count of `QUEUED` rows stranded behind a dead advancer (lease absent or
/// expired). Always 0 while the advancer is alive — a live queue is draining,
/// not stranded. The chain-writer logs this while the queue is enabled: with
/// intake parking claims regardless of liveness, this warning is the
/// operator's signal that the throttle is holding but nothing is draining.
pub async fn stranded_queued(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT count(*) AS stranded FROM username_reservations \
         WHERE status = 'QUEUED' \
           AND NOT EXISTS (SELECT 1 FROM writer_lease \
                           WHERE name = $1 AND expires_at > now())",
    )
    .bind(ADVANCER_LEASE_NAME)
    .fetch_one(pool)
    .await?;
    row.try_get("stranded")
}

/// The queue-retirement janitor, run by the chain-writer **only while
/// `QUEUE_ENABLED` is off** — with the flag on, draining would bypass the free
/// lane's throttle. Promotes `QUEUED` rows once the advancer's lease has been
/// expired longer than `grace`, the window that lets a live advancer finish a
/// fair drain during the retire sequence. An absent lease drains immediately:
/// no timestamp exists to measure from, and nothing else would promote them.
pub async fn fallback_drain(pool: &PgPool, grace: Duration) -> Result<u64, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE username_reservations SET status = 'RESERVED', updated_at = now() \
         WHERE status = 'QUEUED' \
           AND NOT EXISTS (SELECT 1 FROM writer_lease \
                           WHERE name = $1 \
                             AND expires_at > now() - ($2 * interval '1 second'))",
    )
    .bind(ADVANCER_LEASE_NAME)
    .bind(grace.as_secs() as i64)
    .execute(pool)
    .await?;
    Ok(done.rows_affected())
}

/// The `registration-queue` service loop: hold the advancer lease, then every
/// `interval` renew it, refresh groups, and run one promotion iteration.
///
/// Per-iteration errors are logged and the loop continues; a lost lease drops
/// back to acquisition. If the process dies, claims park as `QUEUED` behind the
/// throttle and the chain-writer raises the stranded-queue warning.
pub async fn run_advancer(pool: PgPool, chain: PeopleChain, config: AdvancerConfig) {
    tracing::info!(
        interval_secs = config.interval.as_secs(),
        holder = %config.holder_id,
        "registration-queue advancer starting"
    );
    http_common::metrics::spawn_readiness_probe(
        "registration-queue",
        (pool.clone(), chain.clone()),
        |(p, c)| crate::http::health::probe(p, c),
    );
    loop {
        let epoch = match lease::try_acquire(
            &pool,
            ADVANCER_LEASE_NAME,
            &config.holder_id,
            config.lease_ttl,
        )
        .await
        {
            Ok(Some(epoch)) => epoch,
            Ok(None) => {
                tracing::info!("advancer lease held by another instance; waiting");
                tokio::time::sleep(config.interval).await;
                continue;
            }
            Err(error) => {
                tracing::warn!(error = %error, "advancer lease acquisition failed");
                tokio::time::sleep(config.interval).await;
                continue;
            }
        };
        tracing::info!(epoch, "acquired advancer lease");

        loop {
            tokio::time::sleep(config.interval).await;
            match lease::renew(
                &pool,
                ADVANCER_LEASE_NAME,
                &config.holder_id,
                epoch,
                config.lease_ttl,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    // Stolen or expired (renew refuses expired leases): the
                    // fallback paths may have observed us dead, so go back
                    // through acquisition for a fresh epoch.
                    tracing::warn!("lost advancer lease; re-acquiring");
                    break;
                }
                Err(error) => {
                    // Can't prove liveness — stop advancing so the fallback
                    // paths take over cleanly, then try to re-acquire.
                    tracing::warn!(error = %error, "advancer lease renewal failed; re-acquiring");
                    break;
                }
            }

            // Keep renewing while the iteration works: a large queue's group
            // refresh can outlast the lease TTL, and letting it lapse
            // mid-iteration would make a healthy advancer look dead — firing
            // the writer's stranded-queue warning (or, queue-disabled, its
            // janitor drain) while we are still promoting.
            let work = async {
                // The refresh is the only chain-dependent step, so it gets a
                // hard deadline: a degraded RPC must not stall *draining*
                // while the fresh lease advertises a healthy queue. On
                // timeout the iteration advances with the current groups
                // (stale priorities for one interval, never a stuck queue).
                match tokio::time::timeout(config.lease_ttl, refresh_groups(&pool, &chain)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(error = %error, "queue group refresh failed");
                    }
                    Err(_) => tracing::warn!(
                        timeout_secs = config.lease_ttl.as_secs(),
                        "queue group refresh timed out; advancing with current groups"
                    ),
                }
                match advance_iteration(&pool).await {
                    Ok(promoted) => {
                        for p in &promoted {
                            tracing::info!(id = p.id, username = %p.full_username, slot = p.slot, "queued claim promoted");
                        }
                    }
                    Err(error) => tracing::warn!(error = %error, "queue advance iteration failed"),
                }
            };
            tokio::pin!(work);
            let mut renew = tokio::time::interval(config.lease_ttl / 3);
            renew.tick().await; // consume the immediate first tick
            let renewed = loop {
                tokio::select! {
                    () = &mut work => break true,
                    _ = renew.tick() => {
                        match lease::renew(
                            &pool,
                            ADVANCER_LEASE_NAME,
                            &config.holder_id,
                            epoch,
                            config.lease_ttl,
                        )
                        .await
                        {
                            Ok(true) => {}
                            Ok(false) | Err(_) => break false,
                        }
                    }
                }
            };
            if !renewed {
                // Abandoning the iteration is safe: refresh updates and slot
                // promotions are independent, idempotent statements.
                tracing::warn!("lost advancer lease mid-iteration; re-acquiring");
                break;
            }
        }
    }
}

/// Queue standing for one claim, as served by `GET /api/v1/registration/queue`
/// and embedded in the claim response's `queue` field.
#[derive(Serialize, ToSchema)]
pub struct QueueStatusResponse {
    /// 1-based position in the drain order of the current queue snapshot.
    #[serde(rename = "queuePosition")]
    #[schema(rename = "queuePosition", example = 17)]
    pub queue_position: u32,
    /// Priority group `1..=4` (4 = highest; raised by topping up the account).
    #[schema(example = 2)]
    pub group: u8,
    /// Advancer iterations until promotion, per the snapshot simulation.
    #[serde(rename = "estimatedIterationsRemaining")]
    #[schema(rename = "estimatedIterationsRemaining", example = 5)]
    pub estimated_iterations_remaining: u32,
}

/// The caller's standing computed against `snapshot`; `None` when the subject
/// has no queued claim (multiple claims resolve to the earliest-enqueued).
pub fn status_in_snapshot(snapshot: &[QueuedEntry], subject: &str) -> Option<QueueStatusResponse> {
    let target = snapshot.iter().find(|entry| entry.account_id == subject)?;
    let estimate = drain_estimate(snapshot, target.id)?;
    Some(QueueStatusResponse {
        queue_position: estimate.position,
        group: target.group,
        estimated_iterations_remaining: estimate.iterations,
    })
}

/// Registration-queue standing for the authenticated account.
#[utoipa::path(
    get,
    path = "/api/v1/registration/queue",
    tag = "Usernames",
    security(("bearer_jwt" = [])),
    description = "Queue standing for the caller's pending username claim. This route exists only \
      on deployments with the registration queue enabled (`QUEUE_ENABLED`); with the queue \
      disabled the path serves the standard plain-text 404. Clients should treat ANY 404 here as \
      \"not (or no longer) queued\" and assume the registration is proceeding — queued claims keep \
      draining even if the queue is later disabled. When an account has several queued claims, the \
      response reports the earliest-enqueued one until it drains.",
    responses(
        (status = 200, description = "The caller's queued claim: position, priority group, and the \
          estimated advancer iterations until it is promoted for on-chain registration.",
         body = QueueStatusResponse,
         example = json!({ "queuePosition": 17, "group": 2, "estimatedIterationsRemaining": 5 })),
        (status = 401, description = "Missing or invalid bearer token.",
         body = serde_json::Value),
        (status = 404, description = "The account has no queued registration (JSON body), or the \
          deployment runs queue-disabled (plain-text body). Either way: stop polling, the claim is \
          proceeding without the queue.",
         body = serde_json::Value,
         example = json!({ "error": "No queue entry found" })),
        (status = 429, description = "Subject rate limit exceeded (with `Retry-After`).",
         body = serde_json::Value)
    )
)]
pub async fn status(
    State(state): State<AppState>,
    auth: AuthSubject,
) -> UsernamesResult<Json<QueueStatusResponse>> {
    // Subject-keyed like the rest of the authenticated usernames surface, but
    // its own bucket: each hit is O(queue) work, and polling here must not
    // eat the claim path's quota.
    let key = format!("/api/v1/registration/queue:{}", auth.subject);
    if let Err(err) = state.limiter.allow(key).await {
        return Err(UsernamesError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        });
    }
    let snapshot = queued_snapshot(&state.pool).await?;
    let status =
        status_in_snapshot(&snapshot, &auth.subject).ok_or(UsernamesError::NoQueueEntry)?;
    Ok(Json(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn group_boundaries_follow_the_spec_thresholds() {
        assert_eq!(group_for_balance(0), 1);
        assert_eq!(group_for_balance(10 * PLANCK_PER_DOT - 1), 1);
        assert_eq!(group_for_balance(10 * PLANCK_PER_DOT), 2);
        assert_eq!(group_for_balance(100 * PLANCK_PER_DOT - 1), 2);
        assert_eq!(group_for_balance(100 * PLANCK_PER_DOT), 3);
        assert_eq!(group_for_balance(1000 * PLANCK_PER_DOT - 1), 3);
        assert_eq!(group_for_balance(1000 * PLANCK_PER_DOT), 4);
        assert_eq!(group_for_balance(u128::MAX), 4);
    }

    #[test]
    fn subject_parses_only_as_0x_hex_32_bytes() {
        assert_eq!(
            parse_subject(&format!("0x{}", "ab".repeat(32))),
            Some([0xab; 32])
        );
        assert_eq!(parse_subject(&"ab".repeat(32)), None);
        assert_eq!(parse_subject("0xabcd"), None);
        assert_eq!(parse_subject("0xzz"), None);
    }

    fn entries(groups: &[u8]) -> Vec<QueuedEntry> {
        groups
            .iter()
            .enumerate()
            .map(|(index, &group)| QueuedEntry {
                id: index as i64 + 1,
                account_id: format!("subject-{index}"),
                group,
            })
            .collect()
    }

    fn drain_order(groups: &[u8]) -> Vec<(i64, u32)> {
        let entries = entries(groups);
        entries
            .iter()
            .map(|entry| {
                let estimate = drain_estimate(&entries, entry.id).expect("entry is queued");
                (estimate.position, (entry.id, estimate.iterations))
            })
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_values()
            .collect()
    }

    #[test]
    fn all_lowest_group_drains_one_per_iteration_via_slot_four() {
        assert_eq!(drain_order(&[1, 1, 1]), [(1, 1), (2, 2), (3, 3)]);
    }

    #[test]
    fn all_highest_group_drains_four_per_iteration_in_fifo_order() {
        assert_eq!(
            drain_order(&[4, 4, 4, 4, 4]),
            [(1, 1), (2, 1), (3, 1), (4, 1), (5, 2)]
        );
    }

    #[test]
    fn slots_pick_earliest_enqueued_among_eligible_groups() {
        assert_eq!(drain_order(&[1, 2, 3, 4]), [(4, 1), (3, 1), (2, 1), (1, 1)]);
    }

    #[test]
    fn empty_eligible_sets_skip_slots_mid_iteration() {
        let entries = entries(&[2, 4]);
        assert_eq!(
            drain_estimate(&entries, 2),
            Some(DrainEstimate {
                position: 1,
                iterations: 1
            })
        );
        assert_eq!(
            drain_estimate(&entries, 1),
            Some(DrainEstimate {
                position: 2,
                iterations: 1
            })
        );
    }

    #[test]
    fn fifo_ties_within_a_group_resolve_by_enqueue_order() {
        assert_eq!(
            drain_order(&[2, 2, 2, 2, 2, 2]),
            [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3), (6, 3)]
        );
    }

    #[test]
    fn a_group_four_flood_cannot_starve_lower_groups_completely() {
        let entries = entries(&[1, 4, 4, 4, 4, 4]);
        assert_eq!(
            drain_estimate(&entries, 1),
            Some(DrainEstimate {
                position: 4,
                iterations: 1
            })
        );
    }

    #[test]
    fn unknown_target_is_none() {
        assert_eq!(drain_estimate(&entries(&[1, 2]), 99), None);
        assert_eq!(drain_estimate(&[], 1), None);
    }

    #[test]
    fn status_resolves_the_subjects_earliest_claim_or_none() {
        let mut snapshot = entries(&[4, 1]);
        snapshot[1].account_id = snapshot[0].account_id.clone();
        let status = status_in_snapshot(&snapshot, "subject-0").expect("queued");
        assert_eq!(status.queue_position, 1);
        assert_eq!(status.group, 4);
        assert!(status_in_snapshot(&snapshot, "subject-1").is_none());
    }

    #[test]
    fn cadence_validation_rejects_flapping_and_hot_loop_configs() {
        let secs = Duration::from_secs;
        assert!(validate_cadence(secs(6), secs(30)).is_ok());
        assert!(validate_cadence(secs(25), secs(30)).is_err());
        assert!(validate_cadence(secs(19), secs(30)).is_ok());
        assert!(validate_cadence(secs(20), secs(30)).is_err());
        assert!(validate_cadence(secs(0), secs(30)).is_err());
    }

    #[test]
    fn strict_env_parsing_fails_loudly_on_garbage() {
        std::env::set_var("QUEUE_TEST_STRICT_GARBAGE", "30s");
        assert!(env_u64_strict("QUEUE_TEST_STRICT_GARBAGE", 30).is_err());
        std::env::set_var("QUEUE_TEST_STRICT_PADDED", " 42 ");
        assert_eq!(env_u64_strict("QUEUE_TEST_STRICT_PADDED", 30).unwrap(), 42);
        assert_eq!(env_u64_strict("QUEUE_TEST_STRICT_UNSET", 30).unwrap(), 30);
    }

    #[test]
    fn queue_status_serializes_the_spec_wire_names() {
        let body = QueueStatusResponse {
            queue_position: 17,
            group: 2,
            estimated_iterations_remaining: 5,
        };
        assert_eq!(
            serde_json::to_value(body).expect("serialize"),
            json!({ "queuePosition": 17, "group": 2, "estimatedIterationsRemaining": 5 })
        );
    }
}
