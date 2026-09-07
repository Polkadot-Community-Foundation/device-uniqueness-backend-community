// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use sqlx::PgPool;
use time::OffsetDateTime;

use super::observe::record_submit_outcome;
use super::UNFUNDED_PARK_BACKOFF_SECS;
use crate::chain::lease;
use crate::chain::outbox::{self, Guard, Reservation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome<'a> {
    /// Submitted and on-chain
    Landed,
    /// Candidate appears as owner
    Observed,
    /// Transient failure.
    Retry(&'a str),
    /// The signer cannot pay fees. Backs off without spending an attempt, so a
    /// drained signer never turns a queue terminal.
    Park(&'a str),
    Defer {
        until: OffsetDateTime,
        reason: &'a str,
        cause: Defer,
    },
    /// Permanent failure.
    Failed(&'a str),
    Expired(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Defer {
    /// Batch failure counts as a submission outcome, because a submission was attempted.
    Batch,
    /// DotNS signature future-dated, doesn't count as attempt since we just need to wait.
    NotYet,
}

pub(super) trait Lane {
    /// Metric label: `"people"`, `"dotns"`.
    const NAME: &'static str;

    async fn record(
        pool: &PgPool,
        guard: &Guard,
        r: &Reservation,
        outcome: Outcome<'_>,
    ) -> Result<()>;
}

fn park_until() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::seconds(UNFUNDED_PARK_BACKOFF_SECS)
}

fn row_backoff(attempt: i32) -> time::Duration {
    time::Duration::seconds(2i64.saturating_pow(attempt.clamp(0, 6) as u32))
}

pub(super) struct People;

impl Lane for People {
    const NAME: &'static str = "people";

    async fn record(
        pool: &PgPool,
        guard: &Guard,
        r: &Reservation,
        outcome: Outcome<'_>,
    ) -> Result<()> {
        match outcome {
            Outcome::Landed | Outcome::Observed => {
                // Assignment and device consumption commit together under the lease.
                let mut tx = pool.begin().await?;
                if !lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch).await? {
                    anyhow::bail!("lease lost while assigning");
                }
                if !outbox::mark_assigned(&mut *tx, guard, r.id).await? {
                    anyhow::bail!("lease lost while assigning");
                }
                crate::widevine::store::consume_for_reservation(&mut *tx, r.id).await?;
                tx.commit().await?;
                record_submit_outcome(Self::NAME, "ok");
                let waited = (OffsetDateTime::now_utc() - r.created_at).as_seconds_f64();
                if outcome == Outcome::Landed {
                    metrics::histogram!("dub_registration_latency_seconds").record(waited.max(0.0));
                }
                tracing::info!(
                    id = r.id,
                    username = %r.full_username,
                    waited_secs = waited,
                    observed = outcome == Outcome::Observed,
                    "registration assigned on-chain"
                );
            }
            Outcome::Retry(reason) => {
                let attempt = r.attempt + 1;
                let backoff = row_backoff(attempt);
                let not_before = OffsetDateTime::now_utc() + backoff;
                if !outbox::mark_retry(pool, guard, r.id, not_before, attempt, reason).await? {
                    anyhow::bail!("lease lost while scheduling retry");
                }
                record_submit_outcome(Self::NAME, "retry");
                tracing::warn!(
                    id = r.id,
                    attempt,
                    backoff_secs = backoff.whole_seconds(),
                    reason,
                    "registration retry scheduled"
                );
            }
            Outcome::Park(reason) => {
                if !outbox::mark_retry(pool, guard, r.id, park_until(), r.attempt, reason).await? {
                    anyhow::bail!("lease lost while parking a registration");
                }
                record_submit_outcome(Self::NAME, "parked");
                tracing::warn!(
                    id = r.id,
                    username = %r.full_username,
                    attempt = r.attempt,
                    backoff_secs = UNFUNDED_PARK_BACKOFF_SECS,
                    reason,
                    "registration parked without spending an attempt; the signer cannot pay fees"
                );
            }
            Outcome::Defer {
                until,
                reason,
                cause,
            } => {
                if !outbox::mark_retry(pool, guard, r.id, until, r.attempt, reason).await? {
                    anyhow::bail!("lease lost while re-queueing a failed batch");
                }
                if cause == Defer::Batch {
                    record_submit_outcome(Self::NAME, "retry");
                }
            }
            Outcome::Failed(reason) | Outcome::Expired(reason) => {
                let mut tx = pool.begin().await?;
                // Fence takeover before locking the reservation. A replacement
                // writer cannot acquire this lease until both terminal writes
                // commit or roll back, so it never observes an active claim
                // whose device was released.
                if !lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch).await? {
                    anyhow::bail!("lease lost while failing");
                }
                if !outbox::mark_failed(&mut *tx, guard, r.id, reason).await? {
                    anyhow::bail!("lease lost while failing");
                }
                let released =
                    crate::widevine::store::release_for_reservation(&mut *tx, r.id).await?;
                tx.commit().await?;
                if released {
                    tracing::info!(
                        id = r.id,
                        "widevine device record released with the failed claim"
                    );
                }
                record_submit_outcome(Self::NAME, "terminal");
                tracing::warn!(id = r.id, username = %r.full_username, reason, "registration failed terminally");
            }
        }
        Ok(())
    }
}

pub(super) struct Dotns;

impl Lane for Dotns {
    const NAME: &'static str = "dotns";

    async fn record(
        pool: &PgPool,
        guard: &Guard,
        r: &Reservation,
        outcome: Outcome<'_>,
    ) -> Result<()> {
        match outcome {
            Outcome::Landed | Outcome::Observed => {
                if !outbox::mark_dotns_reserved(pool, guard, r.id).await? {
                    anyhow::bail!("lease lost while reserving dotns name");
                }
                record_submit_outcome(Self::NAME, "ok");
                tracing::info!(id = r.id, username = %r.full_username, "dotns reserved on-chain");
            }
            Outcome::Retry(reason) => {
                let attempt = r.dotns_attempt + 1;
                let backoff = row_backoff(attempt);
                let not_before = OffsetDateTime::now_utc() + backoff;
                if !outbox::mark_dotns_retry(pool, guard, r.id, not_before, attempt, reason).await?
                {
                    anyhow::bail!("lease lost while scheduling dotns retry");
                }
                record_submit_outcome(Self::NAME, "retry");
                tracing::warn!(
                    id = r.id,
                    attempt,
                    backoff_secs = backoff.whole_seconds(),
                    reason,
                    "dotns reservation retry scheduled"
                );
            }
            Outcome::Park(reason) => {
                if !outbox::mark_dotns_retry(
                    pool,
                    guard,
                    r.id,
                    park_until(),
                    r.dotns_attempt,
                    reason,
                )
                .await?
                {
                    anyhow::bail!("lease lost while parking a dotns reservation");
                }
                record_submit_outcome(Self::NAME, "parked");
                tracing::warn!(
                    id = r.id,
                    username = %r.full_username,
                    attempt = r.dotns_attempt,
                    backoff_secs = UNFUNDED_PARK_BACKOFF_SECS,
                    reason,
                    "dotns reservation parked without spending an attempt; \
                     the signer cannot pay fees"
                );
            }
            Outcome::Defer {
                until,
                reason,
                cause,
            } => {
                if !outbox::mark_dotns_retry(pool, guard, r.id, until, r.dotns_attempt, reason)
                    .await?
                {
                    anyhow::bail!("lease lost while re-queueing a failed dotns batch");
                }
                match cause {
                    Defer::Batch => record_submit_outcome(Self::NAME, "retry"),
                    Defer::NotYet => tracing::warn!(
                        id = r.id,
                        username = %r.full_username,
                        until = %until,
                        reason,
                        "dotns reservation deferred; not yet within the gateway's skew bound"
                    ),
                }
            }
            Outcome::Failed(reason) => {
                if !outbox::mark_dotns_failed(pool, guard, r.id, reason).await? {
                    anyhow::bail!("lease lost while failing dotns reservation");
                }
                record_submit_outcome(Self::NAME, "terminal");
                tracing::warn!(
                    id = r.id,
                    username = %r.full_username,
                    reason,
                    "dotns reservation failed terminally; the People registration is unaffected"
                );
            }
            Outcome::Expired(reason) => {
                if !outbox::mark_dotns_expired(pool, guard, r.id, reason).await? {
                    anyhow::bail!("lease lost while expiring dotns reservation");
                }
                record_submit_outcome(Self::NAME, "terminal");
                tracing::warn!(
                    id = r.id,
                    username = %r.full_username,
                    reason,
                    "dotns reservation signature expired before submission"
                );
            }
        }
        Ok(())
    }
}
