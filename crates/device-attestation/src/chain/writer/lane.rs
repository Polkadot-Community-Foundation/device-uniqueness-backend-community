// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use chain_client::settle_batch_size;
use sqlx::PgPool;
use subxt::{dynamic::Value, tx::DynamicPayload, utils::AccountId32};
use time::OffsetDateTime;

use super::{
    engine::{
        Cx, SIGNER_CONTENTION_BACKOFF_SECS, STALE_NONCE, STALE_NONCE_BACKOFF_SECS,
        UNFUNDED_PARK_BACKOFF_SECS,
    },
    error::WriterError,
    link::Link as ChainLink,
    observe::record_submit_outcome,
};
use crate::chain::{
    outbox::{Guard, Reservation},
    registry::NameRegistry,
};

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
    /// The node refused the submission over a condition that belongs to the
    /// *signer*, not to this row: the nonce it needs is already held by an
    /// earlier transaction still sitting in the pool. Every row behind that one
    /// gets the same refusal until it is included, so spending an attempt here
    /// bills a queue to whoever happened to be standing in it.
    Signer,
    /// The node refused the nonce as already consumed. Also the signer's
    /// condition rather than the row's, but nothing is queued ahead of it: the
    /// next pass re-reads the nonce and goes again.
    StaleNonce,
    /// DotNS signature future-dated, doesn't count as attempt since we just need to wait.
    NotYet,
}

pub(super) trait Lane {
    type Chain: NameRegistry;

    /// The connection this lane runs against, and its park policy.
    type Link: ChainLink<Chain = Self::Chain, Ctx = Self::Ctx>;

    type Ctx: Copy;

    const NAME: &'static str;

    const OWNED_ELSEWHERE: &'static str;

    const RECONCILED: &'static str;

    const NONCE_FETCH: &'static str;

    fn attempt(r: &Reservation) -> i32;

    async fn claim(pool: &PgPool, limit: i64) -> Result<Vec<Reservation>, sqlx::Error>;

    async fn submitting(pool: &PgPool) -> Result<Vec<Reservation>, sqlx::Error>;

    fn gate(r: &Reservation, ctx: Self::Ctx, now: i64) -> Result<[u8; 32], Gate>;

    fn tx(
        rows: &[(&Reservation, [u8; 32])],
        proxy_for: Option<&[u8; 32]>,
    ) -> DynamicPayload<Vec<Value>>;

    async fn account_nonce(chain: &Self::Chain, signer: &AccountId32) -> Result<u64>;

    async fn submit_one(
        cx: &Cx<'_>,
        chain: &Self::Chain,
        nonce: u64,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> Result<()>;

    async fn submit_batch(
        cx: &Cx<'_>,
        chain: &Self::Chain,
        nonce: u64,
        rows: &[(&Reservation, [u8; 32])],
    ) -> Result<Vec<Result<(), String>>>;

    async fn record(
        pool: &PgPool,
        guard: &Guard,
        r: &Reservation,
        outcome: Outcome<'_>,
    ) -> Result<(), WriterError>;
}

pub(super) enum Gate {
    Failed(String),
    Expired(String),
    NotYet {
        until: OffsetDateTime,
        reason: String,
    },
}

impl Gate {
    pub(super) fn outcome(&self) -> Outcome<'_> {
        match self {
            Gate::Failed(reason) => Outcome::Failed(reason),
            Gate::Expired(reason) => Outcome::Expired(reason),
            Gate::NotYet { until, reason } => Outcome::Defer {
                until: *until,
                reason,
                cause: Defer::NotYet,
            },
        }
    }
}

/// Re-queue a row for a failure that belongs to the signer's nonce rather than
/// to the row. Spends no attempt, so a pool jam that outlives the whole retry
/// budget cannot turn a perfectly valid registration terminal.
pub(super) fn signer_defer(reason: &str) -> Outcome<'_> {
    let (backoff, cause) = signer_defer_cause(reason);
    Outcome::Defer {
        until: OffsetDateTime::now_utc() + time::Duration::seconds(backoff),
        reason,
        cause,
    }
}

fn signer_defer_cause(reason: &str) -> (i64, Defer) {
    if reason.contains(STALE_NONCE) {
        (STALE_NONCE_BACKOFF_SECS, Defer::StaleNonce)
    } else {
        (SIGNER_CONTENTION_BACKOFF_SECS, Defer::Signer)
    }
}

/// The shared half of both lanes' [`Outcome::Defer`] arm: what a deferral is
/// counted and said as, given why it was deferred.
pub(super) fn observe_defer(
    lane: &'static str,
    r: &Reservation,
    until: OffsetDateTime,
    reason: &str,
    cause: Defer,
) {
    match cause {
        Defer::Batch => record_submit_outcome(lane, "retry"),
        Defer::Signer => {
            record_submit_outcome(lane, "deferred");
            tracing::warn!(
                lane,
                id = r.id,
                username = %r.full_username,
                until = %until,
                reason,
                "submission deferred without spending an attempt; the signer's nonce is \
                 held by an earlier transaction still in the node's pool"
            );
        }
        Defer::StaleNonce => {
            record_submit_outcome(lane, "deferred");
            tracing::warn!(
                lane,
                id = r.id,
                username = %r.full_username,
                until = %until,
                reason,
                "submission deferred without spending an attempt; the signer's nonce was \
                 already consumed on chain, re-reading it next pass"
            );
        }
        Defer::NotYet => tracing::warn!(
            lane,
            id = r.id,
            username = %r.full_username,
            until = %until,
            reason,
            "dotns reservation deferred; not yet within the gateway's skew bound"
        ),
    }
}

pub(super) fn park_until() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::seconds(UNFUNDED_PARK_BACKOFF_SECS)
}

pub(super) fn row_backoff(attempt: i32) -> time::Duration {
    time::Duration::seconds(2i64.saturating_pow(attempt.clamp(0, 6) as u32))
}

const CEILING_PROBE_RUN: u16 = 20;

#[derive(Debug, Clone, Copy)]
pub(super) struct BatchLane {
    lane: &'static str,
    pub(super) size: u16,
    failures: u16,
    ceiling: Option<u16>,
    clean: u16,
}

impl BatchLane {
    pub(super) fn new(lane: &'static str, size: u16) -> Self {
        let lane = Self {
            lane,
            size,
            failures: 0,
            ceiling: None,
            clean: 0,
        };
        lane.record_size();
        lane
    }

    pub(super) fn succeeded(&mut self, max: u16) {
        self.failures = 0;
        self.clean = self.clean.saturating_add(1);
        if self.clean >= CEILING_PROBE_RUN {
            self.clean = 0;
            self.ceiling = match self.ceiling {
                Some(c) if c < max => Some(c + 1),
                Some(_) => None,
                None => None,
            };
        }
        self.size = settle_batch_size(self.size, self.grow_limit(max), true);
        self.record_size();
    }

    pub(super) fn failed(&mut self, max: u16) -> time::Duration {
        let attempted = self.size;
        self.size = settle_batch_size(self.size, max, false);
        if self.size < attempted {
            self.ceiling = Some(self.ceiling.map_or(attempted, |c| c.min(attempted)));
        }
        self.clean = 0;
        self.failures = self.failures.saturating_add(1);
        metrics::counter!("dub_chain_batch_failed_total", "lane" => self.lane).increment(1);
        self.record_size();
        time::Duration::seconds(2i64.saturating_pow(u32::from(self.failures).clamp(1, 6)))
    }

    fn grow_limit(&self, max: u16) -> u16 {
        match self.ceiling {
            Some(c) => max.min(c.saturating_sub(1)).max(1),
            None => max,
        }
    }

    fn record_size(&self) {
        metrics::gauge!("dub_chain_batch_size", "lane" => self.lane).set(f64::from(self.size));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_nonce_is_told_apart_from_a_pool_jam() {
        let outdated = "Error during transaction progress: The transaction is not valid: \
                        Invalid transaction: Transaction is outdated";
        assert_eq!(
            signer_defer_cause(outdated),
            (STALE_NONCE_BACKOFF_SECS, Defer::StaleNonce)
        );
        assert_eq!(
            signer_defer_cause("Priority is too low: (278 vs 278)"),
            (SIGNER_CONTENTION_BACKOFF_SECS, Defer::Signer)
        );
        assert_eq!(
            signer_defer_cause("finalization timed out"),
            (SIGNER_CONTENTION_BACKOFF_SECS, Defer::Signer)
        );
    }

    #[test]
    fn a_failing_lane_halves_its_batch_and_backs_off_once_per_failure() {
        let mut lane = BatchLane::new("test", 25);
        assert_eq!(lane.size, 25);

        assert_eq!(lane.failed(25), time::Duration::seconds(2));
        assert_eq!(lane.size, 12);
        assert_eq!(lane.failed(25), time::Duration::seconds(4));
        assert_eq!(lane.size, 6);

        lane.succeeded(25);
        assert_eq!(lane.size, 7);
        assert_eq!(lane.failed(25), time::Duration::seconds(2));

        let mut floored = BatchLane::new("test", 25);
        for _ in 0..10 {
            floored.failed(25);
        }
        assert_eq!(floored.size, 1);

        assert_eq!(floored.failed(25), time::Duration::seconds(64));
    }

    #[test]
    fn a_size_that_failed_is_remembered_and_only_re_probed_after_a_clean_run() {
        let mut lane = BatchLane::new("test", 25);

        while lane.size > 1 {
            lane.failed(25);
        }
        assert_eq!(lane.size, 1);
        assert_eq!(lane.ceiling, Some(3));

        lane.succeeded(25);
        assert_eq!(lane.size, 2);
        lane.failed(25);
        assert_eq!(lane.size, 1);
        assert_eq!(
            lane.ceiling,
            Some(2),
            "2 is the smallest size known to fail"
        );

        for _ in 0..(CEILING_PROBE_RUN - 1) {
            lane.succeeded(25);
            assert_eq!(lane.size, 1);
        }

        lane.succeeded(25);
        assert_eq!(lane.ceiling, Some(3));
        assert_eq!(lane.size, 2);

        let mut healthy = BatchLane::new("test", 25);
        healthy.size = 1;
        for _ in 0..5 {
            healthy.succeeded(25);
        }
        assert_eq!(healthy.size, 6);
        assert_eq!(healthy.ceiling, None);
    }
}
