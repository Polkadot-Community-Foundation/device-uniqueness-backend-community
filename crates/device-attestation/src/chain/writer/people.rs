// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use chain_types::{PeopleConfig, PeopleExtrinsicParamsBuilder};
use sqlx::PgPool;
use subxt::{dynamic::Value, tx::DynamicPayload, utils::AccountId32};
use time::OffsetDateTime;

use super::{
    engine::{finalize, parse_candidate, Cx, UNFUNDED_PARK_BACKOFF_SECS},
    error::{Op, WriterError},
    events::{check_proxied_call, item_results},
    lane::{observe_defer, park_until, row_backoff, Gate, Lane, Outcome},
    link::PeopleLink,
    observe::record_submit_outcome,
    tx::{build_registration_batch_tx, build_registration_tx},
};
use crate::chain::{
    lease,
    outbox::{self, Guard, Reservation},
    people::PeopleChain,
};

pub(super) struct People;

impl Lane for People {
    type Link = PeopleLink;
    type Chain = PeopleChain;
    type Ctx = ();

    const NAME: &'static str = "people";
    const OWNED_ELSEWHERE: &'static str = "username owned by another account";
    const RECONCILED: &'static str = "reconcile: not yet on-chain, re-queued";
    const NONCE_FETCH: &'static str = "nonce fetch";

    fn attempt(r: &Reservation) -> i32 {
        r.attempt
    }

    async fn claim(pool: &PgPool, limit: i64) -> Result<Vec<Reservation>, sqlx::Error> {
        outbox::claim_due(pool, limit).await
    }

    async fn submitting(pool: &PgPool) -> Result<Vec<Reservation>, sqlx::Error> {
        outbox::submitting(pool).await
    }

    fn gate(r: &Reservation, _ctx: (), _now: i64) -> Result<[u8; 32], Gate> {
        parse_candidate(r)
    }

    fn tx(
        rows: &[(&Reservation, [u8; 32])],
        proxy_for: Option<&[u8; 32]>,
    ) -> DynamicPayload<Vec<Value>> {
        match rows {
            [(r, candidate)] => build_registration_tx(r, candidate, proxy_for),
            _ => build_registration_batch_tx(rows, proxy_for),
        }
    }

    async fn account_nonce(chain: &PeopleChain, signer: &AccountId32) -> Result<u64> {
        chain.next_nonce(signer).await
    }

    async fn submit_one(
        cx: &Cx<'_>,
        chain: &PeopleChain,
        nonce: u64,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> Result<()> {
        let signed = sign(cx, chain, nonce, &[(r, candidate)]).await?;
        let tx_hash = format!("{:?}", signed.hash());
        mark(cx, r, &tx_hash, nonce).await?;
        tracing::info!(id = r.id, username = %r.full_username, nonce, tx = %tx_hash, "submitting registration");

        let (events, metadata) = finalize(cx, signed.submit_and_watch().await?).await?;
        check_proxied_call(&events, &metadata)
    }

    async fn submit_batch(
        cx: &Cx<'_>,
        chain: &PeopleChain,
        nonce: u64,
        rows: &[(&Reservation, [u8; 32])],
    ) -> Result<Vec<Result<(), String>>> {
        let signed = sign(cx, chain, nonce, rows).await?;
        let tx_hash = format!("{:?}", signed.hash());
        for (r, _) in rows {
            mark(cx, r, &tx_hash, nonce).await?;
        }
        tracing::info!(
            batch = rows.len(),
            nonce,
            tx = %tx_hash,
            "submitting registration batch"
        );
        metrics::histogram!("dub_chain_batch_items", "lane" => Self::NAME)
            .record(rows.len() as f64);

        let (events, metadata) = finalize(cx, signed.submit_and_watch().await?).await?;
        check_proxied_call(&events, &metadata)?;
        item_results(&events, &metadata)
    }

    async fn record(
        pool: &PgPool,
        guard: &Guard,
        r: &Reservation,
        outcome: Outcome<'_>,
    ) -> Result<(), WriterError> {
        match outcome {
            Outcome::Landed | Outcome::Observed => {
                let mut tx = pool.begin().await?;
                if !lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch).await? {
                    return Err(WriterError::LeaseLost(Op::Landing));
                }
                if !outbox::mark_assigned(&mut *tx, guard, r.id).await? {
                    return Err(WriterError::LeaseLost(Op::Landing));
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
                    return Err(WriterError::LeaseLost(Op::Retrying));
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
                    return Err(WriterError::LeaseLost(Op::Parking));
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
                    return Err(WriterError::LeaseLost(Op::Deferring));
                }
                observe_defer(Self::NAME, r, until, reason, cause);
            }
            Outcome::Failed(reason) | Outcome::Expired(reason) => {
                let mut tx = pool.begin().await?;
                if !lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch).await? {
                    return Err(WriterError::LeaseLost(Op::Failing));
                }
                if !outbox::mark_failed(&mut *tx, guard, r.id, reason).await? {
                    return Err(WriterError::LeaseLost(Op::Failing));
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

async fn sign(
    cx: &Cx<'_>,
    chain: &PeopleChain,
    nonce: u64,
    rows: &[(&Reservation, [u8; 32])],
) -> Result<
    subxt::tx::SubmittableTransaction<
        PeopleConfig,
        subxt::client::OnlineClientAtBlockImpl<PeopleConfig>,
    >,
> {
    let payload = People::tx(rows, cx.proxy_for.as_ref());
    let params = PeopleExtrinsicParamsBuilder::new().nonce(nonce).build();
    let mut tx_client = chain.online().tx().await?;
    Ok(tx_client.create_signed(&payload, cx.signer, params).await?)
}

async fn mark(cx: &Cx<'_>, r: &Reservation, tx_hash: &str, nonce: u64) -> Result<(), WriterError> {
    if !outbox::mark_submitting(
        cx.pool,
        cx.guard,
        r.id,
        tx_hash,
        nonce as i64,
        r.attempt + 1,
    )
    .await?
    {
        return Err(WriterError::LeaseLost(Op::Submitting));
    }
    Ok(())
}
