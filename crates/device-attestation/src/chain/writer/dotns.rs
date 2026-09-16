// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;
use chain_types::{AssetHubConfig, AssetHubExtrinsicParamsBuilder};
use sqlx::PgPool;
use subxt::{dynamic::Value, tx::DynamicPayload, utils::AccountId32};
use time::OffsetDateTime;

use super::{
    engine::{finalize, parse_candidate, Cx, UNFUNDED_PARK_BACKOFF_SECS},
    error::{Op, WriterError},
    events::{check_proxied_call, item_results},
    lane::{observe_defer, park_until, row_backoff, Gate, Lane, Outcome},
    link::{DotnsLink, Window},
    observe::record_submit_outcome,
    tx::{build_reserve_name_batch_tx, build_reserve_name_tx},
};
use crate::{
    chain::{
        asset_hub::{AssetHub, ValidityWindow},
        outbox::{self, Guard, Reservation},
    },
    dotns,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DotnsReject {
    NotInLane,
    UnbuildableLabel(String),
    UnbuildableReserved(String),
    BadSignature,
    Expired { signed_at: i64, deadline_secs: u64 },
    FutureDated { signed_at: i64, submittable_at: i64 },
}

pub(super) const MAX_LABEL_BYTES: usize = 32;

pub(super) fn check_dotns_submittable(
    r: &Reservation,
    candidate: &[u8; 32],
    attester: &[u8; 32],
    window: ValidityWindow,
    now: i64,
) -> Result<(), DotnsReject> {
    let (Some(signature), Some(signed_at)) = (&r.dotns_signature, r.dotns_signed_at) else {
        return Err(DotnsReject::NotInLane);
    };

    let label = &r.full_username;
    if label.len() > MAX_LABEL_BYTES {
        return Err(DotnsReject::UnbuildableLabel(format!(
            "lite label is {} bytes, over BaseLabel's {MAX_LABEL_BYTES}",
            label.len()
        )));
    }
    let base = dotns::lite_base(label);
    if base.len() == label.len() {
        return Err(DotnsReject::UnbuildableLabel(
            "lite label has no digit suffix".to_string(),
        ));
    }
    if let Some(reserved) = &r.reserved_username {
        if reserved.len() > MAX_LABEL_BYTES {
            return Err(DotnsReject::UnbuildableReserved(format!(
                "reservedUsername is {} bytes, over BaseLabel's {MAX_LABEL_BYTES}",
                reserved.len()
            )));
        }
    }

    let max_future_skew = i64::try_from(window.max_future_skew_secs).unwrap_or(i64::MAX);
    if signed_at > now.saturating_add(max_future_skew) {
        return Err(DotnsReject::FutureDated {
            signed_at,
            submittable_at: signed_at.saturating_sub(max_future_skew),
        });
    }

    if dotns::reservation_expired(signed_at, window.max_validity_secs, now) {
        return Err(DotnsReject::Expired {
            signed_at,
            deadline_secs: window.max_validity_secs,
        });
    }

    let signed_at = u64::try_from(signed_at).map_err(|_| DotnsReject::BadSignature)?;
    if !dotns::verify_reservation_signature(
        signature,
        candidate,
        attester,
        base.as_bytes(),
        &r.identifier_key,
        r.reserved_username.as_ref().map(|s| s.as_bytes()),
        signed_at,
    ) {
        return Err(DotnsReject::BadSignature);
    }
    Ok(())
}

impl DotnsReject {
    fn gate(self, window: ValidityWindow, now: i64) -> Gate {
        match self {
            DotnsReject::Expired {
                signed_at,
                deadline_secs,
            } => Gate::Expired(format!(
                "reservation signature expired: signed_at={signed_at}, window {deadline_secs}s, \
                 now={now}. Only the client can re-sign."
            )),
            DotnsReject::NotInLane => Gate::Failed("row has no complete dotns block".to_string()),
            DotnsReject::BadSignature => {
                Gate::Failed("dotns signature does not verify".to_string())
            }
            DotnsReject::UnbuildableLabel(why) | DotnsReject::UnbuildableReserved(why) => {
                Gate::Failed(why)
            }
            DotnsReject::FutureDated {
                signed_at,
                submittable_at,
            } => Gate::NotYet {
                until: OffsetDateTime::from_unix_timestamp(submittable_at)
                    .unwrap_or_else(|_| OffsetDateTime::now_utc()),
                reason: format!(
                    "reservation signature is future-dated: signed_at={signed_at}, now={now}, \
                     gateway tolerates {}s of skew. Re-queued until {submittable_at}.",
                    window.max_future_skew_secs
                ),
            },
        }
    }
}

pub(super) struct Dotns;

impl Lane for Dotns {
    type Link = DotnsLink;
    type Chain = AssetHub;
    type Ctx = Window;

    const NAME: &'static str = "dotns";
    const OWNED_ELSEWHERE: &'static str = "lite label reserved by another account";
    const RECONCILED: &'static str = "reconcile: not yet on Asset Hub, re-queued";
    const NONCE_FETCH: &'static str = "asset hub nonce fetch";

    fn attempt(r: &Reservation) -> i32 {
        r.dotns_attempt
    }

    async fn claim(pool: &PgPool, limit: i64) -> Result<Vec<Reservation>, sqlx::Error> {
        outbox::claim_dotns_due(pool, limit).await
    }

    async fn submitting(pool: &PgPool) -> Result<Vec<Reservation>, sqlx::Error> {
        outbox::dotns_submitting(pool).await
    }

    fn gate(r: &Reservation, ctx: Window, now: i64) -> Result<[u8; 32], Gate> {
        let candidate = parse_candidate(r)?;
        match check_dotns_submittable(r, &candidate, &ctx.attester, ctx.window, now) {
            Ok(()) => Ok(candidate),
            Err(reject) => Err(reject.gate(ctx.window, now)),
        }
    }

    fn tx(
        rows: &[(&Reservation, [u8; 32])],
        proxy_for: Option<&[u8; 32]>,
    ) -> DynamicPayload<Vec<Value>> {
        match rows {
            [(r, candidate)] => build_reserve_name_tx(r, candidate, proxy_for),
            _ => build_reserve_name_batch_tx(rows, proxy_for),
        }
    }

    async fn account_nonce(chain: &AssetHub, signer: &AccountId32) -> Result<u64> {
        chain.next_nonce(signer).await
    }

    async fn submit_one(
        cx: &Cx<'_>,
        chain: &AssetHub,
        nonce: u64,
        r: &Reservation,
        candidate: [u8; 32],
    ) -> Result<()> {
        let signed = sign(cx, chain, nonce, &[(r, candidate)]).await?;
        let tx_hash = format!("{:?}", signed.hash());
        mark(cx, r, &tx_hash).await?;
        tracing::info!(
            id = r.id,
            username = %r.full_username,
            nonce,
            tx = %tx_hash,
            "submitting dotns reservation"
        );

        let (events, metadata) = finalize(cx, signed.submit_and_watch().await?).await?;
        check_proxied_call(&events, &metadata)
    }

    async fn submit_batch(
        cx: &Cx<'_>,
        chain: &AssetHub,
        nonce: u64,
        rows: &[(&Reservation, [u8; 32])],
    ) -> Result<Vec<Result<(), String>>> {
        let signed = sign(cx, chain, nonce, rows).await?;
        let tx_hash = format!("{:?}", signed.hash());
        for (r, _) in rows {
            mark(cx, r, &tx_hash).await?;
        }
        tracing::info!(
            batch = rows.len(),
            nonce,
            tx = %tx_hash,
            "submitting dotns reservation batch"
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
                if !outbox::mark_dotns_reserved(pool, guard, r.id).await? {
                    return Err(WriterError::LeaseLost(Op::Landing));
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
                    return Err(WriterError::LeaseLost(Op::Retrying));
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
                    return Err(WriterError::LeaseLost(Op::Parking));
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
                    return Err(WriterError::LeaseLost(Op::Deferring));
                }
                observe_defer(Self::NAME, r, until, reason, cause);
            }
            Outcome::Failed(reason) => {
                if !outbox::mark_dotns_failed(pool, guard, r.id, reason).await? {
                    return Err(WriterError::LeaseLost(Op::Failing));
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
                    return Err(WriterError::LeaseLost(Op::Expiring));
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

async fn sign(
    cx: &Cx<'_>,
    chain: &AssetHub,
    nonce: u64,
    rows: &[(&Reservation, [u8; 32])],
) -> Result<
    subxt::tx::SubmittableTransaction<
        AssetHubConfig,
        subxt::client::OnlineClientAtBlockImpl<AssetHubConfig>,
    >,
> {
    let payload = Dotns::tx(rows, cx.proxy_for.as_ref());
    let params = AssetHubExtrinsicParamsBuilder::new().nonce(nonce).build();
    let at = chain.online().at_current_block().await?;
    Ok(chain_client::create_signed_v4(&at, &payload, cx.signer, params).await?)
}

async fn mark(cx: &Cx<'_>, r: &Reservation, tx_hash: &str) -> Result<(), WriterError> {
    if !outbox::mark_dotns_submitting(cx.pool, cx.guard, r.id, tx_hash, r.dotns_attempt + 1).await?
    {
        return Err(WriterError::LeaseLost(Op::Submitting));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::writer::fixtures::*;

    #[test]
    fn a_fresh_verified_reservation_passes_the_gates() {
        let (r, candidate, attester) = signed_reservation();
        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, BOUNDS, SIGNED_AT + 60),
            Ok(())
        );
    }

    #[test]
    fn a_future_dated_reservation_is_deferred_not_failed() {
        let (r, candidate, attester) = signed_reservation();

        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, BOUNDS, SIGNED_AT - SKEW as i64),
            Ok(())
        );

        assert_eq!(
            check_dotns_submittable(
                &r,
                &candidate,
                &attester,
                BOUNDS,
                SIGNED_AT - SKEW as i64 - 1
            ),
            Err(DotnsReject::FutureDated {
                signed_at: SIGNED_AT,
                submittable_at: SIGNED_AT - SKEW as i64,
            })
        );

        assert_eq!(
            check_dotns_submittable(
                &r,
                &candidate,
                &[99; 32],
                BOUNDS,
                SIGNED_AT - SKEW as i64 - 1
            ),
            Err(DotnsReject::FutureDated {
                signed_at: SIGNED_AT,
                submittable_at: SIGNED_AT - SKEW as i64,
            })
        );

        let absurd = ValidityWindow {
            max_validity_secs: WINDOW,
            max_future_skew_secs: u64::MAX,
        };
        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, absurd, SIGNED_AT),
            Ok(())
        );
    }

    #[test]
    fn each_offline_gate_maps_to_its_own_terminal_state() {
        let (r, candidate, attester) = signed_reservation();

        assert_eq!(
            check_dotns_submittable(
                &r,
                &candidate,
                &attester,
                BOUNDS,
                SIGNED_AT + WINDOW as i64 + 1
            ),
            Err(DotnsReject::Expired {
                signed_at: SIGNED_AT,
                deadline_secs: WINDOW
            })
        );
        assert_eq!(
            check_dotns_submittable(&r, &candidate, &attester, BOUNDS, SIGNED_AT + WINDOW as i64),
            Ok(())
        );

        assert_eq!(
            check_dotns_submittable(&r, &candidate, &[99; 32], BOUNDS, SIGNED_AT),
            Err(DotnsReject::BadSignature)
        );

        assert_eq!(
            check_dotns_submittable(&reservation(), &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::NotInLane)
        );

        let mut no_digits = r.clone();
        no_digits.full_username = "testing".to_string();
        assert!(matches!(
            check_dotns_submittable(&no_digits, &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::UnbuildableLabel(_))
        ));

        let mut long_label = r.clone();
        long_label.full_username = format!("{}.42", "a".repeat(30));
        assert!(matches!(
            check_dotns_submittable(&long_label, &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::UnbuildableLabel(_))
        ));

        let mut long_reserved = r.clone();
        long_reserved.reserved_username = Some("a".repeat(33));
        assert!(matches!(
            check_dotns_submittable(&long_reserved, &candidate, &attester, BOUNDS, SIGNED_AT),
            Err(DotnsReject::UnbuildableReserved(_))
        ));
    }

    #[test]
    fn expiry_is_reported_ahead_of_a_bad_signature() {
        let (mut r, candidate, attester) = signed_reservation();
        r.dotns_signature = Some(vec![0; 64]);
        assert!(matches!(
            check_dotns_submittable(
                &r,
                &candidate,
                &attester,
                BOUNDS,
                SIGNED_AT + WINDOW as i64 + 1
            ),
            Err(DotnsReject::Expired { .. })
        ));
    }
}
