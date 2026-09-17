// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! PCF fork: settle gateway-minted dotNS names into their owners' `LabelStore`s.
//!
//! Chain-driven: walks `DotnsGateway::AccountNames` (every account the gateway
//! ever minted for, whichever backend submitted it), asks the PoP controller for
//! each account's pending-claim count, and settles as a third party from this
//! writer's signer. A dry run sizes every call so the extrinsic never carries a
//! guessed weight, and a controller revert is skipped rather than retried into a
//! fee. Accounts found settled are remembered by record value, so a later
//! full-name claim re-arms them.

use std::time::{Duration, Instant};

use chain_types::AssetHubExtrinsicParamsBuilder;
use subxt::tx::Payload;

use super::{
    engine::{finalize, Cx, Drain},
    error::WriterError,
    hex_account, Dotns,
};
use crate::chain::{asset_hub::AssetHub, settle};
use crate::config::ConfigError;

/// Settlement configuration (`DOTNS_SETTLE_*`).
#[derive(Debug, Clone)]
pub struct SettleConfig {
    /// Whether the settlement pass runs (`DOTNS_SETTLE_ENABLED`, default on).
    pub enabled: bool,
    /// Cadence of the pass over `DotnsGateway::AccountNames`.
    pub interval: Duration,
    /// `limit` argument of `settlePendingClaims`: claims settled per call.
    pub claim_limit: u64,
    /// Upper bound on settlement submissions in one pass, so a backlog cannot
    /// starve the registration lanes.
    pub max_per_pass: usize,
}

impl SettleConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            enabled: crate::config::env_bool("DOTNS_SETTLE_ENABLED", true)?,
            interval: Duration::from_secs(super::strict("DOTNS_SETTLE_INTERVAL_SECS", 60)?),
            claim_limit: super::strict("DOTNS_SETTLE_CLAIM_LIMIT", 10)?,
            max_per_pass: usize::try_from(super::strict("DOTNS_SETTLE_MAX_PER_PASS", 20)?)
                .map_err(|_| ConfigError::Invalid {
                    key: "DOTNS_SETTLE_MAX_PER_PASS",
                    reason: "must fit a usize".to_string(),
                })?,
        })
    }
}

/// Per-process state of the settlement pass.
pub(super) struct Settlement {
    config: SettleConfig,
    last: Option<Instant>,
    cache: settle::SettledCache,
    /// `true` once `Revive::OriginalAccount` shows the signer mapped (or this
    /// writer mapped it).
    signer_mapped: bool,
    warned_no_dispatcher: bool,
}

impl Settlement {
    pub(super) fn new(config: SettleConfig) -> Self {
        Self {
            config,
            last: None,
            cache: settle::SettledCache::default(),
            signer_mapped: false,
            warned_no_dispatcher: false,
        }
    }

    /// Run the pass if it is enabled and due. Only a lost lease is returned;
    /// every other failure is logged and retried on the next interval.
    pub(super) async fn tick(
        &mut self,
        cx: &Cx<'_>,
        dotns: &mut Drain<Dotns>,
    ) -> Result<(), WriterError> {
        if !self.config.enabled
            || self
                .last
                .is_some_and(|t| t.elapsed() < self.config.interval)
        {
            return Ok(());
        }
        self.last = Some(Instant::now());
        let Some(asset_hub) = dotns.chain().await else {
            return Ok(());
        };
        match self.pass(cx, dotns, &asset_hub).await {
            Err(e) if e.is_lease_lost() => Err(e),
            Err(e) => {
                tracing::warn!(error = %e, "dotns settlement pass failed");
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    async fn pass(
        &mut self,
        cx: &Cx<'_>,
        dotns: &mut Drain<Dotns>,
        asset_hub: &AssetHub,
    ) -> Result<(), WriterError> {
        let Some(controller) = asset_hub.dispatcher_address().await? else {
            if !self.warned_no_dispatcher {
                self.warned_no_dispatcher = true;
                tracing::warn!("DotnsGateway::DispatcherAddress is unset; nothing to settle into");
            }
            return Ok(());
        };
        let records = asset_hub.account_names().await?;
        let signer = cx.signer_account.0;
        let mut pending_accounts = 0usize;
        let mut submitted = 0usize;
        for record in records {
            if self.cache.is_settled(&record.account, &record.raw) {
                continue;
            }
            let user = settle::to_h160(&record.account);
            let count = match asset_hub
                .revive_dry_run(
                    &signer,
                    &controller,
                    settle::pending_claim_count_calldata(&user),
                )
                .await
            {
                Ok(run) => match run.result {
                    Ok(data) => settle::decode_uint(&data)?,
                    Err(reason) => {
                        tracing::warn!(account = %hex_account(&record.account), %reason, "pendingClaimCountOf reverted");
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!(account = %hex_account(&record.account), error = %e, "pendingClaimCountOf dry run failed");
                    continue;
                }
            };
            if count == 0 {
                self.cache.mark(record.account, record.raw);
                continue;
            }
            pending_accounts += 1;
            if submitted >= self.config.max_per_pass {
                continue;
            }
            if !self.ensure_signer_mapped(cx, dotns, asset_hub).await? {
                break;
            }
            let calldata = settle::settle_calldata(&user, self.config.claim_limit);
            let run = match asset_hub
                .revive_dry_run(&signer, &controller, calldata)
                .await
            {
                Ok(run) => run,
                Err(e) => {
                    tracing::warn!(account = %hex_account(&record.account), error = %e, "settlePendingClaims dry run failed");
                    continue;
                }
            };
            if let Err(reason) = &run.result {
                tracing::warn!(account = %hex_account(&record.account), %reason, "settlePendingClaims would revert; skipped");
                metrics::counter!("dub_dotns_settle_total", "outcome" => "revert").increment(1);
                continue;
            }
            let payload = settle::settle_tx(&controller, &user, self.config.claim_limit, run.cost);
            tracing::info!(
                account = %hex_account(&record.account),
                user = %format!("0x{}", hex::encode(user)),
                pending = count,
                ref_time = run.cost.ref_time,
                storage_deposit = run.cost.storage_deposit,
                "settling dotns pending claims"
            );
            match submit(cx, dotns, asset_hub, &payload, "dotns settle").await {
                Ok(tx) => {
                    submitted += 1;
                    metrics::counter!("dub_dotns_settle_total", "outcome" => "ok").increment(1);
                    // Verified on the next pass rather than assumed: the cache
                    // is only written by a zero count.
                    tracing::info!(account = %hex_account(&record.account), %tx, "dotns pending claims settled");
                }
                Err(e) if e.is_lease_lost() => return Err(e),
                Err(e) => {
                    metrics::counter!("dub_dotns_settle_total", "outcome" => "failed").increment(1);
                    tracing::warn!(account = %hex_account(&record.account), error = %e, "dotns settlement failed");
                }
            }
        }
        metrics::gauge!("dub_dotns_pending_claim_accounts").set(pending_accounts as f64);
        if submitted > 0 || pending_accounts > 0 {
            tracing::info!(
                pending_accounts,
                submitted,
                settled_cached = self.cache.len(),
                "dotns settlement pass"
            );
        }
        Ok(())
    }

    /// A substrate signer must hold a revive address mapping before it can
    /// call a contract. Checked once per process; mapped here if missing.
    async fn ensure_signer_mapped(
        &mut self,
        cx: &Cx<'_>,
        dotns: &mut Drain<Dotns>,
        asset_hub: &AssetHub,
    ) -> Result<bool, WriterError> {
        if self.signer_mapped {
            return Ok(true);
        }
        if asset_hub.is_revive_mapped(&cx.signer_account.0).await? {
            self.signer_mapped = true;
            return Ok(true);
        }
        tracing::info!(
            signer = %hex_account(&cx.signer_account.0),
            "mapping the writer's signer for revive (Revive.map_account)"
        );
        match submit(
            cx,
            dotns,
            asset_hub,
            &settle::map_account_tx(),
            "revive map_account",
        )
        .await
        {
            Ok(_) => {
                self.signer_mapped = true;
                Ok(true)
            }
            Err(e) if e.is_lease_lost() => Err(e),
            Err(e) => {
                tracing::warn!(error = %e, "Revive.map_account failed; settlement skipped this pass");
                Ok(false)
            }
        }
    }
}

/// Sign from the writer's signer at the node's next nonce and await
/// finalization. The dotNS lane shares this nonce lane, so its cached nonce is
/// dropped whatever the outcome.
async fn submit(
    cx: &Cx<'_>,
    dotns: &mut Drain<Dotns>,
    asset_hub: &AssetHub,
    payload: &impl Payload,
    what: &'static str,
) -> Result<String, WriterError> {
    dotns.reset_nonce();
    let nonce = asset_hub.next_nonce(cx.signer_account).await?;
    let params = AssetHubExtrinsicParamsBuilder::new().nonce(nonce).build();
    let at = asset_hub
        .online()
        .at_current_block()
        .await
        .map_err(anyhow::Error::from)?;
    let signed = chain_client::create_signed_v4(&at, payload, cx.signer, params)
        .await
        .map_err(anyhow::Error::from)?;
    let tx = format!("{:?}", signed.hash());
    tracing::debug!(%tx, nonce, what, "submitting");
    let progress = signed
        .submit_and_watch()
        .await
        .map_err(anyhow::Error::from)?;
    match finalize(cx, progress).await {
        Ok(_) => Ok(tx),
        Err(e) => match e.downcast::<WriterError>() {
            Ok(lease_lost) => Err(lease_lost),
            Err(e) => Err(WriterError::Chain(e.context(what))),
        },
    }
}
